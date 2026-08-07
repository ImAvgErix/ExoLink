[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$ApiHost,
    [Parameter(Mandatory)]
    [string]$SshPrivateKey,
    [string]$SshUser = "ubuntu",
    [string]$BackupRoot = (
        Join-Path (
            [Environment]::GetFolderPath("LocalApplicationData")
        ) "ExocordOperator\backups"
    ),
    [ValidateRange(1, 30)]
    [int]$RetentionSets = 7,
    [switch]$CreateFreshBackup
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$knownHosts = Join-Path $repoRoot "outputs\oracle-alpha\known_hosts"
$remoteBackupDirectory = "/var/backups/exocord-alpha"
$remoteBackupScript = (
    "/opt/exocord/deploy/alpha/scripts/backup-alpha.sh"
)

function Test-PublicIpv4 {
    param([Net.IPAddress]$Address)
    $bytes = $Address.GetAddressBytes()
    -not (
        $bytes[0] -eq 0 -or
        $bytes[0] -eq 10 -or
        $bytes[0] -eq 127 -or
        ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        $bytes[0] -ge 224
    )
}

function Invoke-External {
    param(
        [Parameter(Mandatory)]
        [string]$Program,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE."
    }
}

function Invoke-SshCapture {
    param([string]$Command)
    $result = @(& ssh.exe @sshOptions $remote $Command)
    if ($LASTEXITCODE -ne 0) {
        throw "ssh.exe failed with exit code $LASTEXITCODE."
    }
    ($result -join "`n").Trim()
}

function Get-FileSha256 {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        [BitConverter]::ToString(
            $hasher.ComputeHash($stream)
        ).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Assert-ChildPath {
    param([string]$Parent, [string]$Child)
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith(
        $parentFull,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing a path outside the backup root: $childFull"
    }
}

$parsedIp = $null
if (
    -not [Net.IPAddress]::TryParse($ApiHost, [ref]$parsedIp) -or
    $parsedIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    -not (Test-PublicIpv4 $parsedIp)
) {
    throw "ApiHost must be the Oracle instance's public IPv4 address."
}
if ($SshUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw "SshUser is invalid."
}
$SshPrivateKey = [IO.Path]::GetFullPath($SshPrivateKey)
if (-not (Test-Path -LiteralPath $SshPrivateKey -PathType Leaf)) {
    throw "SSH private key not found: $SshPrivateKey"
}
if (-not (Test-Path -LiteralPath $knownHosts -PathType Leaf)) {
    throw (
        "Pinned Oracle SSH host keys are missing. Complete the Oracle " +
        "installation before syncing backups."
    )
}
foreach ($program in @("ssh.exe", "scp.exe")) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "$program is required from Windows OpenSSH."
    }
}

$BackupRoot = [IO.Path]::GetFullPath($BackupRoot)
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$backupRootItem = Get-Item -LiteralPath $BackupRoot
if (
    ($backupRootItem.Attributes -band [IO.FileAttributes]::Encrypted) -eq 0
) {
    throw (
        "The off-host backup directory is not EFS encrypted. Encrypt it " +
        "with 'cipher /E /A `"$BackupRoot`"' before copying server data."
    )
}
$remote = "${SshUser}@${ApiHost}"
$sshOptions = @(
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=20",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=$knownHosts",
    "-i", $SshPrivateKey
)

if ($CreateFreshBackup) {
    if (-not $PSCmdlet.ShouldProcess(
        $remote,
        "Stop the API briefly and create a fresh verified backup"
    )) {
        return
    }
    $createdManifest = Invoke-SshCapture -Command (
        "sudo bash $remoteBackupScript $remoteBackupDirectory"
    )
    $manifestName = [IO.Path]::GetFileName(
        ($createdManifest -split "`n" | Select-Object -Last 1)
    )
}
else {
    $latestManifest = Invoke-SshCapture -Command (
        "sudo find $remoteBackupDirectory -maxdepth 1 -type f " +
        "-name 'exocord-*.sha256' -printf '%f\n' | sort -r | head -n 1"
    )
    $manifestName = ($latestManifest -split "`n" | Select-Object -Last 1)
}

if (
    $manifestName -notmatch
        '^exocord-(?<stamp>[0-9]{8}T[0-9]{6}Z)\.sha256$'
) {
    throw "The API host did not return a valid backup manifest name."
}
$prefix = "exocord-$($Matches.stamp)"
$backupFiles = @(
    "$prefix.dump",
    "$prefix.state.tar.gz",
    "$prefix.sha256"
)
$remoteStage = "/tmp/exocord-offhost-" + [guid]::NewGuid().ToString("N")
if ($remoteStage -notmatch '^/tmp/exocord-offhost-[0-9a-f]{32}$') {
    throw "The temporary remote path is invalid."
}
$localStage = Join-Path (
    $BackupRoot
) (".incoming-" + [guid]::NewGuid().ToString("N"))
Assert-ChildPath -Parent $BackupRoot -Child $localStage

if (-not $PSCmdlet.ShouldProcess(
    "${remote}:$remoteBackupDirectory/$prefix",
    "Copy and verify the backup set off-host"
)) {
    return
}

try {
    New-Item -ItemType Directory -Path $localStage | Out-Null
    $quotedSources = $backupFiles |
        ForEach-Object { "'$remoteBackupDirectory/$_'" }
    $stageCommand = (
        "umask 077; install -d -m 700 '$remoteStage'; " +
        "sudo install -m 600 -o '$SshUser' -g '$SshUser' " +
        ($quotedSources -join " ") +
        " '$remoteStage/'"
    )
    Invoke-SshCapture -Command $stageCommand | Out-Null

    foreach ($file in $backupFiles) {
        Invoke-External -Program "scp.exe" -Arguments @(
            $sshOptions +
            "${remote}:$remoteStage/$file" +
            $localStage
        )
    }

    $localManifest = Join-Path $localStage "$prefix.sha256"
    $manifestLines = @(Get-Content -LiteralPath $localManifest)
    if ($manifestLines.Count -ne 2) {
        throw "The downloaded backup manifest has an unexpected shape."
    }
    $expected = @{}
    foreach ($line in $manifestLines) {
        if (
            $line -notmatch
                '^(?<hash>[0-9a-f]{64})  (?<file>exocord-[0-9]{8}T[0-9]{6}Z\.(?:dump|state\.tar\.gz))$'
        ) {
            throw "The downloaded backup manifest contains an invalid entry."
        }
        if ($Matches.file -notin $backupFiles -or $expected.ContainsKey($Matches.file)) {
            throw "The downloaded backup manifest contains an unexpected file."
        }
        $expected[$Matches.file] = $Matches.hash
    }
    foreach ($payload in @("$prefix.dump", "$prefix.state.tar.gz")) {
        $payloadPath = Join-Path $localStage $payload
        if (
            -not (Test-Path -LiteralPath $payloadPath -PathType Leaf) -or
            (Get-Item -LiteralPath $payloadPath).Length -lt 1
        ) {
            throw "The downloaded backup payload is missing or empty: $payload"
        }
        if ((Get-FileSha256 -Path $payloadPath) -ne $expected[$payload]) {
            throw "The downloaded backup failed SHA-256 verification: $payload"
        }
    }

    foreach ($file in $backupFiles) {
        $destination = Join-Path $BackupRoot $file
        if (Test-Path -LiteralPath $destination) {
            if ((Get-FileSha256 -Path $destination) -ne (
                Get-FileSha256 -Path (Join-Path $localStage $file)
            )) {
                throw "A different local backup file already exists: $destination"
            }
            Remove-Item -LiteralPath (Join-Path $localStage $file)
        }
        else {
            Move-Item -LiteralPath (Join-Path $localStage $file) `
                -Destination $destination
        }
        if (
            ((Get-Item -LiteralPath $destination).Attributes -band
                [IO.FileAttributes]::Encrypted) -eq 0
        ) {
            throw "The local backup payload was not encrypted by EFS: $destination"
        }
    }

    $retainedManifests = @(
        Get-ChildItem -LiteralPath $BackupRoot -File -Filter "exocord-*.sha256" |
            Where-Object {
                $_.Name -match '^exocord-[0-9]{8}T[0-9]{6}Z\.sha256$'
            } |
            Sort-Object Name -Descending
    )
    foreach ($expired in $retainedManifests | Select-Object -Skip $RetentionSets) {
        $expiredPrefix = $expired.BaseName
        foreach ($suffix in @(".dump", ".state.tar.gz", ".sha256")) {
            $expiredPath = Join-Path $BackupRoot "$expiredPrefix$suffix"
            Assert-ChildPath -Parent $BackupRoot -Child $expiredPath
            if (Test-Path -LiteralPath $expiredPath -PathType Leaf) {
                Remove-Item -LiteralPath $expiredPath
            }
        }
    }
}
finally {
    try {
        Invoke-SshCapture -Command "rm -rf -- '$remoteStage'" | Out-Null
    }
    catch {
        Write-Warning "Could not remove the remote temporary backup staging path."
    }
    if (Test-Path -LiteralPath $localStage -PathType Container) {
        Assert-ChildPath -Parent $BackupRoot -Child $localStage
        Remove-Item -LiteralPath $localStage -Recurse -Force
    }
}

[ordered]@{
    status = "verified"
    prefix = $prefix
    storedAt = $BackupRoot
    retentionSets = $RetentionSets
    note = "The verified backup set is protected by Windows EFS."
} | ConvertTo-Json -Compress
