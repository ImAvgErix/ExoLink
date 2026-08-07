[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$ApiHost,
    [Parameter(Mandatory)]
    [string]$SshPrivateKey,
    [Parameter(Mandatory)]
    [string]$ApiDomain,
    [Parameter(Mandatory)]
    [string]$VoiceUrl,
    [Parameter(Mandatory)]
    [string]$AcmeEmail,
    [Parameter(Mandatory)]
    [string]$SupportEmail,
    [Parameter(Mandatory)]
    [string]$AbuseEmail,
    [string]$OperatorName = "Exocord Friends Alpha",
    [string]$SshUser = "ubuntu",
    [string]$SourceArchive,
    [string]$ImageTag,
    [switch]$UseGeneratedLiveKitCredentials,
    [switch]$AcceptNewHostKey
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SourceArchive)) {
    $manifest = Get-Content -Raw (Join-Path $repoRoot "Cargo.toml")
    $workspaceVersion = [regex]::Match(
        $manifest,
        '(?m)^version\s*=\s*"([^"]+)"\s*$'
    )
    if (-not $workspaceVersion.Success) {
        throw "The workspace version could not be read from Cargo.toml."
    }
    $version = $workspaceVersion.Groups[1].Value
    $SourceArchive = Join-Path $repoRoot (
        "artifacts\server-alpha\$version\exocord-api-source-$version.tar.gz"
    )
}
$SourceArchive = [IO.Path]::GetFullPath($SourceArchive)
$SshPrivateKey = [IO.Path]::GetFullPath($SshPrivateKey)
$installer = Join-Path $repoRoot "deploy\oracle\install-api-host.sh"
$checksumFile = Join-Path (Split-Path -Parent $SourceArchive) "SHA256SUMS.txt"

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

function Assert-SafeEmail {
    param([string]$Name, [string]$Value)
    if (
        $Value.Length -gt 254 -or
        $Value -notmatch '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$'
    ) {
        throw "$Name must be one normal public email address."
    }
}

function ConvertFrom-SecureValue {
    param([Security.SecureString]$Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
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

if (-not (Test-Path -LiteralPath $SourceArchive -PathType Leaf)) {
    throw "Server source archive not found: $SourceArchive"
}
if (-not (Test-Path -LiteralPath $checksumFile -PathType Leaf)) {
    throw "Server checksum file not found: $checksumFile"
}
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Oracle host installer not found: $installer"
}
if (-not (Test-Path -LiteralPath $SshPrivateKey -PathType Leaf)) {
    throw "SSH private key not found: $SshPrivateKey"
}
foreach ($program in @("ssh.exe", "scp.exe")) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "$program is required from Windows OpenSSH."
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
$ApiDomain = $ApiDomain.Trim().ToLowerInvariant()
if (
    $ApiDomain.Length -gt 253 -or
    $ApiDomain -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$'
) {
    throw "ApiDomain must be a public DNS hostname."
}
$resolvedApiAddresses = @(
    [Net.Dns]::GetHostAddresses($ApiDomain) |
        Where-Object {
            $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
        } |
        ForEach-Object { $_.IPAddressToString }
)
if ($resolvedApiAddresses -notcontains $parsedIp.IPAddressToString) {
    throw "ApiDomain must resolve directly to ApiHost before deployment."
}
$voice = $null
if (
    -not [Uri]::TryCreate($VoiceUrl.Trim(), [UriKind]::Absolute, [ref]$voice) -or
    $voice.Scheme -ne "wss" -or
    -not [string]::IsNullOrEmpty($voice.UserInfo) -or
    -not [string]::IsNullOrEmpty($voice.Query) -or
    -not [string]::IsNullOrEmpty($voice.Fragment) -or
    $voice.AbsolutePath -ne "/"
) {
    throw "VoiceUrl must be a credential-free WSS origin."
}
Assert-SafeEmail -Name "AcmeEmail" -Value $AcmeEmail
Assert-SafeEmail -Name "SupportEmail" -Value $SupportEmail
Assert-SafeEmail -Name "AbuseEmail" -Value $AbuseEmail
if (
    $OperatorName.Length -lt 1 -or
    $OperatorName.Length -gt 100 -or
    $OperatorName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]*$'
) {
    throw "OperatorName may use letters, digits, spaces, period, underscore, and hyphen."
}
if ($SshUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw "SshUser is invalid."
}

$archiveLeaf = [IO.Path]::GetFileName($SourceArchive)
$archivePattern = [Regex]::Escape($archiveLeaf)
$expectedLine = Get-Content -LiteralPath $checksumFile |
    Where-Object { $_ -match "\s{2}$archivePattern$" } |
    Select-Object -First 1
if (-not $expectedLine -or $expectedLine -notmatch '^([0-9a-f]{64})\s{2}') {
    throw "The source archive checksum manifest is invalid."
}
$expectedSha256 = $Matches[1]
$actualSha256 = Get-FileSha256 -Path $SourceArchive
if ($actualSha256 -ne $expectedSha256) {
    throw "The server source archive does not match SHA256SUMS.txt."
}
if ([string]::IsNullOrWhiteSpace($ImageTag)) {
    $ImageTag = "bundle-" + $actualSha256.Substring(0, 12)
}
if ($ImageTag -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$') {
    throw "ImageTag is not a valid immutable Docker tag."
}

$runtimeDirectory = Join-Path $repoRoot "outputs\oracle-alpha"
New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
$knownHosts = Join-Path $runtimeDirectory "known_hosts"
$strictHostKeyChecking = if ($AcceptNewHostKey) { "accept-new" } else { "yes" }
$sshOptions = @(
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=20",
    "-o", "StrictHostKeyChecking=$strictHostKeyChecking",
    "-o", "UserKnownHostsFile=$knownHosts",
    "-i", $SshPrivateKey
)
$remote = "${SshUser}@${ApiHost}"
$temporaryEnvironment = Join-Path (
    [IO.Path]::GetTempPath()
) ("exocord-alpha-" + [guid]::NewGuid().ToString("N") + ".env")

try {
    $environmentLines = @(
        "EXOCORD_DOMAIN=$ApiDomain",
        "ACME_EMAIL=$AcmeEmail",
        "EXOCORD_IMAGE_TAG=bootstrap-unbuilt",
        "EXOCORD_OPERATOR_NAME=$OperatorName",
        "EXOCORD_PRIVACY_URL=https://$ApiDomain/privacy",
        "EXOCORD_TERMS_URL=https://$ApiDomain/terms",
        "EXOCORD_SUPPORT_EMAIL=$SupportEmail",
        "EXOCORD_ABUSE_EMAIL=$AbuseEmail",
        "POSTGRES_DB=exocord",
        "POSTGRES_USER=exocord",
        "EXOCORD_DATABASE_MAX_CONNECTIONS=20",
        "EXOCORD_ALLOWED_ORIGINS=http://tauri.localhost",
        "EXOCORD_ATTACHMENT_MAX_STORAGE_BYTES=5368709120",
        "EXOCORD_BACKUP_RETENTION_SETS=3",
        "EXOCORD_LIVEKIT_URL=$($voice.AbsoluteUri.TrimEnd('/'))",
        "EXOCORD_LOG=info,exo_monolith=info",
        "EXOCORD_APPLE_CLIENT_ID=",
        "EXOCORD_APPLE_TEAM_ID=",
        "EXOCORD_APPLE_KEY_ID="
    )
    # The staged file is consumed by Linux tools. Write explicit LF endings so
    # values never acquire a trailing carriage return during validation.
    [IO.File]::WriteAllText(
        $temporaryEnvironment,
        (($environmentLines -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )

    $target = "$remote (https://$ApiDomain)"
    if (-not $PSCmdlet.ShouldProcess($target, "Install the Exocord API host")) {
        return
    }

    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $remote +
        "cloud-init status --wait && test -s /var/lib/exocord-bootstrap-ready"
    )
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions + $SourceArchive +
        "${remote}:/tmp/exocord-api-source.tar.gz"
    )
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions + $temporaryEnvironment +
        "${remote}:/tmp/exocord-alpha.env"
    )
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions + $installer +
        "${remote}:/tmp/exocord-install-api-host.sh"
    )

    if ($UseGeneratedLiveKitCredentials) {
        Invoke-External -Program "ssh.exe" -Arguments @(
            $sshOptions + $remote +
            "sudo test -s /var/lib/exocord-livekit/api-key && sudo test -s /var/lib/exocord-livekit/api-secret && sudo install -m 600 /var/lib/exocord-livekit/api-key /tmp/exocord-livekit-api-key && sudo install -m 600 /var/lib/exocord-livekit/api-secret /tmp/exocord-livekit-api-secret"
        )
    }
    else {
        $livekitKeySecure = Read-Host "LiveKit API key" -AsSecureString
        $livekitSecretSecure = Read-Host "LiveKit API secret" -AsSecureString
        $livekitKey = ConvertFrom-SecureValue $livekitKeySecure
        $livekitSecret = ConvertFrom-SecureValue $livekitSecretSecure
        try {
            if (
                [string]::IsNullOrWhiteSpace($livekitKey) -or
                [string]::IsNullOrWhiteSpace($livekitSecret) -or
                $livekitKey.IndexOfAny([char[]]"`r`n") -ge 0 -or
                $livekitSecret.IndexOfAny([char[]]"`r`n") -ge 0
            ) {
                throw "LiveKit credentials cannot be empty or contain newlines."
            }
            $livekitKey | & ssh.exe @sshOptions $remote (
                "umask 077; cat > /tmp/exocord-livekit-api-key"
            )
            if ($LASTEXITCODE -ne 0) {
                throw "Could not transfer the LiveKit API key."
            }
            $livekitSecret | & ssh.exe @sshOptions $remote (
                "umask 077; cat > /tmp/exocord-livekit-api-secret"
            )
            if ($LASTEXITCODE -ne 0) {
                throw "Could not transfer the LiveKit API secret."
            }
        }
        finally {
            $livekitKey = $null
            $livekitSecret = $null
            $livekitKeySecure.Dispose()
            $livekitSecretSecure.Dispose()
        }
    }

    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $remote +
        "sudo bash /tmp/exocord-install-api-host.sh $actualSha256 $ImageTag"
    )
}
finally {
    if (Test-Path -LiteralPath $temporaryEnvironment) {
        [IO.File]::Delete($temporaryEnvironment)
    }
}

[pscustomobject]@{
    api = "https://$ApiDomain"
    imageTag = $ImageTag
    sourceSha256 = $actualSha256
    knownHosts = $knownHosts
    next = "Run scripts/alpha-preflight.ps1 from a different network."
} | ConvertTo-Json -Compress
