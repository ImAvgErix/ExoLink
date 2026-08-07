[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$GeneratorHost,
    [Parameter(Mandatory)]
    [string]$VoiceHost,
    [Parameter(Mandatory)]
    [string]$SshPrivateKey,
    [Parameter(Mandatory)]
    [string]$PrimaryDomain,
    [Parameter(Mandatory)]
    [string]$TurnDomain,
    [string]$SshUser = "ubuntu",
    [switch]$AcceptNewHostKey
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$generatorScript = Join-Path $repoRoot "deploy\oracle\generate-livekit.sh"
$SshPrivateKey = [IO.Path]::GetFullPath($SshPrivateKey)

function Resolve-PublicIpv4 {
    param([string]$Name, [string]$Value)
    $parsed = $null
    if (
        -not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork
    ) {
        throw "$Name must be a public IPv4 address."
    }
    $bytes = $parsed.GetAddressBytes()
    if (
        $bytes[0] -eq 0 -or
        $bytes[0] -eq 10 -or
        $bytes[0] -eq 127 -or
        ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) -or
        ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        $bytes[0] -ge 224
    ) {
        throw "$Name must be a public IPv4 address."
    }
    $parsed
}

function Assert-Domain {
    param([string]$Name, [string]$Value)
    if (
        $Value.Length -gt 253 -or
        $Value -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$'
    ) {
        throw "$Name must be a public DNS hostname."
    }
}

function Invoke-External {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE."
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

function Test-TlsName {
    param([string]$Domain)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($Domain, 443)
        if (-not $connect.Wait([TimeSpan]::FromSeconds(10))) {
            throw "TLS connection timed out for $Domain."
        }
        $tls = [Net.Security.SslStream]::new($client.GetStream(), $false)
        try {
            $tls.AuthenticateAsClient($Domain)
            if (-not $tls.IsAuthenticated -or -not $tls.IsEncrypted) {
                throw "TLS was not authenticated for $Domain."
            }
        }
        finally {
            $tls.Dispose()
        }
    }
    finally {
        $client.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $generatorScript -PathType Leaf)) {
    throw "LiveKit generator wrapper not found: $generatorScript"
}
if (-not (Test-Path -LiteralPath $SshPrivateKey -PathType Leaf)) {
    throw "SSH private key not found: $SshPrivateKey"
}
foreach ($program in @("ssh.exe", "scp.exe")) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "$program is required from Windows OpenSSH."
    }
}

$generatorIp = Resolve-PublicIpv4 -Name "GeneratorHost" -Value $GeneratorHost
$voiceIp = Resolve-PublicIpv4 -Name "VoiceHost" -Value $VoiceHost
if ($generatorIp.Equals($voiceIp)) {
    throw "GeneratorHost and VoiceHost must be separate Oracle instances."
}
$PrimaryDomain = $PrimaryDomain.Trim().ToLowerInvariant()
$TurnDomain = $TurnDomain.Trim().ToLowerInvariant()
Assert-Domain -Name "PrimaryDomain" -Value $PrimaryDomain
Assert-Domain -Name "TurnDomain" -Value $TurnDomain
if ($PrimaryDomain -eq $TurnDomain) {
    throw "PrimaryDomain and TurnDomain must be different."
}
foreach ($mapping in @(
    @{ Domain = $PrimaryDomain; Expected = $voiceIp.IPAddressToString },
    @{ Domain = $TurnDomain; Expected = $voiceIp.IPAddressToString }
)) {
    $addresses = @(
        [Net.Dns]::GetHostAddresses($mapping.Domain) |
            Where-Object {
                $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
            } |
            ForEach-Object { $_.IPAddressToString }
    )
    if ($addresses -notcontains $mapping.Expected) {
        throw "$($mapping.Domain) must resolve directly to VoiceHost."
    }
}
if ($SshUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw "SshUser is invalid."
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
$generatorRemote = "${SshUser}@${GeneratorHost}"
$voiceRemote = "${SshUser}@${VoiceHost}"
$temporaryInstaller = Join-Path (
    [IO.Path]::GetTempPath()
) ("exocord-livekit-" + [guid]::NewGuid().ToString("N") + ".sh")

try {
    $target = "$voiceRemote (wss://$PrimaryDomain)"
    if (-not $PSCmdlet.ShouldProcess($target, "Install official LiveKit/TURN configuration")) {
        return
    }

    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $generatorRemote +
        "cloud-init status --wait && test -s /var/lib/exocord-bootstrap-ready"
    )
    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $voiceRemote +
        "cloud-init status --wait && test -s /var/lib/exocord-voice-bootstrap-ready"
    )
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions + $generatorScript +
        "${generatorRemote}:/tmp/exocord-generate-livekit.sh"
    )
    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $generatorRemote +
        "sudo bash /tmp/exocord-generate-livekit.sh $PrimaryDomain $TurnDomain"
    )
    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $generatorRemote +
        "sudo cp /var/lib/exocord-livekit/voice-init.sh /tmp/exocord-livekit-voice-init.sh && sudo chown $SshUser /tmp/exocord-livekit-voice-init.sh && chmod 600 /tmp/exocord-livekit-voice-init.sh"
    )
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions +
        "${generatorRemote}:/tmp/exocord-livekit-voice-init.sh" +
        $temporaryInstaller
    )
    $expectedInstallerHash = (
        & ssh.exe @sshOptions $generatorRemote (
            "sudo awk '{print `$1}' /var/lib/exocord-livekit/voice-init.sha256"
        )
    ).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $expectedInstallerHash -notmatch '^[0-9a-f]{64}$') {
        throw "Could not read the generated LiveKit installer checksum."
    }
    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $generatorRemote +
        "rm -f /tmp/exocord-livekit-voice-init.sh"
    )
    if (
        -not (Test-Path -LiteralPath $temporaryInstaller -PathType Leaf) -or
        (Get-Item -LiteralPath $temporaryInstaller).Length -lt 1024
    ) {
        throw "The generated LiveKit installer is missing or unexpectedly small."
    }
    $actualInstallerHash = Get-FileSha256 -Path $temporaryInstaller
    if ($actualInstallerHash -ne $expectedInstallerHash) {
        throw "The transferred LiveKit installer failed checksum verification."
    }
    Invoke-External -Program "scp.exe" -Arguments @(
        $sshOptions + $temporaryInstaller +
        "${voiceRemote}:/tmp/exocord-livekit-voice-init.sh"
    )
    Invoke-External -Program "ssh.exe" -Arguments @(
        $sshOptions + $voiceRemote +
        "chmod 700 /tmp/exocord-livekit-voice-init.sh && sudo /tmp/exocord-livekit-voice-init.sh && rm -f /tmp/exocord-livekit-voice-init.sh && sudo systemctl is-active --quiet livekit-docker"
    )

    $tlsReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
        try {
            Test-TlsName -Domain $PrimaryDomain
            Test-TlsName -Domain $TurnDomain
            $tlsReady = $true
            break
        }
        catch {
            Start-Sleep -Seconds 2
        }
    }
    if (-not $tlsReady) {
        throw "LiveKit and TURN TLS certificates were not ready within two minutes."
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryInstaller) {
        [IO.File]::Delete($temporaryInstaller)
    }
}

[pscustomobject]@{
    voiceUrl = "wss://$PrimaryDomain"
    turnDomain = $TurnDomain
    credentials = "sealed on the Oracle API bootstrap host"
    next = "Run scripts/install-oracle-api.ps1 with -UseGeneratedLiveKitCredentials."
} | ConvertTo-Json -Compress
