[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$ApiHost,
    [Parameter(Mandatory)]
    [string]$VoiceHost,
    [Parameter(Mandatory)]
    [string]$SshPrivateKey,
    [Parameter(Mandatory)]
    [string]$AcmeEmail,
    [Parameter(Mandatory)]
    [string]$SupportEmail,
    [Parameter(Mandatory)]
    [string]$AbuseEmail,
    [string]$OperatorName = "Exocord Friends Alpha",
    [string]$ApiDomain,
    [string]$VoiceDomain,
    [string]$TurnDomain,
    [switch]$UseTemporarySslipDomains,
    [string]$SshUser = "ubuntu",
    [switch]$AcceptNewHostKey
)

$ErrorActionPreference = "Stop"
$liveKitInstaller = Join-Path $PSScriptRoot "install-oracle-livekit.ps1"
$apiInstaller = Join-Path $PSScriptRoot "install-oracle-api.ps1"

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
    $parsed.IPAddressToString
}

function Assert-Domain {
    param([string]$Name, [string]$Value)
    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value.Length -gt 253 -or
        $Value -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$'
    ) {
        throw "$Name must be a public DNS hostname."
    }
}

if (-not (Test-Path -LiteralPath $liveKitInstaller -PathType Leaf)) {
    throw "LiveKit installer not found: $liveKitInstaller"
}
if (-not (Test-Path -LiteralPath $apiInstaller -PathType Leaf)) {
    throw "API installer not found: $apiInstaller"
}

$ApiHost = Resolve-PublicIpv4 -Name "ApiHost" -Value $ApiHost
$VoiceHost = Resolve-PublicIpv4 -Name "VoiceHost" -Value $VoiceHost
if ($ApiHost -eq $VoiceHost) {
    throw "ApiHost and VoiceHost must be separate Oracle instances."
}

$explicitDomains = @($ApiDomain, $VoiceDomain, $TurnDomain) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($UseTemporarySslipDomains) {
    if ($explicitDomains.Count -ne 0) {
        throw "Do not combine -UseTemporarySslipDomains with explicit domains."
    }
    $apiDashIp = $ApiHost.Replace(".", "-")
    $voiceDashIp = $VoiceHost.Replace(".", "-")
    $ApiDomain = "api-$apiDashIp.sslip.io"
    $VoiceDomain = "voice-$voiceDashIp.sslip.io"
    $TurnDomain = "turn-$voiceDashIp.sslip.io"
}
elseif ($explicitDomains.Count -ne 3) {
    throw (
        "Provide ApiDomain, VoiceDomain, and TurnDomain, or use " +
        "-UseTemporarySslipDomains for the no-cost friends alpha."
    )
}

$ApiDomain = $ApiDomain.Trim().ToLowerInvariant()
$VoiceDomain = $VoiceDomain.Trim().ToLowerInvariant()
$TurnDomain = $TurnDomain.Trim().ToLowerInvariant()
Assert-Domain -Name "ApiDomain" -Value $ApiDomain
Assert-Domain -Name "VoiceDomain" -Value $VoiceDomain
Assert-Domain -Name "TurnDomain" -Value $TurnDomain
if (@($ApiDomain, $VoiceDomain, $TurnDomain | Select-Object -Unique).Count -ne 3) {
    throw "API, LiveKit, and TURN domains must be distinct."
}

$target = (
    "API $ApiHost ($ApiDomain) and voice $VoiceHost " +
    "($VoiceDomain, $TurnDomain)"
)
if (-not $PSCmdlet.ShouldProcess($target, "Install the complete Exocord alpha")) {
    return
}

$liveKitArguments = @{
    GeneratorHost = $ApiHost
    VoiceHost = $VoiceHost
    SshPrivateKey = $SshPrivateKey
    PrimaryDomain = $VoiceDomain
    TurnDomain = $TurnDomain
    SshUser = $SshUser
    Confirm = $false
}
if ($AcceptNewHostKey) {
    $liveKitArguments.AcceptNewHostKey = $true
}
& $liveKitInstaller @liveKitArguments
if (-not $?) {
    throw "LiveKit installation failed."
}

& $apiInstaller `
    -ApiHost $ApiHost `
    -SshPrivateKey $SshPrivateKey `
    -ApiDomain $ApiDomain `
    -VoiceUrl "wss://$VoiceDomain" `
    -AcmeEmail $AcmeEmail `
    -SupportEmail $SupportEmail `
    -AbuseEmail $AbuseEmail `
    -OperatorName $OperatorName `
    -SshUser $SshUser `
    -UseGeneratedLiveKitCredentials `
    -Confirm:$false
if (-not $?) {
    throw "API installation failed."
}

[ordered]@{
    apiUrl = "https://$ApiDomain"
    voiceUrl = "wss://$VoiceDomain"
    turnDomain = $TurnDomain
    dns = if ($UseTemporarySslipDomains) {
        "temporary_sslip"
    }
    else {
        "operator_managed"
    }
    next = (
        "Run scripts/alpha-preflight.ps1, then build the Windows installer " +
        "with this apiUrl."
    )
} | ConvertTo-Json -Compress
