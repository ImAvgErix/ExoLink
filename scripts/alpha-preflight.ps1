[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ApiUrl,
    [Parameter(Mandatory)]
    [string]$VoiceUrl
)

$ErrorActionPreference = "Stop"
$requiredConversationActions = "replies_edits_deletes_unicode_reactions"

$api = $null
if (
    -not [Uri]::TryCreate($ApiUrl.Trim(), [UriKind]::Absolute, [ref]$api) -or
    $api.Scheme -ne "https" -or
    -not [string]::IsNullOrEmpty($api.UserInfo) -or
    -not [string]::IsNullOrEmpty($api.Query) -or
    -not [string]::IsNullOrEmpty($api.Fragment)
) {
    throw "ApiUrl must be a credential-free HTTPS origin."
}
$voice = $null
if (
    -not [Uri]::TryCreate($VoiceUrl.Trim(), [UriKind]::Absolute, [ref]$voice) -or
    $voice.Scheme -ne "wss" -or
    [string]::IsNullOrWhiteSpace($voice.Host) -or
    -not [string]::IsNullOrEmpty($voice.UserInfo) -or
    -not [string]::IsNullOrEmpty($voice.Query) -or
    -not [string]::IsNullOrEmpty($voice.Fragment)
) {
    throw "VoiceUrl must be a credential-free WSS URL with no query or fragment."
}

$origin = $api.AbsoluteUri.TrimEnd("/")
$healthResponse = Invoke-WebRequest -UseBasicParsing -Uri "$origin/health" -TimeoutSec 10
if ($healthResponse.Content.Trim() -ne "ok") {
    throw "The API health endpoint did not return ok."
}
$hsts = $healthResponse.Headers["Strict-Transport-Security"] -join ","
$contentTypeOptions = $healthResponse.Headers["X-Content-Type-Options"] -join ","
$referrerPolicy = $healthResponse.Headers["Referrer-Policy"] -join ","
if ($hsts -notmatch "max-age=31536000") {
    throw "The API edge is missing the required HSTS policy."
}
if ($contentTypeOptions -ne "nosniff") {
    throw "The API edge is missing X-Content-Type-Options: nosniff."
}
if ($referrerPolicy -ne "no-referrer") {
    throw "The API edge is missing Referrer-Policy: no-referrer."
}
if ($healthResponse.Headers["Server"]) {
    throw "The API edge exposes a Server fingerprint."
}
$ready = Invoke-RestMethod -Uri "$origin/ready" -TimeoutSec 10
$providers = Invoke-RestMethod -Uri "$origin/v1/auth/providers" -TimeoutSec 10
$capabilities = Invoke-RestMethod -Uri "$origin/v1/meta/capabilities" -TimeoutSec 10
$operator = Invoke-RestMethod -Uri "$origin/v1/meta/operator" -TimeoutSec 10

if (-not $ready.ready) {
    throw "The API reports that it is not ready."
}
if ($ready.storage -ne "postgres") {
    throw "The alpha API must report postgres storage."
}
if ($ready.auth -ne "password_sessions") {
    throw "The alpha API must report durable password sessions."
}
if ($ready.attachments -notin @("local", "r2")) {
    throw "The production alpha API must report local or R2 attachment storage."
}
if (-not $providers.password) {
    throw "The alpha API must enable email/password sign-in."
}
if ($providers.developmentCodePreview) {
    throw "A production alpha must not expose development login codes."
}
if (-not $providers.proofOfWork) {
    throw "The production alpha must enable sign-in proof of work."
}
if ($capabilities.conversation_actions -ne $requiredConversationActions) {
    throw "The API conversation protocol does not match this desktop build."
}
if ($capabilities.native_voice -ne "livekit_sframe_mls_exporter") {
    throw "The alpha API must report MLS-exported LiveKit frame encryption."
}
if ([string]::IsNullOrWhiteSpace($operator.name)) {
    throw "The alpha API must publish its operator name."
}
$privacy = $null
if (
    -not [Uri]::TryCreate(
        ([string]$operator.privacyUrl),
        [UriKind]::Absolute,
        [ref]$privacy
    ) -or
    $privacy.Scheme -ne "https" -or
    -not [string]::IsNullOrEmpty($privacy.UserInfo) -or
    -not [string]::IsNullOrEmpty($privacy.Query) -or
    -not [string]::IsNullOrEmpty($privacy.Fragment)
) {
    throw "The alpha API must publish a credential-free HTTPS privacy notice."
}
if (
    [string]::IsNullOrWhiteSpace($operator.abuseEmail) -or
    ([string]$operator.abuseEmail).Split("@").Count -ne 2
) {
    throw "The alpha API must publish an abuse-report email."
}
if (
    [string]::IsNullOrWhiteSpace($operator.supportEmail) -or
    ([string]$operator.supportEmail).Split("@").Count -ne 2
) {
    throw "The alpha API must publish a tester-support email."
}
$privacyResponse = Invoke-WebRequest -UseBasicParsing `
    -Uri $privacy.AbsoluteUri -TimeoutSec 10
$privacyContentType = $privacyResponse.Headers["Content-Type"] -join ","
if (
    $privacyContentType -notmatch "^text/html" -or
    [string]::IsNullOrWhiteSpace($privacyResponse.Content) -or
    $privacyResponse.Content.Length -lt 500
) {
    throw "The published privacy notice is not a usable HTML page."
}
if (
    ($privacyResponse.Headers["Content-Security-Policy"] -join "") -notmatch
        "default-src 'none'"
) {
    throw "The published privacy notice is missing the hardened content policy."
}
if (-not [string]::IsNullOrWhiteSpace($operator.termsUrl)) {
    $terms = $null
    if (
        -not [Uri]::TryCreate(
            ([string]$operator.termsUrl),
            [UriKind]::Absolute,
            [ref]$terms
        ) -or
        $terms.Scheme -ne "https" -or
        -not [string]::IsNullOrEmpty($terms.UserInfo) -or
        -not [string]::IsNullOrEmpty($terms.Query) -or
        -not [string]::IsNullOrEmpty($terms.Fragment)
    ) {
        throw "The published terms URL is not a credential-free HTTPS URL."
    }
    $termsResponse = Invoke-WebRequest -UseBasicParsing `
        -Uri $terms.AbsoluteUri -TimeoutSec 10
    $termsContentType = $termsResponse.Headers["Content-Type"] -join ","
    if (
        $termsContentType -notmatch "^text/html" -or
        [string]::IsNullOrWhiteSpace($termsResponse.Content) -or
        $termsResponse.Content.Length -lt 500
    ) {
        throw "The published terms are not a usable HTML page."
    }
    if (
        ($termsResponse.Headers["Content-Security-Policy"] -join "") -notmatch
            "default-src 'none'"
    ) {
        throw "The published terms are missing the hardened content policy."
    }
}

function Test-TlsEndpoint {
    param(
        [Parameter(Mandatory)]
        [Uri]$Uri,
        [Parameter(Mandatory)]
        [string]$Label
    )
    $port = if ($Uri.IsDefaultPort) { 443 } else { $Uri.Port }
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $connected = $tcp.ConnectAsync($Uri.Host, $port).Wait(
            [TimeSpan]::FromSeconds(10)
        )
        if (-not $connected -or -not $tcp.Connected) {
            throw "$Label TLS port could not be reached."
        }
        $tls = [Net.Security.SslStream]::new($tcp.GetStream(), $false)
        try {
            $tls.AuthenticateAsClient($Uri.Host)
            if (-not $tls.IsAuthenticated -or -not $tls.IsEncrypted) {
                throw "$Label did not establish authenticated TLS."
            }
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $tls.RemoteCertificate
            )
            if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(14)) {
                throw "$Label certificate expires within 14 days."
            }
            [ordered]@{
                expiresAt = $certificate.NotAfter.ToUniversalTime().ToString("o")
                protocol = $tls.SslProtocol.ToString()
            }
        }
        finally {
            $tls.Dispose()
        }
    }
    finally {
        $tcp.Dispose()
    }
}

$apiTls = Test-TlsEndpoint -Uri $api -Label "API"
$voiceTls = Test-TlsEndpoint -Uri $voice -Label "LiveKit"

$corsHeaders = @{
    Origin = "http://tauri.localhost"
    "Access-Control-Request-Method" = "GET"
}
$allowedCors = Invoke-WebRequest -UseBasicParsing -Method Options `
    -Uri "$origin/v1/auth/providers" -Headers $corsHeaders -TimeoutSec 10
if (
    ($allowedCors.Headers["Access-Control-Allow-Origin"] -join "") -ne
    "http://tauri.localhost"
) {
    throw "The API does not allow the signed Windows Tauri origin."
}
$corsHeaders.Origin = "https://malicious.example.test"
$rejectedCors = Invoke-WebRequest -UseBasicParsing -Method Options `
    -Uri "$origin/v1/auth/providers" -Headers $corsHeaders -TimeoutSec 10
if ($rejectedCors.Headers["Access-Control-Allow-Origin"]) {
    throw "The API CORS policy allows an untrusted website origin."
}

[ordered]@{
    api = $origin
    health = "ok"
    ready = $ready.ready
    storage = $ready.storage
    attachments = $ready.attachments
    password = $providers.password
    optionalEmailCode = $providers.email
    apple = $providers.apple
    conversationActions = $capabilities.conversation_actions
    voiceCapability = $capabilities.native_voice
    operator = $operator.name
    privacyUrl = $operator.privacyUrl
    supportEmail = $operator.supportEmail
    abuseEmail = $operator.abuseEmail
    apiTlsProtocol = $apiTls.protocol
    apiCertificateExpiresAt = $apiTls.expiresAt
    voiceTlsProtocol = $voiceTls.protocol
    voiceCertificateExpiresAt = $voiceTls.expiresAt
    cors = "windows_tauri_only"
} | ConvertTo-Json -Compress
