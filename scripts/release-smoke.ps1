param(
    [string]$Binary = ".\target\release\exo-monolith.exe",
    [int]$Port = 4413
)

$ErrorActionPreference = "Stop"
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$smokeRoot = Join-Path $temporaryRoot (
    "exocord-release-smoke-" + [guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $smokeRoot | Out-Null

$stdoutPath = Join-Path $smokeRoot "stdout.log"
$stderrPath = Join-Path $smokeRoot "stderr.log"
$baseUrl = "http://127.0.0.1:$Port"
$process = $null

try {
    $env:EXOCORD_ENV = "development"
    $env:EXOCORD_BIND = "127.0.0.1:$Port"
    $env:EXOCORD_PUBLIC_API_URL = $baseUrl
    $env:EXOCORD_STATE_DIR = $smokeRoot
    $env:EXOCORD_OPERATOR_NAME = "Exocord Release Smoke"
    $env:EXOCORD_PRIVACY_URL = "https://alpha.example.test/privacy"
    $env:EXOCORD_TERMS_URL = "https://alpha.example.test/terms"
    $env:EXOCORD_SUPPORT_EMAIL = "help@alpha.example.test"
    $env:EXOCORD_ABUSE_EMAIL = "abuse@alpha.example.test"
    $env:EXOCORD_OPERATOR_TOKEN = "exo_op_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    Remove-Item Env:EXOCORD_DATABASE_URL -ErrorAction SilentlyContinue

    $process = Start-Process `
        -FilePath $Binary `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $started = $false
    for ($attempt = 0; $attempt -lt 50; $attempt += 1) {
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/health" -TimeoutSec 1
            $started = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $started) {
        throw "Release backend did not start."
    }

    $ready = Invoke-RestMethod -Uri "$baseUrl/ready"
    $capabilities = Invoke-RestMethod -Uri "$baseUrl/v1/meta/capabilities"
    $operator = Invoke-RestMethod -Uri "$baseUrl/v1/meta/operator"
    $privacy = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/privacy"
    $terms = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/terms"
    if (
        $operator.name -ne "Exocord Release Smoke" -or
        $privacy.StatusCode -ne 200 -or
        $privacy.Content -notmatch 'data-exocord-policy="privacy-v2"' -or
        ($privacy.Headers["Content-Security-Policy"] -join "") -notmatch
            "default-src 'none'" -or
        $terms.StatusCode -ne 200 -or
        $terms.Content -notmatch 'data-exocord-policy="terms-v2"'
    ) {
        throw "Release operator metadata or policy pages did not pass."
    }
    try {
        Invoke-WebRequest `
            -UseBasicParsing `
            -Uri "$baseUrl/v1/operator/reports" `
            -Headers @{ Authorization = "Bearer exo_at_not-an-operator-token" } |
            Out-Null
        throw "A normal account-style token reached the operator report API."
    }
    catch {
        if (
            -not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 401
        ) {
            throw
        }
    }
    $operatorReports = Invoke-WebRequest `
        -UseBasicParsing `
        -Uri "$baseUrl/v1/operator/reports?status=open&limit=10" `
        -Headers @{ Authorization = "Bearer $env:EXOCORD_OPERATOR_TOKEN" }
    if (
        $operatorReports.StatusCode -ne 200 -or
        $operatorReports.Content -ne "[]" -or
        ($operatorReports.Headers["Cache-Control"] -join "") -ne
            "no-store, private"
    ) {
        throw "The release operator report boundary did not pass."
    }

    $accountPassword = "release smoke private password"
    $accountEmail = "release-smoke-$([guid]::NewGuid().ToString('N'))@example.test"
    $accountDevice = "018f04b2-3c71-7f42-b12d-6f090d44be31"
    $accountLoginBody = @{
        email = $accountEmail
        password = $accountPassword
        deviceId = $accountDevice
        clientName = "Release enforcement smoke"
    } | ConvertTo-Json
    $registeredAccount = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/v1/auth/password/register" `
        -ContentType "application/json" `
        -Body $accountLoginBody
    $accountId = $registeredAccount.user.id
    $accountUri = "$baseUrl/v1/operator/users/$accountId/suspension"
    try {
        Invoke-WebRequest `
            -UseBasicParsing `
            -Uri $accountUri `
            -Headers @{
                Authorization = "Bearer $($registeredAccount.accessToken)"
            } |
            Out-Null
        throw "A normal account token reached account enforcement."
    }
    catch {
        if (
            -not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 401
        ) {
            throw
        }
    }
    $operatorHeaders = @{
        Authorization = "Bearer $env:EXOCORD_OPERATOR_TOKEN"
    }
    $suspendedAccount = Invoke-WebRequest `
        -UseBasicParsing `
        -Method Put `
        -Uri $accountUri `
        -Headers $operatorHeaders `
        -ContentType "application/json" `
        -Body (@{
            reason = "Release account-enforcement boundary test."
        } | ConvertTo-Json)
    $suspendedAccountBody = $suspendedAccount.Content | ConvertFrom-Json
    if (
        $suspendedAccount.StatusCode -ne 200 -or
        -not $suspendedAccountBody.suspended -or
        ($suspendedAccount.Headers["Cache-Control"] -join "") -ne
            "no-store, private"
    ) {
        throw "The release account suspension response did not pass."
    }
    try {
        Invoke-WebRequest `
            -UseBasicParsing `
            -Uri "$baseUrl/v1/auth/me" `
            -Headers @{
                Authorization = "Bearer $($registeredAccount.accessToken)"
            } |
            Out-Null
        throw "Account suspension did not revoke the old session."
    }
    catch {
        if (
            -not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 401
        ) {
            throw
        }
    }
    try {
        Invoke-WebRequest `
            -UseBasicParsing `
            -Method Post `
            -Uri "$baseUrl/v1/auth/password/login" `
            -ContentType "application/json" `
            -Body $accountLoginBody |
            Out-Null
        throw "Account suspension did not block a new login."
    }
    catch {
        if (
            -not $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 403
        ) {
            throw
        }
    }
    $accountOverview = Invoke-RestMethod `
        -Uri $accountUri `
        -Headers $operatorHeaders
    if (
        -not $accountOverview.suspension.suspended -or
        $accountOverview.events.Count -ne 1 -or
        $accountOverview.events[0].action -ne "suspended"
    ) {
        throw "The release account-enforcement audit did not pass."
    }
    $reinstatedAccount = Invoke-RestMethod `
        -Method Delete `
        -Uri $accountUri `
        -Headers $operatorHeaders `
        -ContentType "application/json" `
        -Body (@{
            reason = "Release test reinstatement."
        } | ConvertTo-Json)
    if ($reinstatedAccount.suspended) {
        throw "The release account reinstatement did not pass."
    }
    $freshAccountSession = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/v1/auth/password/login" `
        -ContentType "application/json" `
        -Body $accountLoginBody
    if ($freshAccountSession.accessToken -notlike "exo_at_*") {
        throw "The reinstated release account could not start a fresh session."
    }

    $headers = @{ "x-exocord-user-id" = "1" }
    $sync = Invoke-RestMethod -Uri "$baseUrl/v1/sync" -Headers $headers
    $channelId = (
        $sync.channels |
            Where-Object { $_.kind -eq "text" } |
            Select-Object -First 1
    ).id
    if (-not $channelId) {
        throw "Release sync did not return a text channel."
    }

    $root = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/v1/channels/$channelId/messages" `
        -Headers $headers `
        -ContentType "application/json" `
        -Body (@{
            content = "release smoke root"
            nonce = "release-smoke-root"
        } | ConvertTo-Json)
    $reply = Invoke-RestMethod `
        -Method Post `
        -Uri "$baseUrl/v1/channels/$channelId/messages" `
        -Headers $headers `
        -ContentType "application/json" `
        -Body (@{
            content = "release smoke reply"
            nonce = "release-smoke-reply"
            reply_to = $root.id
        } | ConvertTo-Json)
    $edited = Invoke-RestMethod `
        -Method Patch `
        -Uri "$baseUrl/v1/channels/$channelId/messages/$($reply.id)" `
        -Headers $headers `
        -ContentType "application/json" `
        -Body (@{
            content = "release smoke edited"
            nonce = "release-smoke-edit"
        } | ConvertTo-Json)
    $thumbsUp = [char]::ConvertFromUtf32(0x1F44D)
    $reactionBody = [Text.Encoding]::UTF8.GetBytes(
        (@{ emoji = $thumbsUp } | ConvertTo-Json)
    )
    $reaction = Invoke-RestMethod `
        -Method Put `
        -Uri "$baseUrl/v1/channels/$channelId/messages/$($reply.id)/reactions" `
        -Headers $headers `
        -ContentType "application/json; charset=utf-8" `
        -Body $reactionBody

    $listed = Invoke-RestMethod `
        -Uri "$baseUrl/v1/channels/$channelId/messages?limit=100" `
        -Headers $headers
    $stored = $listed | Where-Object { $_.id -eq $reply.id }
    if (
        $stored.reply_to -ne $root.id -or
        $stored.content -ne "release smoke edited" -or
        $stored.reactions[0].count -ne 1 -or
        -not $stored.reactions[0].me
    ) {
        throw "Release conversation state did not round-trip."
    }

    Invoke-RestMethod `
        -Method Delete `
        -Uri "$baseUrl/v1/channels/$channelId/messages/$($reply.id)" `
        -Headers $headers |
        Out-Null
    $afterDelete = Invoke-RestMethod `
        -Uri "$baseUrl/v1/channels/$channelId/messages?limit=100" `
        -Headers $headers
    if ($afterDelete | Where-Object { $_.id -eq $reply.id }) {
        throw "Release delete did not remove the message."
    }

    [pscustomobject]@{
        health = $health
        ready = $ready.ready
        storage = $ready.storage
        conversationActions = $capabilities.conversation_actions
        operator = $operator.name
        privacy = ($privacy.StatusCode -eq 200)
        terms = ($terms.StatusCode -eq 200)
        operatorReportsSecured = $true
        operatorAccountEnforcementSecured = $true
        reply = ($reply.reply_to -eq $root.id)
        edited = ($edited.content -eq "release smoke edited")
        reactionCount = $reaction.count
        deleted = $true
    } | ConvertTo-Json -Compress
}
catch {
    if (Test-Path -LiteralPath $stderrPath) {
        $stderr = Get-Content -LiteralPath $stderrPath -Raw
        if ($stderr) {
            Write-Error $stderr
        }
    }
    throw
}
finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id
        Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
    }
    $resolvedSmokeRoot = [IO.Path]::GetFullPath($smokeRoot)
    if (
        $resolvedSmokeRoot.StartsWith(
            $temporaryRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -and
        (Test-Path -LiteralPath $resolvedSmokeRoot)
    ) {
        Remove-Item -LiteralPath $resolvedSmokeRoot -Recurse -Force
    }
}
