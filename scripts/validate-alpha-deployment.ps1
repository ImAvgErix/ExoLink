[CmdletBinding()]
param(
    [switch]$RequireExternalLinters
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$deployDir = Join-Path $repoRoot "deploy\alpha"
$checks = [ordered]@{}

function Assert-Condition {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,
        [Parameter(Mandatory)]
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Resolve-Tool {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [string[]]$Fallbacks = @()
    )
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    foreach ($fallback in $Fallbacks) {
        $candidate = if ([IO.Path]::IsPathRooted($fallback)) {
            $fallback
        }
        else {
            Join-Path $repoRoot $fallback
        }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $repoRoot
    )
    Push-Location $WorkingDirectory
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 promotes any native stderr line to a terminating
        # NativeCommandError under Stop, even when the process exits zero.
        $ErrorActionPreference = "Continue"
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "$FilePath failed with exit code ${exitCode}:`n$($output -join "`n")"
    }
    return $output
}

$docker = Resolve-Tool -Name "docker"
$standaloneCompose = Resolve-Tool -Name "docker-compose" -Fallbacks @(
    "work\docker-compose-v5.1.4\docker-compose-windows-x86_64.exe"
)
if ($docker) {
    $composeExe = $docker
    $composePrefix = @("compose")
}
elseif ($standaloneCompose) {
    $composeExe = $standaloneCompose
    $composePrefix = @()
}
else {
    throw "Docker Compose is required. Install the Docker Compose plugin or docker-compose."
}

function Invoke-Compose {
    param([string[]]$Arguments)
    Invoke-Checked -FilePath $composeExe `
        -Arguments @($composePrefix + $Arguments) `
        -WorkingDirectory $repoRoot
}

$baseComposeArguments = @(
    "--env-file", (Join-Path $deployDir ".env.example"),
    "-f", (Join-Path $deployDir "compose.yaml"),
    "config", "--format", "json"
)
$baseJson = Invoke-Compose -Arguments $baseComposeArguments
$base = ($baseJson -join "`n") | ConvertFrom-Json

$serviceNames = @($base.services.PSObject.Properties.Name | Sort-Object)
Assert-Condition ($serviceNames.Count -eq 3) "Compose must contain exactly three services."
Assert-Condition (
    ($serviceNames -join ",") -eq "api,caddy,postgres"
) "Compose service set must be api, caddy, and postgres."
Assert-Condition ($base.networks.backend.internal -eq $true) `
    "The PostgreSQL backend network must be internal."
Assert-Condition (
    @($base.services.api.ports | Where-Object { $null -ne $_ }).Count -eq 0
) `
    "The API must not publish a host port."
Assert-Condition (
    @($base.services.postgres.ports | Where-Object { $null -ne $_ }).Count -eq 0
) `
    "PostgreSQL must not publish a host port."

$publishedPorts = @(
    $base.services.caddy.ports |
        ForEach-Object { "$($_.published)/$($_.protocol)" } |
        Sort-Object
)
Assert-Condition (
    ($publishedPorts -join ",") -eq "443/tcp,443/udp,80/tcp"
) "Only Caddy ports 80/tcp, 443/tcp, and 443/udp may be published."
Assert-Condition ($base.services.api.read_only -eq $true) `
    "The API root filesystem must be read-only."
Assert-Condition (
    @($base.services.api.cap_drop) -contains "ALL"
) "The API must drop every Linux capability."
Assert-Condition (
    @($base.services.api.security_opt) -contains "no-new-privileges:true"
) "The API must enable no-new-privileges."
Assert-Condition (
    $base.services.api.environment.EXOCORD_ALLOWED_ORIGINS -eq
        "http://tauri.localhost"
) "The default production CORS origin must be the Windows Tauri origin."
Assert-Condition (
    $base.services.api.environment.EXOCORD_ATTACHMENT_STORAGE -eq "local"
) "The zero-provider alpha must use local attachment storage."
Assert-Condition (
    [uint64]$base.services.api.environment.EXOCORD_ATTACHMENT_MAX_STORAGE_BYTES -eq
        5368709120
) "The local alpha attachment quota must default to five GiB."
foreach ($operatorSetting in @(
    "EXOCORD_OPERATOR_NAME",
    "EXOCORD_PRIVACY_URL",
    "EXOCORD_SUPPORT_EMAIL",
    "EXOCORD_ABUSE_EMAIL"
)) {
    Assert-Condition (
        -not [string]::IsNullOrWhiteSpace(
            $base.services.api.environment.$operatorSetting
        )
    ) "Compose must publish $operatorSetting to the API."
}
Assert-Condition (
    $base.services.api.image -match "^exocord-api:[A-Za-z0-9_.-]+$"
) "The API must use a tagged local image."

$expectedApiSecrets = @(
    "attachment-capability-key",
    "attachment-object-key",
    "franking-key",
    "livekit-api-key",
    "livekit-api-secret",
    "operator-token",
    "postgres-password"
) | Sort-Object
$actualApiSecrets = @(
    $base.services.api.secrets | ForEach-Object source | Sort-Object
)
Assert-Condition (
    ($actualApiSecrets -join ",") -eq ($expectedApiSecrets -join ",")
) "The API Compose secret set is incomplete or unexpectedly expanded."

$forbiddenEnvironmentSecrets = @(
    "EXOCORD_ATTACHMENT_CAPABILITY_KEY",
    "EXOCORD_ATTACHMENT_OBJECT_KEY",
    "EXOCORD_DATABASE_PASSWORD",
    "EXOCORD_DATABASE_URL",
    "EXOCORD_FRANKING_KEY",
    "EXOCORD_LIVEKIT_API_KEY",
    "EXOCORD_LIVEKIT_API_SECRET",
    "EXOCORD_OPERATOR_TOKEN",
    "EXOCORD_R2_ACCESS_KEY_ID",
    "EXOCORD_R2_SECRET_ACCESS_KEY",
    "EXOCORD_RESEND_API_KEY"
)
$apiEnvironmentNames = @($base.services.api.environment.PSObject.Properties.Name)
foreach ($forbidden in $forbiddenEnvironmentSecrets) {
    Assert-Condition (
        $apiEnvironmentNames -notcontains $forbidden
    ) "Secret $forbidden must be file-mounted instead of set in the environment."
}
Assert-Condition (
    $base.services.api.environment.EXOCORD_OPERATOR_TOKEN_FILE -eq
        "/run/secrets/operator-token"
) "The report operator token must be file-mounted."

$expectedVolumes = [ordered]@{
    "api-state" = "exocord-alpha-api-state"
    "caddy-config" = "exocord-alpha-caddy-config"
    "caddy-data" = "exocord-alpha-caddy-data"
    "postgres-data" = "exocord-alpha-postgres-data"
}
foreach ($volume in $expectedVolumes.GetEnumerator()) {
    Assert-Condition (
        $base.volumes.($volume.Key).name -eq $volume.Value
    ) "Persistent volume $($volume.Key) does not have its stable explicit name."
}
$dockerfileText = Get-Content -Raw -LiteralPath (
    Join-Path $deployDir "Dockerfile"
)
foreach ($requiredDockerBuildText in @(
    "exocord-cargo-registry",
    "exocord-cargo-git",
    "exocord-cargo-target",
    "CARGO_PROFILE_RELEASE_LTO=false",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4",
    "find apps crates vendor -type f",
    "-exec touch {} +",
    "/out/exo-monolith"
)) {
    Assert-Condition ($dockerfileText.Contains($requiredDockerBuildText)) `
        "The resumable Oracle Docker build is missing: $requiredDockerBuildText"
}
$secretInitText = Get-Content -Raw -LiteralPath (
    Join-Path $deployDir "scripts\init-secrets.sh"
)
foreach ($requiredSecretOwnershipText in @(
    "api_uid=10001",
    "api_gid=10001",
    'chown "$api_uid:$api_gid" "$path"',
    'chmod 400 "$path"'
)) {
    Assert-Condition ($secretInitText.Contains($requiredSecretOwnershipText)) `
        "API secret ownership is missing: $requiredSecretOwnershipText"
}
$backupScriptText = Get-Content -Raw -LiteralPath (
    Join-Path $deployDir "scripts\backup-alpha.sh"
)
foreach ($requiredSafeBackupText in @(
    "read_env_value",
    "EXOCORD_BACKUP_RETENTION_SETS",
    'postgres_user="$(read_env_value POSTGRES_USER)"',
    'postgres_db="$(read_env_value POSTGRES_DB)"'
)) {
    Assert-Condition ($backupScriptText.Contains($requiredSafeBackupText)) `
        "The safe backup environment parser is missing: $requiredSafeBackupText"
}
Assert-Condition (
    -not $backupScriptText.Contains('source "$deploy_dir/.env"')
) "The backup script must not execute the Compose environment as shell code."
$checks.composeBase = "passed"

$r2Names = @(
    "EXOCORD_R2_ENDPOINT",
    "EXOCORD_R2_BUCKET",
    "EXOCORD_CDN_URL"
)
$savedR2Environment = @{}
foreach ($name in $r2Names) {
    $savedR2Environment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        "Process"
    )
}
try {
    $env:EXOCORD_R2_ENDPOINT = "https://account.r2.cloudflarestorage.com"
    $env:EXOCORD_R2_BUCKET = "exocord-alpha"
    $env:EXOCORD_CDN_URL = "https://media.alpha.example.com"
    $r2Json = Invoke-Compose -Arguments @(
        "--env-file", (Join-Path $deployDir ".env.example"),
        "-f", (Join-Path $deployDir "compose.yaml"),
        "-f", (Join-Path $deployDir "compose.r2.yaml"),
        "config", "--format", "json"
    )
}
finally {
    foreach ($name in $r2Names) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $savedR2Environment[$name],
            "Process"
        )
    }
}
$r2 = ($r2Json -join "`n") | ConvertFrom-Json
Assert-Condition (
    $r2.services.api.environment.EXOCORD_ATTACHMENT_STORAGE -eq "r2"
) "The R2 overlay must select R2 attachment storage."
$r2Secrets = @(
    $r2.services.api.secrets | ForEach-Object source | Sort-Object
)
Assert-Condition ($r2Secrets.Count -eq ($expectedApiSecrets.Count + 2)) `
    "The R2 overlay must mount exactly two additional secrets."
Assert-Condition ($r2Secrets -contains "r2-access-key-id") `
    "The R2 overlay must mount its access key ID."
Assert-Condition ($r2Secrets -contains "r2-secret-access-key") `
    "The R2 overlay must mount its secret access key."
$checks.composeR2 = "passed"

$appleNames = @(
    "EXOCORD_APPLE_CLIENT_ID",
    "EXOCORD_APPLE_TEAM_ID",
    "EXOCORD_APPLE_KEY_ID"
)
$savedAppleEnvironment = @{}
foreach ($name in $appleNames) {
    $savedAppleEnvironment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        "Process"
    )
}
try {
    $env:EXOCORD_APPLE_CLIENT_ID = "com.example.exocord.web"
    $env:EXOCORD_APPLE_TEAM_ID = "ABCDE12345"
    $env:EXOCORD_APPLE_KEY_ID = "ZYXWV9876"
    $appleJson = Invoke-Compose -Arguments @(
        "--env-file", (Join-Path $deployDir ".env.example"),
        "-f", (Join-Path $deployDir "compose.yaml"),
        "-f", (Join-Path $deployDir "compose.apple.yaml"),
        "config", "--format", "json"
    )
}
finally {
    foreach ($name in $appleNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $savedAppleEnvironment[$name],
            "Process"
        )
    }
}
$apple = ($appleJson -join "`n") | ConvertFrom-Json
$appleSecrets = @(
    $apple.services.api.secrets | ForEach-Object source | Sort-Object
)
Assert-Condition ($appleSecrets.Count -eq ($expectedApiSecrets.Count + 2)) `
    "The Apple overlay must mount exactly two additional secrets."
Assert-Condition ($appleSecrets -contains "apple-private-key") `
    "The Apple overlay must mount the Apple private key."
Assert-Condition ($appleSecrets -contains "provider-token-key") `
    "The Apple overlay must mount the provider-token encryption key."
Assert-Condition (
    $apple.services.api.environment.EXOCORD_PROVIDER_TOKEN_KEY_FILE -eq
        "/run/secrets/provider-token-key"
) "The Apple provider token key must be file-mounted."
$checks.composeApple = "passed"

$r2Policy = Get-Content -Raw -LiteralPath (Join-Path $deployDir "r2-cors.json") |
    ConvertFrom-Json
Assert-Condition ($r2Policy.Count -eq 1) "R2 must have exactly one CORS rule."
Assert-Condition (
    (@($r2Policy[0].AllowedOrigins) -join ",") -eq "http://tauri.localhost"
) "R2 CORS must allow only the Windows Tauri origin."
Assert-Condition (
    (@($r2Policy[0].AllowedMethods | Sort-Object) -join ",") -eq "GET,HEAD,PUT"
) "R2 CORS methods must be GET, HEAD, and PUT."
$checks.r2Cors = "passed"

$caddyText = Get-Content -Raw -LiteralPath (Join-Path $deployDir "Caddyfile")
foreach ($required in @(
    "request>uri delete",
    "request>remote_ip hash",
    "request>client_ip hash",
    "request>headers>User-Agent delete",
    "request>headers>X-Forwarded-For delete"
)) {
    Assert-Condition ($caddyText.Contains($required)) `
        "Caddy privacy logging is missing: $required"
}
$checks.caddyPrivacy = "passed"

$powerShellScripts = @(
    "scripts\alpha-preflight.ps1",
    "scripts\build-server-alpha.ps1",
    "scripts\install-oracle-api.ps1",
    "scripts\install-oracle-livekit.ps1",
    "scripts\triage-alpha-reports.ps1"
)
foreach ($relativeScript in $powerShellScripts) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repoRoot $relativeScript),
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    Assert-Condition ($parseErrors.Count -eq 0) `
        "$relativeScript has PowerShell parse errors."
}
$oracleApiHandoff = Get-Content -Raw -LiteralPath (
    Join-Path $repoRoot "scripts\install-oracle-api.ps1"
)
Assert-Condition (
    $oracleApiHandoff.Contains("[IO.File]::WriteAllText")
) "The Oracle API handoff must write its Linux environment as explicit text."
Assert-Condition (
    $oracleApiHandoff.Contains('(($environmentLines -join "`n") + "`n")')
) "The Oracle API handoff must use LF line endings."
Assert-Condition (
    -not $oracleApiHandoff.Contains("[IO.File]::WriteAllLines")
) "The Oracle API handoff must not use platform-native CRLF line endings."
$checks.preflightSyntax = "passed"

$systemdDir = Join-Path $deployDir "systemd"
$systemdExpectations = [ordered]@{
    "exocord-alpha-backup.service" =
        "/usr/bin/bash /opt/exocord/deploy/alpha/scripts/backup-alpha.sh"
    "exocord-alpha-backup.timer" =
        "Unit=exocord-alpha-backup.service"
    "exocord-alpha-backup-freshness.service" =
        "/usr/bin/bash /opt/exocord/deploy/alpha/scripts/verify-backup-freshness.sh"
    "exocord-alpha-backup-freshness.timer" =
        "Unit=exocord-alpha-backup-freshness.service"
}
foreach ($unit in $systemdExpectations.GetEnumerator()) {
    $unitPath = Join-Path $systemdDir $unit.Key
    Assert-Condition (
        Test-Path -LiteralPath $unitPath -PathType Leaf
    ) "Missing systemd unit: $($unit.Key)"
    $unitText = Get-Content -Raw -LiteralPath $unitPath
    Assert-Condition (
        $unitText.Contains($unit.Value)
    ) "Systemd unit $($unit.Key) does not target the expected command/unit."
}
$checks.systemdUnits = "passed"

$bash = Resolve-Tool -Name "bash" -Fallbacks @(
    "C:\Program Files\Git\bin\bash.exe"
)
$shellScripts = @(
    Get-ChildItem -LiteralPath (Join-Path $deployDir "scripts") -Filter "*.sh" |
        ForEach-Object FullName
    Get-ChildItem -LiteralPath (Join-Path $repoRoot "deploy\oracle") -Filter "*.sh" |
        ForEach-Object FullName
)
if ($bash) {
    foreach ($script in $shellScripts) {
        Invoke-Checked -FilePath $bash -Arguments @("-n", $script) | Out-Null
    }
    $checks.bashSyntax = "passed"
}
elseif ($RequireExternalLinters) {
    throw "bash is required when -RequireExternalLinters is set."
}
else {
    $checks.bashSyntax = "skipped (bash unavailable)"
}

$shellCheck = Resolve-Tool -Name "shellcheck" -Fallbacks @("work\shellcheck.exe")
if ($shellCheck) {
    Invoke-Checked -FilePath $shellCheck `
        -Arguments (@("--severity=style") + $shellScripts) | Out-Null
    $checks.shellCheck = "passed"
}
elseif ($RequireExternalLinters) {
    throw "ShellCheck is required when -RequireExternalLinters is set."
}
else {
    $checks.shellCheck = "skipped (ShellCheck unavailable)"
}

$hadolint = Resolve-Tool -Name "hadolint" -Fallbacks @(
    "work\hadolint-v2.14.0\hadolint-windows-x86_64.exe"
)
if ($hadolint) {
    Invoke-Checked -FilePath $hadolint `
        -Arguments @((Join-Path $deployDir "Dockerfile")) | Out-Null
    $checks.hadolint = "passed"
}
elseif ($RequireExternalLinters) {
    throw "Hadolint is required when -RequireExternalLinters is set."
}
else {
    $checks.hadolint = "skipped (Hadolint unavailable)"
}

$caddy = Resolve-Tool -Name "caddy" -Fallbacks @(
    "work\caddy-v2.11.4\caddy.exe"
)
if ($caddy) {
    $savedDomain = $env:EXOCORD_DOMAIN
    $savedAcmeEmail = $env:ACME_EMAIL
    try {
        $env:EXOCORD_DOMAIN = "alpha.example.com"
        $env:ACME_EMAIL = "owner@example.com"
        Invoke-Checked -FilePath $caddy `
            -Arguments @(
                "validate",
                "--config", (Join-Path $deployDir "Caddyfile"),
                "--adapter", "caddyfile"
            ) `
            -WorkingDirectory $deployDir | Out-Null
    }
    finally {
        $env:EXOCORD_DOMAIN = $savedDomain
        $env:ACME_EMAIL = $savedAcmeEmail
    }
    $checks.caddyValidate = "passed"
}
elseif ($RequireExternalLinters) {
    throw "Caddy is required when -RequireExternalLinters is set."
}
else {
    $checks.caddyValidate = "skipped (Caddy unavailable)"
}

$oracleCloudInitPath = Join-Path $repoRoot "deploy\oracle\api-cloud-init.yaml"
Assert-Condition (
    Test-Path -LiteralPath $oracleCloudInitPath -PathType Leaf
) "The Oracle API cloud-init file is missing."
$oracleCloudInit = Get-Content -Raw -LiteralPath $oracleCloudInitPath
Assert-Condition (
    $oracleCloudInit.StartsWith("#cloud-config")
) "The Oracle bootstrap must be a cloud-config document."
Assert-Condition (
    [Text.Encoding]::UTF8.GetByteCount($oracleCloudInit) -le 32000
) "The Oracle bootstrap exceeds OCI's 32,000-byte user-data limit."
foreach ($requiredBootstrapText in @(
    "docker-ce",
    "docker-compose-plugin",
    "expect",
    "PasswordAuthentication no",
    "PermitRootLogin no",
    "iptables -C INPUT -j REJECT --reject-with icmp-host-prohibited",
    "[ufw, allow, 80/tcp]",
    "[ufw, allow, 443/tcp]",
    "/var/lib/exocord-bootstrap-ready"
)) {
    Assert-Condition (
        $oracleCloudInit.Contains($requiredBootstrapText)
    ) "The Oracle bootstrap is missing: $requiredBootstrapText"
}
foreach ($forbiddenBootstrapPattern in @(
    "(?im)^\s*(password|passwd)\s*:",
    "BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY",
    "(?im)^\s*power_state\s*:",
    "(?im)\breboot\b",
    "(?im)\b5432\b",
    "(?im)\b4100\b"
)) {
    Assert-Condition (
        $oracleCloudInit -notmatch $forbiddenBootstrapPattern
    ) "The Oracle bootstrap contains a forbidden secret, reboot, or private service exposure."
}
$checks.oracleCloudInit = "passed"

$voiceCloudInitPath = Join-Path $repoRoot "deploy\oracle\voice-cloud-init.yaml"
Assert-Condition (
    Test-Path -LiteralPath $voiceCloudInitPath -PathType Leaf
) "The Oracle voice cloud-init file is missing."
$voiceCloudInit = Get-Content -Raw -LiteralPath $voiceCloudInitPath
Assert-Condition (
    $voiceCloudInit.StartsWith("#cloud-config")
) "The Oracle voice bootstrap must be a cloud-config document."
Assert-Condition (
    [Text.Encoding]::UTF8.GetByteCount($voiceCloudInit) -le 32000
) "The Oracle voice bootstrap exceeds OCI's 32,000-byte user-data limit."
foreach ($requiredVoiceBootstrapText in @(
    "PasswordAuthentication no",
    "PermitRootLogin no",
    "iptables -C INPUT -j REJECT --reject-with icmp-host-prohibited",
    "[ufw, allow, 443/udp]",
    "[ufw, allow, 7881/tcp]",
    "[ufw, allow, 3478/udp]",
    "[ufw, allow, ""50000:60000/udp""]",
    "/var/lib/exocord-voice-bootstrap-ready"
)) {
    Assert-Condition (
        $voiceCloudInit.Contains($requiredVoiceBootstrapText)
    ) "The Oracle voice bootstrap is missing: $requiredVoiceBootstrapText"
}
foreach ($forbiddenVoiceBootstrapPattern in @(
    "(?im)^\s*(password|passwd)\s*:",
    "BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY",
    "(?im)^\s*power_state\s*:",
    "(?im)\breboot\b",
    "(?im)\b5432\b",
    "(?im)\b4100\b",
    "(?im)\b7880\b"
)) {
    Assert-Condition (
        $voiceCloudInit -notmatch $forbiddenVoiceBootstrapPattern
    ) "The Oracle voice bootstrap contains a forbidden secret, reboot, or private service exposure."
}

$liveKitGenerator = Get-Content -Raw -LiteralPath (
    Join-Path $repoRoot "deploy\oracle\generate-livekit.sh"
)
foreach ($requiredGeneratorText in @(
    "docker pull livekit/generate",
    "log_user 0",
    "init_script.sh",
    "chmod 0600",
    "sha256sum"
)) {
    Assert-Condition ($liveKitGenerator.Contains($requiredGeneratorText)) `
        "The LiveKit generator wrapper is missing: $requiredGeneratorText"
}
$apiInstaller = Get-Content -Raw -LiteralPath (
    Join-Path $repoRoot "deploy\oracle\install-api-host.sh"
)
foreach ($requiredInstallerText in @(
    "sha256sum",
    "cloud-init status --wait",
    "install -m 0400 -o 10001 -g 10001",
    "bash scripts/deploy-alpha.sh",
    "bash scripts/backup-alpha.sh",
    "systemctl enable --now",
    'https://$api_domain/ready'
)) {
    Assert-Condition ($apiInstaller.Contains($requiredInstallerText)) `
    "The Oracle API installer is missing: $requiredInstallerText"
}

$upgradeScriptPath = Join-Path $repoRoot "deploy\oracle\upgrade-api-host.sh"
Assert-Condition (
    Test-Path -LiteralPath $upgradeScriptPath -PathType Leaf
) "The transactional Oracle API upgrade script is missing."
$upgradeScript = Get-Content -Raw -LiteralPath $upgradeScriptPath
foreach ($requiredUpgradeText in @(
    "sha256sum",
    "flock --nonblock",
    "backup-alpha.sh",
    ".install-source-sha256",
    "rollback_upgrade",
    "--prebuilt",
    "public readiness failed after upgrade"
)) {
    Assert-Condition ($upgradeScript.Contains($requiredUpgradeText)) `
        "The transactional Oracle upgrade is missing: $requiredUpgradeText"
}

$privateHistoryMigration = Join-Path $repoRoot (
    "apps\exo-monolith\migrations\0017_private_history_recovery.sql"
)
Assert-Condition (
    Test-Path -LiteralPath $privateHistoryMigration -PathType Leaf
) "The private-history recovery migration is missing."
$privateHistorySql = Get-Content -Raw -LiteralPath $privateHistoryMigration
foreach ($requiredHistorySql in @(
    "CREATE TABLE private_message_archives",
    "PRIMARY KEY (user_id, message_id)",
    "REFERENCES users(id) ON DELETE CASCADE",
    "REFERENCES messages(id, channel_id) ON DELETE CASCADE"
)) {
    Assert-Condition ($privateHistorySql.Contains($requiredHistorySql)) `
        "Private-history storage is missing: $requiredHistorySql"
}

$desktopCore = Get-Content -Raw -LiteralPath (
    Join-Path $repoRoot "apps\desktop\src-tauri\src\lib.rs"
)
$credentialVault = Get-Content -Raw -LiteralPath (
    Join-Path $repoRoot "apps\desktop\src-tauri\src\credentials.rs"
)
foreach ($requiredIsolationText in @(
    'const ACTIVE_ACCOUNT_FILENAME: &str = "active-account"',
    '.join("accounts")',
    '.join(account_id.to_string())',
    '.join("client.sqlite3")',
    "session_account_id",
    "upload_recovery_key_vaults"
)) {
    Assert-Condition ($desktopCore.Contains($requiredIsolationText)) `
        "Windows account isolation is missing: $requiredIsolationText"
}
foreach ($requiredVaultText in @(
    'format!("account-{account_id}")',
    '"{prefix}-refresh-session"',
    '"{prefix}-local-cache-key"',
    '"{prefix}-history-key"'
)) {
    Assert-Condition ($credentialVault.Contains($requiredVaultText)) `
        "Windows credential isolation is missing: $requiredVaultText"
}
$checks.accountRecoveryIsolation = "passed"

$oracleAlphaInstallerPath = Join-Path $repoRoot "scripts\install-oracle-alpha.ps1"
Assert-Condition (
    Test-Path -LiteralPath $oracleAlphaInstallerPath -PathType Leaf
) "The one-command Oracle alpha installer is missing."
$oracleAlphaInstaller = Get-Content -Raw -LiteralPath $oracleAlphaInstallerPath
$oracleAlphaTokens = $null
$oracleAlphaParseErrors = $null
[Management.Automation.Language.Parser]::ParseFile(
    $oracleAlphaInstallerPath,
    [ref]$oracleAlphaTokens,
    [ref]$oracleAlphaParseErrors
) | Out-Null
Assert-Condition (
    $oracleAlphaParseErrors.Count -eq 0
) "The one-command Oracle alpha installer is not valid PowerShell."
foreach ($requiredAlphaInstallerText in @(
    "UseTemporarySslipDomains",
    "api-`$apiDashIp.sslip.io",
    "voice-`$voiceDashIp.sslip.io",
    "turn-`$voiceDashIp.sslip.io",
    "install-oracle-livekit.ps1",
    "install-oracle-api.ps1",
    "UseGeneratedLiveKitCredentials",
    "AcceptNewHostKey"
)) {
    Assert-Condition ($oracleAlphaInstaller.Contains($requiredAlphaInstallerText)) `
        "The one-command Oracle installer is missing: $requiredAlphaInstallerText"
}

$offHostBackupPath = Join-Path $repoRoot "scripts\sync-oracle-backup.ps1"
Assert-Condition (
    Test-Path -LiteralPath $offHostBackupPath -PathType Leaf
) "The Oracle off-host backup handoff is missing."
$offHostBackup = Get-Content -Raw -LiteralPath $offHostBackupPath
$offHostBackupTokens = $null
$offHostBackupParseErrors = $null
[Management.Automation.Language.Parser]::ParseFile(
    $offHostBackupPath,
    [ref]$offHostBackupTokens,
    [ref]$offHostBackupParseErrors
) | Out-Null
Assert-Condition (
    $offHostBackupParseErrors.Count -eq 0
) "The Oracle off-host backup handoff is not valid PowerShell."
foreach ($requiredOffHostBackupText in @(
    "StrictHostKeyChecking=yes",
    "UserKnownHostsFile=`$knownHosts",
    "Get-FileSha256",
    "exocord-offhost-",
    "RetentionSets",
    "CreateFreshBackup",
    "[IO.FileAttributes]::Encrypted",
    "cipher /E /A"
)) {
    Assert-Condition ($offHostBackup.Contains($requiredOffHostBackupText)) `
        "The Oracle off-host backup handoff is missing: $requiredOffHostBackupText"
}
$checks.oracleHostHandoff = "passed"

[ordered]@{
    status = "passed"
    checks = $checks
} | ConvertTo-Json -Depth 4
