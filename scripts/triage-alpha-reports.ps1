[CmdletBinding(
    DefaultParameterSetName = "List",
    SupportsShouldProcess,
    ConfirmImpact = "Medium"
)]
param(
    [Parameter(Mandatory)]
    [string]$ApiHost,
    [Parameter(Mandatory)]
    [string]$ApiUrl,
    [Parameter(Mandatory)]
    [string]$SshPrivateKey,
    [string]$SshUser = "ubuntu",
    [Parameter(ParameterSetName = "List")]
    [ValidateSet("open", "actioned", "dismissed", "all")]
    [string]$Status = "open",
    [Parameter(ParameterSetName = "List")]
    [ValidateRange(1, 100)]
    [int]$Limit = 50,
    [Parameter(ParameterSetName = "Resolve", Mandatory)]
    [Parameter(ParameterSetName = "Account")]
    [string]$ReportId,
    [Parameter(ParameterSetName = "Resolve", Mandatory)]
    [ValidateSet("actioned", "dismissed")]
    [string]$Disposition,
    [Parameter(ParameterSetName = "Resolve")]
    [string]$Note,
    [Parameter(ParameterSetName = "Account", Mandatory)]
    [string]$UserId,
    [Parameter(ParameterSetName = "Account", Mandatory)]
    [ValidateSet("status", "suspend", "reinstate")]
    [string]$AccountAction,
    [Parameter(ParameterSetName = "Account")]
    [string]$Reason,
    [switch]$AsJson,
    [switch]$AcceptNewHostKey
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$repoRoot = Split-Path -Parent $PSScriptRoot
$SshPrivateKey = [IO.Path]::GetFullPath($SshPrivateKey)

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

function Invoke-CapturedProgram {
    param(
        [Parameter(Mandatory)]
        [string]$Program,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Program
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "Could not start $Program."
        }
        $standardOutput = $process.StandardOutput.ReadToEnd()
        $standardError = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            $detail = $standardError.Trim()
            if ([string]::IsNullOrWhiteSpace($detail)) {
                $detail = "no diagnostic output"
            }
            throw "$Program failed with exit code $($process.ExitCode): $detail"
        }
        $standardOutput
    }
    finally {
        $process.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $SshPrivateKey -PathType Leaf)) {
    throw "SSH private key not found: $SshPrivateKey"
}
if (-not (Get-Command "ssh.exe" -ErrorAction SilentlyContinue)) {
    throw "ssh.exe is required from Windows OpenSSH."
}
if ($SshUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw "SshUser is invalid."
}

$parsedIp = $null
if (
    -not [Net.IPAddress]::TryParse($ApiHost, [ref]$parsedIp) -or
    $parsedIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    -not (Test-PublicIpv4 $parsedIp)
) {
    throw "ApiHost must be the Oracle API instance's public IPv4 address."
}

$parsedApi = $null
if (
    -not [Uri]::TryCreate($ApiUrl.Trim(), [UriKind]::Absolute, [ref]$parsedApi) -or
    $parsedApi.Scheme -ne "https" -or
    -not [string]::IsNullOrEmpty($parsedApi.UserInfo) -or
    -not [string]::IsNullOrEmpty($parsedApi.Query) -or
    -not [string]::IsNullOrEmpty($parsedApi.Fragment) -or
    $parsedApi.AbsolutePath -ne "/"
) {
    throw "ApiUrl must be a credential-free HTTPS origin with no path, query, or fragment."
}
$apiOrigin = $parsedApi.AbsoluteUri.TrimEnd("/")

if ($PSCmdlet.ParameterSetName -eq "Resolve") {
    if ($ReportId -notmatch '^[1-9][0-9]{0,19}$') {
        throw "ReportId must be a positive decimal report ID."
    }
    if ($Note.Length -gt 1000) {
        throw "Note cannot exceed 1,000 characters."
    }
}
if ($PSCmdlet.ParameterSetName -eq "Account") {
    if ($UserId -notmatch '^[1-9][0-9]{0,19}$') {
        throw "UserId must be a positive decimal user ID."
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportId) -and $ReportId -notmatch '^[1-9][0-9]{0,19}$') {
        throw "ReportId must be a positive decimal report ID."
    }
    if ($AccountAction -ne "status") {
        if ([string]::IsNullOrWhiteSpace($Reason)) {
            throw "Reason is required when suspending or reinstating an account."
        }
        if ($Reason.Trim().Length -gt 1000) {
            throw "Reason cannot exceed 1,000 characters."
        }
    }
}

$runtimeDirectory = Join-Path $repoRoot "outputs\oracle-alpha"
New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
$knownHosts = Join-Path $runtimeDirectory "known_hosts"
$strictHostKeyChecking = if ($AcceptNewHostKey) { "accept-new" } else { "yes" }
$sshArguments = @(
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "ConnectTimeout=15",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
    "-o", "StrictHostKeyChecking=$strictHostKeyChecking",
    "-o", "UserKnownHostsFile=$knownHosts",
    "-i", $SshPrivateKey,
    "${SshUser}@${ApiHost}",
    "sudo -n cat /opt/exocord/deploy/alpha/secrets/operator-token"
)

$operatorToken = $null
try {
    $operatorToken = (
        Invoke-CapturedProgram -Program "ssh.exe" -Arguments $sshArguments
    ).Trim()
    if ($operatorToken -notmatch '^exo_op_[A-Za-z0-9_-]{43}$') {
        throw "The API host returned an invalid operator credential."
    }
    $headers = @{
        Authorization = "Bearer $operatorToken"
        Accept = "application/json"
    }

    if ($PSCmdlet.ParameterSetName -eq "List") {
        $uri = "$apiOrigin/v1/operator/reports?status=$Status&limit=$Limit"
        $reports = @(
            Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        )
        if ($AsJson) {
            $reports | ConvertTo-Json -Depth 12
        }
        else {
            $reports
        }
        return
    }

    if ($PSCmdlet.ParameterSetName -eq "Account") {
        $accountUri = "$apiOrigin/v1/operator/users/$UserId/suspension"
        if ($AccountAction -eq "status") {
            $account = Invoke-RestMethod -Method Get -Uri $accountUri -Headers $headers
            if ($AsJson) {
                $account | ConvertTo-Json -Depth 12
            }
            else {
                $account
            }
            return
        }

        $target = "account $UserId on $apiOrigin"
        if (-not $PSCmdlet.ShouldProcess($target, "$AccountAction account")) {
            return
        }
        $payload = @{
            reason = $Reason.Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($ReportId)) {
            $payload.reportId = $ReportId
        }
        $method = if ($AccountAction -eq "suspend") { "Put" } else { "Delete" }
        $account = Invoke-RestMethod `
            -Method $method `
            -Uri $accountUri `
            -Headers $headers `
            -ContentType "application/json" `
            -Body ($payload | ConvertTo-Json -Compress)
        if ($AsJson) {
            $account | ConvertTo-Json -Depth 12
        }
        else {
            $account
        }
        return
    }

    $target = "report $ReportId on $apiOrigin"
    if (-not $PSCmdlet.ShouldProcess($target, "Mark report $Disposition")) {
        return
    }
    $payload = @{
        status = $Disposition
    }
    if (-not [string]::IsNullOrWhiteSpace($Note)) {
        $payload.note = $Note.Trim()
    }
    $resolved = Invoke-RestMethod `
        -Method Put `
        -Uri "$apiOrigin/v1/operator/reports/$ReportId" `
        -Headers $headers `
        -ContentType "application/json" `
        -Body ($payload | ConvertTo-Json -Compress)
    if ($AsJson) {
        $resolved | ConvertTo-Json -Depth 12
    }
    else {
        $resolved
    }
}
finally {
    $operatorToken = $null
    $headers = $null
}
