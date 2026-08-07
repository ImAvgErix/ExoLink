[CmdletBinding()]
param(
    [switch]$NoApp,
    [int]$ApiPort = 4100,
    [int]$VoicePort = 7880
)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
$runtimeDirectory = Join-Path $workspace "outputs\local-alpha"
$stateDirectory = Join-Path $runtimeDirectory "state"
$processRecord = Join-Path $runtimeDirectory "processes.json"
$backend = Join-Path $workspace "target\release\exo-monolith.exe"
$liveKit = Join-Path $workspace "work\toolchains\livekit-1.9.7\livekit-server.exe"
$installedApp = Join-Path $env:LOCALAPPDATA "Exocord\exocord-desktop.exe"
$portableApp = Join-Path $workspace (
    "artifacts\windows-alpha\0.1.0\" +
    "Exocord-0.1.0-alpha-x64-portable\Exocord.exe"
)

foreach ($path in @($backend, $liveKit)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required local-alpha binary is missing: $path"
    }
}
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null

function Test-TcpPort {
    param([int]$Port)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        return $client.ConnectAsync("127.0.0.1", $Port).Wait(
            [TimeSpan]::FromMilliseconds(500)
        ) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Wait-HttpHealth {
    param([string]$Url)
    for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
        try {
            if (
                (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 1).
                    Content.Trim() -eq "ok"
            ) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }
    throw "Local Exocord backend did not become healthy."
}

function Save-Environment {
    param([string[]]$Prefixes)
    $saved = @{}
    foreach ($entry in Get-ChildItem Env:) {
        if ($Prefixes | Where-Object { $entry.Name.StartsWith($_) }) {
            $saved[$entry.Name] = $entry.Value
            Remove-Item "Env:$($entry.Name)"
        }
    }
    return $saved
}

function Restore-Environment {
    param(
        [hashtable]$Saved,
        [string[]]$Prefixes
    )
    foreach ($entry in Get-ChildItem Env:) {
        if ($Prefixes | Where-Object { $entry.Name.StartsWith($_) }) {
            Remove-Item "Env:$($entry.Name)"
        }
    }
    foreach ($entry in $Saved.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable(
            $entry.Key,
            $entry.Value,
            "Process"
        )
    }
}

$managed = [ordered]@{}
if (Test-Path -LiteralPath $processRecord -PathType Leaf) {
    try {
        $previous = Get-Content -Raw -LiteralPath $processRecord |
            ConvertFrom-Json
        foreach ($name in @("api", "voice")) {
            $candidate = $previous.$name
            if (-not $candidate) {
                continue
            }
            $process = Get-Process -Id ([int]$candidate.id) `
                -ErrorAction SilentlyContinue
            if (-not $process) {
                continue
            }
            $expectedPath = [IO.Path]::GetFullPath([string]$candidate.path)
            $expectedStart = if ($candidate.startedAt -is [DateTime]) {
                $candidate.startedAt.ToUniversalTime()
            }
            else {
                [DateTimeOffset]::Parse(
                    [string]$candidate.startedAt
                ).UtcDateTime
            }
            if (
                $process.Path -and
                [IO.Path]::GetFullPath($process.Path).Equals(
                    $expectedPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                [Math]::Abs(
                    ($process.StartTime.ToUniversalTime() - $expectedStart).
                        TotalSeconds
                ) -le 1
            ) {
                $managed[$name] = [ordered]@{
                    id = $process.Id
                    path = $expectedPath
                    startedAt = $expectedStart.ToString("o")
                }
            }
        }
    }
    catch {
        $managed = [ordered]@{}
    }
}
$apiUrl = "http://127.0.0.1:$ApiPort"
try {
    $health = $null
    try {
        $health = Invoke-WebRequest -UseBasicParsing -Uri "$apiUrl/health" `
            -TimeoutSec 1
    }
    catch {}
    if (-not $health) {
        if (Test-TcpPort -Port $ApiPort) {
            throw "Port $ApiPort is in use by something other than Exocord."
        }
        $saved = Save-Environment -Prefixes @("EXOCORD_")
        try {
            $env:EXOCORD_ENV = "development"
            $env:EXOCORD_BIND = "127.0.0.1:$ApiPort"
            $env:EXOCORD_PUBLIC_API_URL = $apiUrl
            $env:EXOCORD_STATE_DIR = $stateDirectory
            $env:EXOCORD_ALLOW_DEV_AUTH = "1"
            $backendProcess = Start-Process `
                -FilePath $backend `
                -PassThru `
                -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $runtimeDirectory "api.stdout.log") `
                -RedirectStandardError (Join-Path $runtimeDirectory "api.stderr.log")
            $managed.api = [ordered]@{
                id = $backendProcess.Id
                path = $backend
                startedAt = $backendProcess.StartTime.ToUniversalTime().ToString("o")
            }
        }
        finally {
            Restore-Environment -Saved $saved -Prefixes @("EXOCORD_")
        }
        Wait-HttpHealth -Url "$apiUrl/health"
    }
    elseif ($health.Content.Trim() -ne "ok") {
        throw "Port $ApiPort did not return the Exocord health contract."
    }

    if (-not (Test-TcpPort -Port $VoicePort)) {
        $saved = Save-Environment -Prefixes @("LIVEKIT_", "NODE_IP")
        try {
            $voiceProcess = Start-Process `
                -FilePath $liveKit `
                -ArgumentList @(
                    "--dev",
                    "--bind", "127.0.0.1",
                    "--node-ip", "127.0.0.1"
                ) `
                -PassThru `
                -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $runtimeDirectory "voice.stdout.log") `
                -RedirectStandardError (Join-Path $runtimeDirectory "voice.stderr.log")
            $managed.voice = [ordered]@{
                id = $voiceProcess.Id
                path = $liveKit
                startedAt = $voiceProcess.StartTime.ToUniversalTime().ToString("o")
            }
        }
        finally {
            Restore-Environment -Saved $saved -Prefixes @("LIVEKIT_", "NODE_IP")
        }
        for ($attempt = 0; $attempt -lt 60; $attempt += 1) {
            if (Test-TcpPort -Port $VoicePort) {
                break
            }
            Start-Sleep -Milliseconds 200
        }
        if (-not (Test-TcpPort -Port $VoicePort)) {
            throw "Local LiveKit did not open port $VoicePort."
        }
    }

    if ($managed.Count -gt 0) {
        [IO.File]::WriteAllText(
            $processRecord,
            ($managed | ConvertTo-Json -Depth 4),
            [Text.UTF8Encoding]::new($false)
        )
    }

    if (-not $NoApp) {
        $application = if (Test-Path -LiteralPath $installedApp) {
            $installedApp
        }
        elseif (Test-Path -LiteralPath $portableApp) {
            $portableApp
        }
        else {
            throw "Install Exocord or rebuild the portable alpha before launching."
        }
        $saved = Save-Environment -Prefixes @("EXOCORD_API_URL")
        try {
            $env:EXOCORD_API_URL = $apiUrl
            Start-Process -FilePath $application | Out-Null
        }
        finally {
            Restore-Environment -Saved $saved -Prefixes @("EXOCORD_API_URL")
        }
    }

    [ordered]@{
        api = $apiUrl
        voice = "ws://127.0.0.1:$VoicePort"
        persistentState = $stateDirectory
        appOpened = -not $NoApp
        stopCommand = "powershell -ExecutionPolicy Bypass -File scripts/stop-local-alpha.ps1"
    } | ConvertTo-Json -Compress
}
catch {
    Write-Error $_
    throw
}
