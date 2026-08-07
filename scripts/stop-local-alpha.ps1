[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
$runtimeDirectory = Join-Path $workspace "outputs\local-alpha"
$processRecord = Join-Path $runtimeDirectory "processes.json"
if (-not (Test-Path -LiteralPath $processRecord -PathType Leaf)) {
    Write-Output "No managed local alpha processes were recorded."
    exit 0
}

$record = Get-Content -Raw -LiteralPath $processRecord | ConvertFrom-Json
$stopped = @()
foreach ($name in @("api", "voice")) {
    $managed = $record.$name
    if (-not $managed) {
        continue
    }
    $process = Get-Process -Id ([int]$managed.id) -ErrorAction SilentlyContinue
    if (-not $process) {
        continue
    }
    $expectedPath = [IO.Path]::GetFullPath([string]$managed.path)
    $actualPath = [IO.Path]::GetFullPath($process.Path)
    $expectedStart = if ($managed.startedAt -is [DateTime]) {
        $managed.startedAt.ToUniversalTime()
    }
    else {
        [DateTimeOffset]::Parse([string]$managed.startedAt).UtcDateTime
    }
    $actualStart = $process.StartTime.ToUniversalTime()
    if (
        -not $actualPath.Equals(
            $expectedPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -gt 1
    ) {
        throw "Refusing to stop reused or unexpected process ID $($managed.id)."
    }
    Stop-Process -Id $process.Id
    Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    $stopped += $name
}

Remove-Item -LiteralPath $processRecord -Force
[ordered]@{
    stopped = $stopped
    statePreserved = (Join-Path $runtimeDirectory "state")
} | ConvertTo-Json -Compress
