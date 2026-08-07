[CmdletBinding()]
param(
    [string]$Installer = "",
    [int]$WindowTimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
$configuration = Get-Content -Raw -LiteralPath (
    Join-Path $workspace "apps\desktop\src-tauri\tauri.conf.json"
) | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($Installer)) {
    $Installer = Join-Path $workspace (
        "artifacts\windows-alpha\{0}\Exocord-{0}-alpha-x64-setup.exe" -f
            $configuration.version
    )
}
$Installer = [IO.Path]::GetFullPath($Installer)
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "Installer not found: $Installer"
}

$installedDirectory = Join-Path $env:LOCALAPPDATA "Exocord"
$installedExecutable = Join-Path $installedDirectory "exocord-desktop.exe"
$installedLoader = Join-Path $installedDirectory "WebView2Loader.dll"
$releaseLoader = Join-Path $workspace "target\release\WebView2Loader.dll"
$desktopDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::DesktopDirectory
)
$knownDesktopShortcut = Join-Path $desktopDirectory (
    "{0}.lnk" -f $configuration.productName
)
$desktopLinksBefore = @(
    if (Test-Path -LiteralPath $desktopDirectory -PathType Container) {
        Get-ChildItem -LiteralPath $desktopDirectory -Filter "*.lnk" -File |
            ForEach-Object FullName
    }
)

$installerProcess = Start-Process `
    -FilePath $Installer `
    -ArgumentList @("/S", "/NS") `
    -PassThru `
    -Wait `
    -WindowStyle Hidden
if ($installerProcess.ExitCode -ne 0) {
    throw "The silent per-user installer exited $($installerProcess.ExitCode)."
}
$desktopLinksAfter = @(
    if (Test-Path -LiteralPath $desktopDirectory -PathType Container) {
        Get-ChildItem -LiteralPath $desktopDirectory -Filter "*.lnk" -File |
            ForEach-Object FullName
    }
)
$newDesktopLinks = @(
    $desktopLinksAfter | Where-Object { $desktopLinksBefore -notcontains $_ }
)
if ($newDesktopLinks.Count -gt 0) {
    throw "The installer created desktop shortcut(s): $($newDesktopLinks -join ', ')"
}
$unexpectedRemovedDesktopLinks = @(
    $desktopLinksBefore |
        Where-Object {
            $desktopLinksAfter -notcontains $_ -and
            $_ -ine $knownDesktopShortcut
        }
)
if ($unexpectedRemovedDesktopLinks.Count -gt 0) {
    throw "The installer removed unrelated desktop shortcut(s): $($unexpectedRemovedDesktopLinks -join ', ')"
}
foreach ($path in @($installedExecutable, $installedLoader, $releaseLoader)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Expected native release file is missing: $path"
    }
}
$installedLoaderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedLoader).Hash
$releaseLoaderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $releaseLoader).Hash
if ($installedLoaderHash -ne $releaseLoaderHash) {
    throw "The installed WebView2 loader does not match the release architecture."
}

$application = Start-Process -FilePath $installedExecutable -PassThru
try {
    $deadline = [DateTime]::UtcNow.AddSeconds($WindowTimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 200
        $application.Refresh()
    } while (
        -not $application.HasExited -and
        [string]::IsNullOrWhiteSpace($application.MainWindowTitle) -and
        [DateTime]::UtcNow -lt $deadline
    )
    if ($application.HasExited) {
        throw "The installed app exited before opening its window."
    }
    if ($application.MainWindowTitle -ne "Exocord") {
        throw "The installed app did not reach the Exocord window."
    }
    [ordered]@{
        installerExitCode = $installerProcess.ExitCode
        installerArguments = @("/S", "/NS")
        installedExecutable = $installedExecutable
        windowTitle = $application.MainWindowTitle
        webView2LoaderSha256 = $installedLoaderHash
    } | ConvertTo-Json -Compress
}
finally {
    if (-not $application.HasExited) {
        $application.CloseMainWindow() | Out-Null
        if (-not $application.WaitForExit(5000)) {
            Stop-Process -Id $application.Id
        }
    }
}
