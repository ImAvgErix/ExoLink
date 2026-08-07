[CmdletBinding()]
param(
    [string]$Template = ""
)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
$configurationPath = Join-Path $workspace "apps\desktop\src-tauri\tauri.conf.json"
$configuration = Get-Content -Raw -LiteralPath $configurationPath | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($Template)) {
    $Template = Join-Path $workspace "apps\desktop\src-tauri\windows\installer.nsi"
}
$Template = [IO.Path]::GetFullPath($Template)
if (-not (Test-Path -LiteralPath $Template -PathType Leaf)) {
    throw "NSIS template not found: $Template"
}

$templateText = [IO.File]::ReadAllText($Template)
$nsis = $configuration.bundle.windows.nsis
if ([string]$nsis.template -ne "windows/installer.nsi") {
    throw "tauri.conf.json must point NSIS at the checked-in windows/installer.nsi template."
}

function Assert-Contains {
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        [Parameter(Mandatory)]
        [string]$Needle,
        [Parameter(Mandatory)]
        [string]$Failure
    )
    if (-not $Text.Contains($Needle)) {
        throw $Failure
    }
}

function Assert-NotContains {
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        [Parameter(Mandatory)]
        [string]$Needle,
        [Parameter(Mandatory)]
        [string]$Failure
    )
    if ($Text.Contains($Needle)) {
        throw $Failure
    }
}

Assert-Contains $templateText `
    "tauri-v2.11.4" `
    "The template must document its pinned Tauri v2.11.4 source."
Assert-NotContains $templateText `
    "MUI_FINISHPAGE_SHOWREADME" `
    "The finish page must not expose the desktop-shortcut prompt."
Assert-NotContains $templateText `
    "CreateOrUpdateDesktopShortcut" `
    "The template must not contain a desktop-shortcut creation function or call."
Assert-NotContains $templateText `
    'CreateShortcut "$DESKTOP\' `
    "The template must not create any desktop shortcut."
Assert-Contains $templateText `
    'Call RemoveKnownDesktopShortcut' `
    "Install cleanup must remove a known legacy Exocord desktop link."
Assert-Contains $templateText `
    'IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk"' `
    "Desktop cleanup must verify the known Exocord link target."
Assert-Contains $templateText `
    'Delete "$DESKTOP\${PRODUCTNAME}.lnk"' `
    "Desktop cleanup must delete only the known Exocord link."
Assert-Contains $templateText `
    'Call CreateOrUpdateStartMenuShortcut' `
    "Install must retain Start Menu shortcut creation."
Assert-Contains $templateText `
    'CreateShortcut "$SMPROGRAMS\' `
    "The Start Menu shortcut creation path must remain present."

$startMenuFunction = [regex]::Match(
    $templateText,
    '(?s)Function CreateOrUpdateStartMenuShortcut.*?FunctionEnd'
).Value
if ([string]::IsNullOrWhiteSpace($startMenuFunction)) {
    throw "The Start Menu shortcut function is missing."
}
Assert-NotContains $startMenuFunction `
    '$NoShortcutMode' `
    "The /NS desktop policy must not suppress Start Menu shortcut creation."

[ordered]@{
    template = $Template
    pinnedTauri = "2.11.4"
    finishDesktopPrompt = $false
    desktopShortcutCreation = $false
    knownDesktopCleanup = $true
    startMenuShortcut = $true
} | ConvertTo-Json -Compress
