[CmdletBinding()]
param(
    [string]$ApiUrl = "",
    [switch]$SkipChecks,
    [switch]$PackageExisting,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
$cargo = Join-Path $PSScriptRoot "cargo-local.ps1"
$tauri = Join-Path $PSScriptRoot "tauri-local.ps1"
$configuration = Get-Content -Raw (
    Join-Path $workspace "apps\desktop\src-tauri\tauri.conf.json"
) | ConvertFrom-Json
$version = $configuration.version

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspace "artifacts\windows-alpha\$version"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

$normalizedApiUrl = $null
if (-not [string]::IsNullOrWhiteSpace($ApiUrl)) {
    $parsed = $null
    if (
        -not [Uri]::TryCreate($ApiUrl.Trim(), [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne "https" -or
        [string]::IsNullOrWhiteSpace($parsed.Host) -or
        -not [string]::IsNullOrEmpty($parsed.UserInfo) -or
        -not [string]::IsNullOrEmpty($parsed.Query) -or
        -not [string]::IsNullOrEmpty($parsed.Fragment)
    ) {
        throw "ApiUrl must be a credential-free HTTPS origin with no query or fragment."
    }
    $normalizedApiUrl = $parsed.AbsoluteUri.TrimEnd("/")
}
if ($PackageExisting -and $normalizedApiUrl) {
    throw "PackageExisting cannot prove which API URL was embedded. Package an existing generic build only."
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Command,
        [Parameter(Mandatory)]
        [string]$Label
    )
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

Push-Location $workspace
try {
    & (Join-Path $PSScriptRoot "test-windows-nsis-template.ps1")
    if (-not $SkipChecks -and -not $PackageExisting) {
        Invoke-Checked {
            $formatArguments = @("fmt", "--all", "--", "--check")
            & $cargo @formatArguments
        } "Rust formatting"
        Invoke-Checked {
            & pnpm --filter "@exocord/desktop" test
        } "Renderer tests"
        Invoke-Checked {
            & $cargo test --workspace --all-targets
        } "Rust tests"
        Invoke-Checked {
            $clippyArguments = @(
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-Dwarnings"
            )
            & $cargo @clippyArguments
        } "Strict Clippy"
    }

    if (-not $PackageExisting) {
        $hadDefault = Test-Path Env:EXOCORD_DEFAULT_API_URL
        $previousDefault = $env:EXOCORD_DEFAULT_API_URL
        try {
            if ($normalizedApiUrl) {
                $env:EXOCORD_DEFAULT_API_URL = $normalizedApiUrl
            }
            else {
                Remove-Item Env:EXOCORD_DEFAULT_API_URL -ErrorAction SilentlyContinue
            }
            Invoke-Checked {
                & $tauri build
            } "Windows alpha build"
        }
        finally {
            if ($hadDefault) {
                $env:EXOCORD_DEFAULT_API_URL = $previousDefault
            }
            else {
                Remove-Item Env:EXOCORD_DEFAULT_API_URL -ErrorAction SilentlyContinue
            }
        }
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $builtInstaller = Join-Path $workspace (
        "target\release\bundle\nsis\Exocord_{0}_x64-setup.exe" -f $version
    )
    $builtPortable = Join-Path $workspace "target\release\exocord-desktop.exe"
    $builtWebViewLoader = Join-Path $workspace "target\release\WebView2Loader.dll"
    if (-not (Test-Path -LiteralPath $builtInstaller)) {
        throw "The NSIS installer was not produced at $builtInstaller."
    }
    if (-not (Test-Path -LiteralPath $builtPortable)) {
        throw "The portable executable was not produced at $builtPortable."
    }
    if (-not (Test-Path -LiteralPath $builtWebViewLoader)) {
        throw "The x64 WebView2 loader was not produced at $builtWebViewLoader."
    }

    $installer = Join-Path $OutputDirectory (
        "Exocord-{0}-alpha-x64-setup.exe" -f $version
    )
    $portableDirectory = Join-Path $OutputDirectory (
        "Exocord-{0}-alpha-x64-portable" -f $version
    )
    $guide = Join-Path $OutputDirectory "WINDOWS-ALPHA.md"
    $portableArchive = Join-Path $OutputDirectory (
        "Exocord-{0}-alpha-x64-portable.zip" -f $version
    )
    $legacyBrokenPortable = Join-Path $OutputDirectory (
        "Exocord-{0}-alpha-x64-portable.exe" -f $version
    )
    $portablePath = [IO.Path]::GetFullPath($portableDirectory)
    $outputPathPrefix = $OutputDirectory.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    if (-not $portablePath.StartsWith(
        $outputPathPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing to replace portable directory outside $OutputDirectory."
    }
    if (Test-Path -LiteralPath $portablePath) {
        Remove-Item -LiteralPath $portablePath -Recurse -Force
    }
    if (Test-Path -LiteralPath $legacyBrokenPortable) {
        Remove-Item -LiteralPath $legacyBrokenPortable -Force
    }
    New-Item -ItemType Directory -Path $portablePath | Out-Null

    $portableExecutable = Join-Path $portablePath "Exocord.exe"
    $portableWebViewLoader = Join-Path $portablePath "WebView2Loader.dll"
    $portableGuide = Join-Path $portablePath "WINDOWS-ALPHA.md"
    Copy-Item -LiteralPath $builtInstaller -Destination $installer -Force
    Copy-Item -LiteralPath $builtPortable -Destination $portableExecutable -Force
    Copy-Item -LiteralPath $builtWebViewLoader -Destination $portableWebViewLoader -Force
    Copy-Item -LiteralPath (
        Join-Path $workspace "docs\windows-alpha.md"
    ) -Destination $guide -Force
    Copy-Item -LiteralPath $guide -Destination $portableGuide -Force
    Compress-Archive -Path $portablePath -DestinationPath $portableArchive -Force

    $releaseFiles = @($installer, $portableArchive)
    $checksumPath = Join-Path $OutputDirectory "SHA256SUMS.txt"
    $checksums = $releaseFiles | ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_
        "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), (Split-Path -Leaf $_)
    }
    [IO.File]::WriteAllLines(
        $checksumPath,
        [string[]]$checksums,
        [Text.UTF8Encoding]::new($false)
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    [ordered]@{
        version = $version
        apiUrl = if ($normalizedApiUrl) { $normalizedApiUrl } else { "first-run setup" }
        outputDirectory = $OutputDirectory
        installer = $installer
        portableZip = $portableArchive
        checksums = $checksumPath
        signatureStatus = $signature.Status.ToString()
    } | ConvertTo-Json
}
finally {
    Pop-Location
}
