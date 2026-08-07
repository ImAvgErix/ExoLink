[CmdletBinding()]
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Version)) {
    $manifest = Get-Content -Raw (Join-Path $repoRoot "Cargo.toml")
    $workspaceVersion = [regex]::Match(
        $manifest,
        '(?m)^version\s*=\s*"([^"]+)"\s*$'
    )
    if (-not $workspaceVersion.Success) {
        throw "The workspace version could not be read from Cargo.toml."
    }
    $Version = $workspaceVersion.Groups[1].Value
}
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$') {
    throw "Version must be a semantic version."
}
$artifactDirectory = Join-Path $repoRoot "artifacts\server-alpha\$Version"
New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
$archiveName = "exocord-api-source-$Version.tar.gz"
$archivePath = Join-Path $artifactDirectory $archiveName
$temporaryArchive = Join-Path (
    $artifactDirectory
) ("$archiveName." + [guid]::NewGuid().ToString("N") + ".tmp")
$temporaryTar = Join-Path (
    $artifactDirectory
) ("exocord-api-source-$Version." + [guid]::NewGuid().ToString("N") + ".tar")

function Get-FileSha256 {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        [BitConverter]::ToString(
            $hasher.ComputeHash($stream)
        ).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

try {
    Push-Location $repoRoot
    try {
        $tarArguments = @(
            "-cf", $temporaryTar,
            "--format", "ustar",
            "--mtime", "2026-07-29 00:00:00Z",
            "--exclude=target",
            "--exclude=node_modules",
            "--exclude=artifacts",
            "--exclude=outputs",
            "--exclude=work",
            "--exclude=.git",
            "--exclude=.exocord",
            "--exclude=deploy/alpha/.env",
            "--exclude=deploy/alpha/backups",
            "--exclude=deploy/alpha/secrets",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".dockerignore",
            "apps/exo-monolith",
            "apps/desktop/src-tauri",
            "crates",
            "vendor",
            "deploy/alpha",
            "deploy/oracle"
        )
        & tar.exe @tarArguments
        if ($LASTEXITCODE -ne 0) {
            throw "tar failed with exit code $LASTEXITCODE."
        }
        $inputStream = [IO.File]::OpenRead($temporaryTar)
        $outputStream = [IO.File]::Create($temporaryArchive)
        $gzip = [IO.Compression.GZipStream]::new(
            $outputStream,
            [IO.Compression.CompressionMode]::Compress
        )
        try {
            $inputStream.CopyTo($gzip)
        }
        finally {
            $gzip.Dispose()
            $outputStream.Dispose()
            $inputStream.Dispose()
        }
    }
    finally {
        Pop-Location
    }

    $entries = @(& tar.exe -tzf $temporaryArchive)
    if ($LASTEXITCODE -ne 0) {
        throw "The generated source archive could not be read."
    }
    $forbidden = @(
        $entries | Where-Object {
            $_ -match '(^|/)(target|node_modules|artifacts|outputs|work|\.git|\.exocord)(/|$)' -or
            $_ -eq 'deploy/alpha/.env' -or
            $_ -match '^deploy/alpha/secrets(/|$)'
        }
    )
    if ($forbidden.Count -gt 0) {
        throw "The source archive contains forbidden entries: $($forbidden -join ', ')"
    }
    foreach ($required in @(
        "Cargo.lock",
        "apps/desktop/src-tauri/Cargo.toml",
        "apps/desktop/src-tauri/src/main.rs",
        "apps/exo-monolith/src/main.rs",
        "vendor/hpke-rs/Cargo.toml",
        "vendor/jsonwebtoken/Cargo.toml",
        "vendor/sqlx/Cargo.toml",
        "deploy/alpha/compose.yaml",
        "deploy/oracle/api-cloud-init.yaml",
        "deploy/oracle/voice-cloud-init.yaml",
        "deploy/oracle/generate-livekit.sh",
        "deploy/oracle/install-api-host.sh",
        "deploy/oracle/upgrade-api-host.sh"
    )) {
        if ($entries -notcontains $required) {
            throw "The source archive is missing $required."
        }
    }

    if (Test-Path -LiteralPath $archivePath) {
        [IO.File]::Delete($archivePath)
    }
    [IO.File]::Move($temporaryArchive, $archivePath)
    $sha256 = Get-FileSha256 -Path $archivePath
    [IO.File]::WriteAllText(
        (Join-Path $artifactDirectory "SHA256SUMS.txt"),
        "$sha256  $archiveName`n",
        [Text.UTF8Encoding]::new($false)
    )
}
finally {
    if (Test-Path -LiteralPath $temporaryArchive) {
        [IO.File]::Delete($temporaryArchive)
    }
    if (Test-Path -LiteralPath $temporaryTar) {
        [IO.File]::Delete($temporaryTar)
    }
}

[pscustomobject]@{
    archive = $archivePath
    entries = $entries.Count
    bytes = (Get-Item -LiteralPath $archivePath).Length
    sha256 = $sha256
} | ConvertTo-Json -Compress
