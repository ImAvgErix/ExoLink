$TauriArgs = @($args)

$exocordWorkspace = Split-Path -Parent $PSScriptRoot
$exocordToolchains = Join-Path $exocordWorkspace 'work\toolchains'
$exocordCargoHome = Join-Path $exocordToolchains 'cargo'
$exocordRustupHome = Join-Path $exocordToolchains 'rustup'
$exocordGccBin = Join-Path $exocordToolchains 'winlibs\mingw64\bin'
$exocordBuildBin = Join-Path $exocordToolchains 'build-bin'
$exocordPerlBin = Join-Path $exocordToolchains 'msys-perl\usr\bin'
$exocordCargoBin = Join-Path $exocordCargoHome 'bin'

if (-not (Test-Path -LiteralPath (Join-Path $exocordCargoBin 'cargo.exe'))) {
  throw 'The workspace-local Rust toolchain is missing. Install Rust normally or recreate work/toolchains.'
}

$env:CARGO_HOME = $exocordCargoHome
$env:RUSTUP_HOME = $exocordRustupHome
$exocordNativeTools = @(
  $exocordCargoBin,
  $exocordGccBin
)
if (Test-Path -LiteralPath (Join-Path $exocordBuildBin 'make.exe')) {
  $exocordNativeTools += $exocordBuildBin
}
if (Test-Path -LiteralPath (Join-Path $exocordPerlBin 'perl.exe')) {
  $exocordDrive = [IO.Path]::GetPathRoot($exocordToolchains).TrimEnd('\').TrimEnd(':').ToLowerInvariant()
  $exocordMsysToolchains = "/$exocordDrive/$($exocordToolchains.Substring(3).Replace('\', '/'))"
  $env:PERL5LIB = "$exocordMsysToolchains/msys-perl/usr/lib/perl5/core_perl`:$exocordMsysToolchains/msys-perl/usr/share/perl5/core_perl"
  $env:MSYS2_ENV_CONV_EXCL = 'PERL5LIB'
}
# Prefer Strawberry Perl for OpenSSL vendor builds (Git perl is incomplete).
$strawberryPerl = 'C:\Strawberry\perl\bin\perl.exe'
if (Test-Path -LiteralPath $strawberryPerl) {
  $env:OPENSSL_SRC_PERL = $strawberryPerl
}
$exocordGit = Get-Command git.exe -ErrorAction SilentlyContinue
if ($exocordGit) {
  $exocordGitRoot = Split-Path -Parent (Split-Path -Parent $exocordGit.Source)
  $exocordGitUsrBin = Join-Path $exocordGitRoot 'usr\bin'
  if (Test-Path -LiteralPath (Join-Path $exocordGitUsrBin 'touch.exe')) {
    $exocordNativeTools += $exocordGitUsrBin
    # Do not set OPENSSL_SRC_PERL to Git perl — it lacks modules needed by openssl-src.
  }
}
if (-not $env:OPENSSL_SRC_PERL -and (Test-Path -LiteralPath (Join-Path $exocordPerlBin 'perl.exe'))) {
  $exocordNativeTools += $exocordPerlBin
  $env:OPENSSL_SRC_PERL = Join-Path $exocordPerlBin 'perl.exe'
}
# MSVC first so rustc windows-msvc never picks Git/mingw link.exe or ar.
$exocordMsvcBin = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) {
  $vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
  if ($vsInstall) {
    $candidate = Get-ChildItem (Join-Path $vsInstall 'VC\Tools\MSVC\*\bin\Hostx64\x64') -Directory -ErrorAction SilentlyContinue |
      Select-Object -First 1 -ExpandProperty FullName
    if ($candidate) { $exocordMsvcBin = $candidate }
  }
}
$exocordPathPrefix = @($exocordNativeTools)
if ($exocordMsvcBin) {
  $exocordPathPrefix = @($exocordMsvcBin) + $exocordPathPrefix
}
$env:PATH = "$($exocordPathPrefix -join ';');$env:PATH"
# Do not force mingw CC/AR when building with the MSVC rustc target (breaks link.exe).
if ($env:CARGO_BUILD_TARGET -match 'gnu' -or $env:EXOCORD_FORCE_MINGW -eq '1') {
  $env:CC = 'gcc'
  $env:AR = 'ar'
} else {
  Remove-Item Env:CC -ErrorAction SilentlyContinue
  if ($exocordMsvcBin -and (Test-Path (Join-Path $exocordMsvcBin 'lib.exe'))) {
    $env:AR = Join-Path $exocordMsvcBin 'lib.exe'
  } else {
    Remove-Item Env:AR -ErrorAction SilentlyContinue
  }
}
# nmake (OpenSSL vendor build on MSVC) does not accept GNU -j flags.
if ($env:CARGO_BUILD_TARGET -match 'gnu' -or $env:EXOCORD_FORCE_MINGW -eq '1') {
  if (-not $env:MAKEFLAGS) {
    $env:MAKEFLAGS = "-j$([Environment]::ProcessorCount)"
  }
} else {
  Remove-Item Env:MAKEFLAGS -ErrorAction SilentlyContinue
}

if ($TauriArgs.Count -eq 0) {
  $TauriArgs = @('dev')
}

Push-Location $exocordWorkspace
try {
  & pnpm --filter '@exocord/desktop' exec tauri @TauriArgs
  exit $LASTEXITCODE
} finally {
  Pop-Location
}
