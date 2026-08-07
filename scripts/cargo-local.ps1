$CargoArgs = @($args)

$exocordWorkspace = Split-Path -Parent $PSScriptRoot
$exocordToolchains = Join-Path $exocordWorkspace 'work\toolchains'
$exocordCargoHome = Join-Path $exocordToolchains 'cargo'
$exocordRustupHome = Join-Path $exocordToolchains 'rustup'
$exocordGccBin = Join-Path $exocordToolchains 'winlibs\mingw64\bin'
$exocordBuildBin = Join-Path $exocordToolchains 'build-bin'
$exocordPerlBin = Join-Path $exocordToolchains 'msys-perl\usr\bin'
$exocordCargo = Join-Path $exocordCargoHome 'bin\cargo.exe'

if (-not (Test-Path -LiteralPath $exocordCargo)) {
  throw 'The workspace-local Rust toolchain is missing. Install Rust normally or recreate work/toolchains.'
}

$env:CARGO_HOME = $exocordCargoHome
$env:RUSTUP_HOME = $exocordRustupHome
$exocordNativeTools = @(
  (Split-Path -Parent $exocordCargo),
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
$exocordGit = Get-Command git.exe -ErrorAction SilentlyContinue
if ($exocordGit) {
  $exocordGitRoot = Split-Path -Parent (Split-Path -Parent $exocordGit.Source)
  $exocordGitUsrBin = Join-Path $exocordGitRoot 'usr\bin'
  if (Test-Path -LiteralPath (Join-Path $exocordGitUsrBin 'touch.exe')) {
    $exocordNativeTools += $exocordGitUsrBin
    $exocordGitPerl = Join-Path $exocordGitUsrBin 'perl.exe'
    if (Test-Path -LiteralPath $exocordGitPerl) {
      $env:OPENSSL_SRC_PERL = $exocordGitPerl
    }
  }
}
if (-not $env:OPENSSL_SRC_PERL -and (Test-Path -LiteralPath (Join-Path $exocordPerlBin 'perl.exe'))) {
  $exocordNativeTools += $exocordPerlBin
  $env:OPENSSL_SRC_PERL = Join-Path $exocordPerlBin 'perl.exe'
}
$env:PATH = "$($exocordNativeTools -join ';');$env:PATH"
$env:CC = 'gcc'
$env:AR = 'ar'
if (-not $env:MAKEFLAGS) {
  $env:MAKEFLAGS = "-j$([Environment]::ProcessorCount)"
}

if ($CargoArgs.Count -eq 0) {
  $CargoArgs = @('test', '--workspace')
}

& $exocordCargo @CargoArgs
exit $LASTEXITCODE
