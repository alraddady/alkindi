#Requires -Version 5.1
<#
.SYNOPSIS
    Build a minimal static OpenSSL for Windows (MSVC x64).
    Mirrors the feature flags in scripts/build_openssl.sh.
#>

$ErrorActionPreference = 'Stop'

# Paths
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$VersionsFile = Join-Path $ScriptDir '..\build.env'
$BuildDir     = Join-Path $ScriptDir 'openssl-build'
$DownloadDir  = Join-Path $BuildDir  'downloads'
$InstallDir   = Join-Path $BuildDir  'install'

# Read version from build.env
if (-not (Test-Path $VersionsFile)) {
    Write-Error "build.env not found at $VersionsFile"
    exit 1
}

$OpenSslVersion = (Get-Content $VersionsFile |
    Where-Object { $_ -match '^OPENSSL_VERSION=' } |
    Select-Object -First 1) -replace '^OPENSSL_VERSION=', ''

if (-not $OpenSslVersion) {
    Write-Error "OPENSSL_VERSION not found in build.env"
    exit 1
}

Write-Host "[INFO] OpenSSL version: $OpenSslVersion"
Write-Host "[INFO] Install prefix:  $InstallDir"

# Find MSVC via vswhere
$VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $VsWhere)) {
    Write-Error "vswhere.exe not found"
    exit 1
}

$VsPath = & $VsWhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

if (-not $VsPath) {
    Write-Error "No Visual Studio installation with C++ tools found."
    exit 1
}

$VcVarsAll = Join-Path $VsPath 'VC\Auxiliary\Build\vcvarsall.bat'
Write-Host "[INFO] Using MSVC from: $VsPath"

# Verify Perl
if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
    Write-Error "perl not found -- Strawberry Perl is required."
    exit 1
}

Write-Host "[INFO] Perl: $(perl --version | Select-String 'v\d+\.\d+\.\d+')"

# Download
New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir  | Out-Null

$TarName = "openssl-$OpenSslVersion.tar.gz"
$TarPath = Join-Path $DownloadDir $TarName
$Url     = "https://github.com/openssl/openssl/releases/download/openssl-$OpenSslVersion/$TarName"

if (-not (Test-Path $TarPath)) {
    Write-Host "[INFO] Downloading OpenSSL $OpenSslVersion..."
    Invoke-WebRequest -Uri $Url -OutFile $TarPath -UseBasicParsing
} else {
    Write-Host "[INFO] Tarball already present, skipping download."
}

# Extract
$SourceDir = Join-Path $DownloadDir "openssl-$OpenSslVersion"
if (Test-Path $SourceDir) {
    Write-Host "[INFO] Removing existing source directory..."
    Remove-Item -Recurse -Force $SourceDir
}

Write-Host "[INFO] Extracting..."
tar -xzf $TarPath -C $DownloadDir

# Forward slashes required by OpenSSL's Configure script on Windows.
$InstallDirFwd = $InstallDir -replace '\\', '/'

$Flags = @(
    'VC-WIN64A',
    "--prefix=$InstallDirFwd",
    "--openssldir=$InstallDirFwd/ssl",
    'no-shared',
    'no-tls', 'no-dtls', 'no-ssl', 'no-quic',
    'no-aria', 'no-bf', 'no-blake2', 'no-camellia', 'no-cast', 'no-chacha', 'no-cmac',
    'no-des', 'no-dh', 'no-dsa', 'no-ecdh', 'no-ecdsa', 'no-idea', 'no-md4', 'no-mdc2',
    'no-ocb', 'no-poly1305', 'no-rc2', 'no-rc4', 'no-rmd160', 'no-scrypt',
    'no-seed', 'no-siphash', 'no-siv', 'no-sm2', 'no-sm3', 'no-sm4', 'no-whirlpool',
    'no-ec', 'no-ec2m',
    'no-dso', 'no-legacy', 'no-module',
    'no-fips-securitychecks', 'no-fips-post',
    'no-cmp', 'no-cms', 'no-comp', 'no-ct',
    'no-deprecated', 'no-docs',
    'no-gost', 'no-http',
    'no-nextprotoneg', 'no-ocsp',
    'no-psk', 'no-rfc3779',
    'no-sock', 'no-sm2-precomp', 'no-srp', 'no-srtp',
    'no-ssl-trace', 'no-ts', 'no-uplink',
    'no-apps', 'no-async', 'no-autoload-config',
    'no-dgram', 'no-filenames', 'no-makedepend', 'no-tests',
    'no-thread-pool', 'no-default-thread-pool', 'no-ui-console'
)

# Run all MSVC-dependent steps inside a single cmd.exe session that already
# has vcvarsall set up. This avoids the need to absorb env vars into PowerShell.
$FlagsStr  = $Flags -join ' '
$BuildBat = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
$BatchContent = @"
@echo off
call "$VcVarsAll" x64
if errorlevel 1 exit /b 1
cd /d "$SourceDir"
perl Configure $FlagsStr
if errorlevel 1 exit /b 1
nmake /S /NOLOGO
if errorlevel 1 exit /b 1
nmake /S /NOLOGO install_sw
if errorlevel 1 exit /b 1
"@

Write-Host "[INFO] Configuring and building OpenSSL (minimal PQC-only static build)..."

try {
    [System.IO.File]::WriteAllText($BuildBat, $BatchContent)
    cmd /c "$BuildBat"
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }
} finally {
    if (Test-Path $BuildBat) { Remove-Item $BuildBat -Force }
}

Write-Host "[INFO] Build complete. Static libraries:"
Get-ChildItem (Join-Path $InstallDir 'lib') -Filter '*.lib' |
    ForEach-Object { Write-Host "  $($_.Name)" }
