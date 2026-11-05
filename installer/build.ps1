#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a portable, installable ZIP of the SIEM Log Correlator.
.DESCRIPTION
    Assembles the application source, installer scripts, configuration, rules
    and docs into a versioned ZIP under the repository root (e.g.
    SIEM-Setup-1.0.0.zip). The ZIP contains install.ps1 / uninstall.ps1 /
    run.ps1 at its root so it can be copied to any Windows machine, extracted
    and installed.
.PARAMETER OutputDir
    Directory to place the ZIP in (default: repository root).
.PARAMETER NoZip
    Skip creating the ZIP (only stage the folder).
.PARAMETER Desktop
    Build the native desktop app and installer instead (delegates to
    packaging\build-desktop.ps1).
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$NoZip,
    [switch]$Desktop
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$InstallerDir = $PSScriptRoot

if ($Desktop) {
    & (Join-Path $RepoRoot "packaging\build-desktop.ps1")
    exit $LASTEXITCODE
}

if (-not $OutputDir) { $OutputDir = $RepoRoot }

$version = "1.0.0"
$versionFile = Join-Path $RepoRoot "src\siem\version.py"
if (Test-Path $versionFile) {
    $m = Select-String -Path $versionFile -Pattern '__version__\s*=\s*"([^"]+)"'
    if ($m) { $version = $m.Matches[0].Groups[1].Value }
}

$pkgName = "SIEM-$version"
$stageRoot = Join-Path $env:TEMP "siem-build-$([guid]::NewGuid().ToString('N'))"
$stage = Join-Path $stageRoot $pkgName
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Write-Host "Building $pkgName ..." -ForegroundColor Cyan

$includeDirs = @("src", "config", "rules", "docker", "docs", "scripts", "packaging")
$includeFiles = @("README.md", "LICENSE", "pyproject.toml", "requirements.txt",
                  "requirements-prod.txt", "requirements-dev.txt", ".env.example",
                  ".dockerignore", "Dockerfile", "docker-compose.yml",
                  "docker-compose.prod.yml")

foreach ($dir in $includeDirs) {
    $src = Join-Path $RepoRoot $dir
    if (Test-Path $src) {
        $dest = Join-Path $stage $dir
        $robo = @($src, $dest, "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP",
                  "/XD", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                  "*.egg-info")
        & robocopy @robo | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed for $dir ($LASTEXITCODE)" }
    }
}

foreach ($file in $includeFiles) {
    $src = Join-Path $RepoRoot $file
    if (Test-Path $src) { Copy-Item $src -Destination $stage -Force }
}

foreach ($script in @("install.ps1", "uninstall.ps1", "run.ps1", "SIEM.iss")) {
    $src = Join-Path $InstallerDir $script
    if (Test-Path $src) { Copy-Item $src -Destination $stage -Force }
}

$readme = Join-Path $InstallerDir "INSTALL-README.txt"
if (Test-Path $readme) { Copy-Item $readme -Destination $stage -Force }

Get-ChildItem $stage -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $stage -Recurse -Directory -Filter "*.egg-info" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Set-Content -Path (Join-Path $stage "VERSION") -Value $version -Encoding ASCII

if ($NoZip) {
    Write-Host "Staged at: $stage" -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$zipPath = Join-Path $OutputDir "$pkgName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Host "Compressing -> $zipPath"
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -CompressionLevel Optimal

Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue

$sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-Host ""
Write-Host "Build complete: $zipPath ($sizeMb MB)" -ForegroundColor Green
Write-Host "Copy the ZIP to a Windows machine, extract it, and run install.ps1 as Administrator." -ForegroundColor Green
