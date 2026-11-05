#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the SIEM desktop executable with PyInstaller and the installer.
.DESCRIPTION
    Installs the desktop/build extras, produces dist\SIEM\SIEM.exe (onedir),
    and compiles installer\SIEM.iss with Inno Setup when ISCC is available.
.PARAMETER Python
    Python executable to use (default: python).
.PARAMETER SkipInstall
    Do not run pip install (assumes pywebview/pystray/PyInstaller are present).
.PARAMETER Clean
    Pass --clean to PyInstaller (discard its cache).
.PARAMETER WithCli
    Also build dist\SIEM-CLI\SIEM-CLI.exe.
.PARAMETER WithAgent
    Also build dist\siem-agent\siem-agent.exe.
.PARAMETER NoInstaller
    Skip compiling the Inno Setup installer.
.PARAMETER Iscc
    Explicit path to ISCC.exe (Inno Setup compiler).
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipInstall,
    [switch]$Clean,
    [switch]$WithCli,
    [switch]$WithAgent,
    [switch]$NoInstaller,
    [string]$Iscc
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"
$Work = Join-Path $Root "build\pyinstaller"

function Invoke-PyInstaller([string]$SpecName) {
    $pyArgs = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--distpath", $Dist,
        "--workpath", $Work
    )
    if ($Clean) { $pyArgs += "--clean" }
    $pyArgs += (Join-Path $PSScriptRoot $SpecName)
    Write-Host "PyInstaller: $SpecName" -ForegroundColor Cyan
    & $Python @pyArgs
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed for $SpecName (exit $LASTEXITCODE)." }
}

function Find-Iscc {
    if ($Iscc) {
        if (Test-Path $Iscc) { return $Iscc }
        throw "ISCC.exe not found at $Iscc."
    }
    $cmd = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = @(
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}

Write-Host ""
Write-Host "SIEM desktop build" -ForegroundColor Green
Write-Host "Repository: $Root"

if (-not $SkipInstall) {
    Write-Host "Installing build dependencies..." -ForegroundColor Cyan
    Push-Location $Root
    try {
        & $Python -m pip install -e ".[desktop,build]" --disable-pip-version-check
        if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)." }
    } finally {
        Pop-Location
    }
}

Invoke-PyInstaller "siem.spec"
if ($WithCli) { Invoke-PyInstaller "siem-cli.spec" }
if ($WithAgent) { Invoke-PyInstaller "agent.spec" }

$exe = Join-Path $Dist "SIEM\SIEM.exe"
if (-not (Test-Path $exe)) { throw "Expected build output missing: $exe" }
Write-Host "Built: $exe" -ForegroundColor Green

if (-not $NoInstaller) {
    $iscc = Find-Iscc
    if (-not $iscc) {
        Write-Host "Inno Setup (ISCC.exe) not found; skipping installer." -ForegroundColor Yellow
        Write-Host "Install it from https://jrsoftware.org/isinfo.php and rerun with -NoInstaller:`$false"
        exit 0
    }
    Write-Host "Compiling installer..." -ForegroundColor Cyan
    & $iscc (Join-Path $Root "installer\SIEM.iss")
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed (exit $LASTEXITCODE)." }
    $setup = Get-ChildItem -LiteralPath (Join-Path $Root "installer\Output") -Filter "SIEM-Setup-*.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime | Select-Object -Last 1
    if ($setup) {
        $sizeMb = [math]::Round($setup.Length / 1MB, 2)
        Write-Host "Installer: $($setup.FullName) ($sizeMb MB)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Done. Run dist\SIEM\SIEM.exe or installer\Output\SIEM-Setup-*.exe" -ForegroundColor Green
