#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the SIEM desktop application from this folder (portable mode).
.DESCRIPTION
    Prefers the packaged SIEM.exe next to this script (or in ..\dist\SIEM).
    If no executable is present, falls back to running the desktop app from an
    installed Python environment (pip install -e ".[desktop]").
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

$candidates = @(
    (Join-Path $Root "SIEM.exe"),
    (Join-Path (Split-Path -Parent $Root) "dist\SIEM\SIEM.exe")
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($exe) {
    Write-Host "Starting $exe ..." -ForegroundColor Green
    Start-Process -FilePath $exe -WorkingDirectory (Split-Path -Parent $exe)
    exit 0
}

try {
    & python -c "import siem.desktop, webview" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SIEM.exe not found; starting python -m siem.desktop ..." -ForegroundColor Yellow
        & python -m siem.desktop
        exit $LASTEXITCODE
    }
} catch { }

throw "SIEM.exe was not found. Build it with: powershell -ExecutionPolicy Bypass -File packaging\build-desktop.ps1"
