#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the SIEM desktop startup task, firewall rules and shortcuts.
.DESCRIPTION
    Called by the Inno Setup uninstaller. Application files are removed by the
    uninstaller itself; this script only cleans external state. User data in
    %LOCALAPPDATA%\SIEM is preserved unless -DeleteData is supplied.
.PARAMETER InstallDir
    Install directory (used for messages only).
.PARAMETER DeleteData
    Also delete the database, logs and configuration in %LOCALAPPDATA%\SIEM.
.PARAMETER Force
    Do not prompt for confirmation.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "SIEM"),
    [switch]$DeleteData,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$TaskNames = @("SIEM Desktop", "SIEM")
$DataRoot = Join-Path $env:LOCALAPPDATA "SIEM"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $Force) {
    $answer = Read-Host "Remove SIEM from '$InstallDir'? (y/N)"
    if ($answer -notmatch "^(y|yes)$") { Write-Host "Aborted."; exit 0 }
}

foreach ($task in $TaskNames) {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Write-Host "Stopping and removing task '$task'..."
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
}

Get-Process -Name "SIEM" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if (Test-IsAdmin) {
    foreach ($name in @(
        "SIEM Syslog (UDP 514)",
        "SIEM Syslog (TCP 514)",
        "SIEM Dashboard (TCP 5000)"
    )) {
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
}

foreach ($lnk in @(
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "SIEM.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "SIEM Dashboard.lnk"),
    "$env:PUBLIC\Desktop\SIEM.lnk",
    "$env:PUBLIC\Desktop\SIEM Dashboard.lnk"
)) {
    if (Test-Path $lnk) { Remove-Item $lnk -Force -ErrorAction SilentlyContinue }
}

if ($DeleteData) {
    if (Test-Path $DataRoot) {
        Write-Host "Deleting user data in $DataRoot..."
        Remove-Item $DataRoot -Recurse -Force
    }
} else {
    Write-Host "Preserving user data in $DataRoot (pass -DeleteData to remove it)."
}

Write-Host "SIEM cleanup complete." -ForegroundColor Green
