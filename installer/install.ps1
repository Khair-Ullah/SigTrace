#Requires -Version 5.1
<#
.SYNOPSIS
    Registers the packaged SIEM desktop application on Windows.
.DESCRIPTION
    The Inno Setup installer copies the application to the install directory
    and then runs this script elevated. It opens the firewall for syslog and
    registers a per-user logon task that starts SIEM.exe with the privileges
    required to read the Windows Security event log (without a UAC prompt on
    every launch). The application itself seeds its configuration, database
    and first-run administrator password under %LOCALAPPDATA%\SIEM.
.PARAMETER InstallDir
    Directory containing SIEM.exe (default: %ProgramFiles%\SIEM).
.PARAMETER NoTask
    Do not register the logon task.
.PARAMETER NoFirewall
    Do not add firewall rules for syslog (UDP/TCP 514).
.PARAMETER NoStart
    Do not start the application after installation.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "SIEM"),
    [switch]$NoTask,
    [switch]$NoFirewall,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$Source = $PSScriptRoot
$TaskName = "SIEM Desktop"
$LegacyTaskName = "SIEM"
$SyslogPort = 514
$ExeName = "SIEM.exe"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host ""
Write-Host "SIEM Log Correlator - desktop setup" -ForegroundColor Green
Write-Host "Source : $Source"
Write-Host "Target : $InstallDir"

$isAdmin = Test-IsAdmin
$exePath = Join-Path $InstallDir $ExeName

Write-Step "Copying application files"
if ((Resolve-Path $Source).Path -ne (Resolve-Path $InstallDir -ErrorAction SilentlyContinue).Path) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $excludeDirs = @("data", "logs", ".git", "dist", ".pytest_cache", "__pycache__",
                     ".mypy_cache", ".ruff_cache", "*.egg-info")
    $excludeFiles = @("cookies.txt", "cookies2.txt", "cookies_web.txt", "c_live.txt")
    & robocopy $Source $InstallDir /E /NFL /NDL /NJH /NJS /NP /XD @excludeDirs /XF @excludeFiles |
        Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Failed to copy application files (robocopy $LASTEXITCODE)." }
}
if (-not (Test-Path $exePath)) {
    throw "SIEM.exe was not found in '$InstallDir'. Build the desktop app first."
}

if (-not $NoFirewall) {
    if ($isAdmin) {
        Write-Step "Configuring Windows Firewall (syslog)"
        foreach ($rule in @(
            @{ Name = "SIEM Syslog (UDP $SyslogPort)"; Proto = "UDP"; Port = $SyslogPort },
            @{ Name = "SIEM Syslog (TCP $SyslogPort)"; Proto = "TCP"; Port = $SyslogPort }
        )) {
            if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound `
                    -Protocol $rule.Proto -LocalPort $rule.Port -Action Allow | Out-Null
                Write-Host "Added firewall rule: $($rule.Name)"
            }
        }
        # The desktop dashboard listens on 127.0.0.1 only and needs no rule.
        Get-NetFirewallRule -DisplayName "SIEM Dashboard (TCP 5000)" -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } else {
        Write-Host "Skipping firewall rules (administrator rights required)." -ForegroundColor Yellow
    }
}

if (-not $NoTask) {
    Write-Step "Registering logon startup (Scheduled Task: $TaskName)"
    if (Get-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $LegacyTaskName -Confirm:$false
    }

    $account = "$env:USERDOMAIN\$env:USERNAME"
    $action = New-ScheduledTaskAction -Execute $exePath -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 0)
    $principal = New-ScheduledTaskPrincipal -UserId $account `
        -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Task '$TaskName' registered for $account (starts at logon, elevated)."
}

if (-not $NoStart) {
    Write-Step "Starting SIEM"
    if (-not $NoTask) {
        Start-ScheduledTask -TaskName $TaskName
    } else {
        Start-Process -FilePath $exePath -WorkingDirectory $InstallDir
    }
}

$dataRoot = Join-Path $env:LOCALAPPDATA "SIEM"
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host " Installation complete" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host " Application    : $exePath"
Write-Host " Data folder    : $dataRoot"
Write-Host " First run      : the app shows the admin username/password and"
Write-Host "                  writes them to FIRST_RUN_ADMIN.txt in the data folder."
Write-Host " Startup        : Get-ScheduledTask -TaskName `"$TaskName`""
Write-Host " Open window    : double-click the SIEM desktop shortcut (or tray icon)."
Write-Host " Uninstall      : use Settings > Apps, or run uninstall.ps1"
Write-Host ""
