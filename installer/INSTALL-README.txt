SIEM - Desktop Application
==========================

A lightweight, rule-based SIEM log correlation engine with a native Windows
window, a system-tray icon and a packaged installer. No Python installation or
browser is required on the target machine.

INSTALL
-------
Run SIEM-Setup-<version>.exe and follow the wizard. The installer:

  - copies the application to C:\Program Files\SIEM,
  - opens Windows Firewall for syslog (UDP/TCP 514) if selected,
  - registers a per-user logon task that starts SIEM elevated so it can read
    the Windows Security event log without a UAC prompt on every launch,
  - creates Start Menu and desktop shortcuts.

On first launch SIEM creates its data folder at:

    %LOCALAPPDATA%\SIEM

and shows the generated administrator username and password. The same
credentials are written to FIRST_RUN_ADMIN.txt in that folder. Sign in, change
the password, then delete that file.

USING SIEM
----------
  - The dashboard opens in a native window (Microsoft Edge WebView2).
  - Closing the window keeps SIEM running in the system tray; use the tray
    menu to reopen it or to quit.
  - Open the Monitor tab and press "Start Monitoring" to collect this
    machine's Windows Event Log and configured files.
  - Reading the Security channel requires the elevated logon task; if you
    start SIEM manually without it, Security events may be denied.

PORTABLE MODE
-------------
Run SIEM.exe directly from the extracted dist\SIEM folder. The portable copy
uses the same %LOCALAPPDATA%\SIEM data folder. Set SIEM_HOME to use a different
data folder.

TROUBLESHOOTING
---------------
  - "WebView2 required": install the Microsoft Edge WebView2 Runtime from
    https://developer.microsoft.com/microsoft-edge/webview2/
  - Security log "Access is denied": start SIEM from the logon task (or run it
    as administrator).
  - Logs are in %LOCALAPPDATA%\SIEM\logs\siem.log.
  - The dashboard listens on 127.0.0.1 only. Syslog listens on UDP/TCP 514
    (change ports in %LOCALAPPDATA%\SIEM\config\config.yaml).

UNINSTALL
---------
Use Settings > Apps > SIEM, or run the uninstaller from the Start Menu.
User data in %LOCALAPPDATA%\SIEM is preserved. To remove it as well, run
uninstall.ps1 with -DeleteData as administrator.
