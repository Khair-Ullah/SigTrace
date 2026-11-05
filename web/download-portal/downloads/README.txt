SIEM Log Correlator v1.0.0
==========================

Download: SIEM-Setup-1.0.0.exe
Platform: Windows 10 / 11, 64-bit
SHA-256:  DB4236DDDB0A4BF0F92E610FC49B53114CB3D2B6CFB7C3ECA55E6DC785B8FDB8

Install
-------
1. Run SIEM-Setup-1.0.0.exe and approve the Windows administrator prompt.
2. Keep the background service and firewall tasks selected if you want
   syslog ingestion on UDP/TCP 514.
3. Launch SIEM from the desktop shortcut or Start menu.
4. A local administrator is generated on first run. The username and password
   are written to:
     %LOCALAPPDATA%\SIEM\FIRST_RUN_ADMIN.txt
5. Delete or move the credentials file after signing in.

Data and configuration
----------------------
The desktop app stores everything under:
  %LOCALAPPDATA%\SIEM

Important paths:
  config\config.yaml       Main configuration
  config\playbooks.yaml    SOAR-Lite automated response playbooks
  data\siem.db             Local SQLite database
  logs\                    Application and alert logs
  rules\                   Built-in and custom detection rules
  .env                     Local secrets and environment overrides

Set SIEM_HOME to use a different data directory.

SOAR-Lite safety
----------------
SOAR-Lite is enabled but ships in dry-run mode. Matching Critical incidents
produce a preview of the configured command or email without executing it.
Review config\playbooks.yaml, set dry_run: false only when you are ready, and
keep max_runs_per_incident low to avoid duplicate responses.

Email actions require alerting.email.enabled: true and SMTP credentials in .env.
Command actions use argv lists by default (no shell). The pipeline continues
even if an automated response fails.

Verify the download
-------------------
PowerShell:
  Get-FileHash .\SIEM-Setup-1.0.0.exe -Algorithm SHA256

The hash must match the value above. Rebuilds change the hash; always use the
value published with the current installer.
