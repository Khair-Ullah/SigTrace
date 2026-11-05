# Installation

## Requirements

- **Python 3.10+** (3.11 recommended)
- **pip**
- Windows, Linux or macOS
- Optional: **Docker** (see [Deployment](deployment.md)) for a container image

No external database is required — the engine uses an embedded **SQLite**
database that is created automatically.

## Windows desktop app (recommended)

SIEM runs as a native desktop application: a pywebview window backed by a
localhost dashboard, plus a system-tray icon. The engine, pipeline and database
all run inside the app process, so no Python installation or browser is needed
on the target machine.

**Install:** run `SIEM-Setup-<version>.exe` and follow the wizard. The
installer copies the app to `C:\Program Files\SIEM`, optionally opens the
firewall for syslog, and registers a per-user logon task that starts SIEM
elevated (needed for the Security event log) without a UAC prompt on every
launch.

**First run:** SIEM seeds `%LOCALAPPDATA%\SIEM` with `config\`, `logs\`, a
fresh migrated database, built-in rules, SOAR playbooks, and an administrator
account. The username and password are shown in a dialog and written to
`%LOCALAPPDATA%\SIEM\FIRST_RUN_ADMIN.txt`. Change the password after signing
in, then delete that file.

**SOAR-Lite:** the seeded `config\playbooks.yaml` is safe by default
(`dry_run: true`). Matching Critical incidents log their intended command and
email without executing them. Review [SOAR-Lite Playbooks](soar.md) before
turning dry-run off.

**Download page:** the Vercel-ready static portal in `web\download-portal`
ships the current installer in `downloads\` and reads the published hash from
`downloads\version.json`.

**Tray behaviour:** closing the window hides it; monitoring continues. Use the
tray menu to reopen the dashboard, open the data folder, or quit. If the tray
cannot start, closing the window exits the app.

**Portable:** run `dist\SIEM\SIEM.exe` directly. Set `SIEM_HOME` to choose a
different data folder. Windows requires the Microsoft Edge WebView2 Runtime
(preinstalled on current Windows 11 and most Windows 10 systems).

### Build the desktop app and installer

```powershell
# One step: installs extras, builds dist\SIEM\SIEM.exe, compiles the installer
powershell -ExecutionPolicy Bypass -File .\packaging\build-desktop.ps1

# Optional: also build the CLI and the remote agent
.\packaging\build-desktop.ps1 -WithCli -WithAgent
```

Outputs:

- `dist\SIEM\SIEM.exe` (PyInstaller **onedir** bundle - keep the folder intact)
- `installer\Output\SIEM-Setup-<version>.exe` (requires
  [Inno Setup 6 or 7](https://jrsoftware.org/isinfo.php); skipped if `ISCC.exe` is
  not found)

For the download portal, copy the new installer to
`web\download-portal\downloads\` and update `downloads\version.json` with its
filename, byte size and SHA-256 hash. The page loads that metadata at runtime,
so no HTML edit is needed for a new build.

The build needs `pip install -e ".[desktop,build]"` (handled automatically by
the script). Use `-SkipInstall` when the dependencies are already installed and
`-Iscc <path>` to point at a non-standard `ISCC.exe`. The old source-ZIP flow is
still available with `installer\build.ps1`; `installer\run.ps1` launches the
portable executable.

Smoke-test the frozen build without opening a window (writes
`selftest.json` to the data folder and exits 0 on success):

```powershell
$env:SIEM_DESKTOP_SELFTEST = "1"
$env:SIEM_HOME = "$env:TEMP\siem-selftest"
.\dist\SIEM\SIEM.exe
Get-Content "$env:TEMP\siem-selftest\selftest.json"
Remove-Item Env:SIEM_DESKTOP_SELFTEST, Env:SIEM_HOME
```

## 1. Get the code

```powershell
git clone <repository-url> SIEM
cd SIEM
```

## 2. Create a virtual environment

```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```powershell
pip install -r requirements.txt

# Editable install so the `siem` command and packages are importable
pip install -e .
```

> If pip is interrupted by a flaky network, retry with
> `pip install --retries 10 --timeout 120 -r requirements.txt`.

## 4. Configure the environment (optional)

```powershell
Copy-Item .env.example .env
```

Edit `.env` to override the database path, secret key, ports or log level.
See [Configuration](configuration.md) for details.

## 5. Initialise the database

```powershell
python scripts/setup_db.py
```

This creates `data/siem.db`, applies all schema migrations and tunes the
SQLite connection (WAL mode). It is safe to re-run — migrations are
idempotent. Use `--force` to drop and recreate.

## 6. Create a dashboard user

```powershell
python scripts/create_user.py create --username admin --password "change-me" --role admin
```

Roles: `admin` (full control), `analyst` (acknowledge alerts, change
incident status, toggle rules off), `viewer` (read-only).

## 7. Verify

```powershell
python -m siem status
python -m siem rules validate
```

## 8. Run it

```powershell
# Start ingestion + correlation + dashboard
python -m siem run --web

# ...or just the dashboard
python -m siem web
```

Open <http://localhost:5000> and sign in.

To run the same engine as the native desktop shell from a checkout:

```powershell
pip install -e ".[desktop]"
python -m siem.desktop
```

In source mode the data root stays the repository root (use `SIEM_HOME` to
override it); the frozen app uses `%LOCALAPPDATA%\SIEM`.

## Monitoring this machine

The dashboard's **Monitor** tab (sidebar) collects logs from the local host on
demand. An administrator presses **Start Monitoring** and SIEM begins reading
the configured sources — by default the Windows Event Log (System,
Application and Security channels) — feeding each entry through the detection
rules. Reading the **Security** channel requires the process to run as
administrator/SYSTEM (the Windows installer's elevated logon task starts the
desktop app that way).

Configure additional log files under `monitoring.files` in
`config/config.yaml`:

```yaml
monitoring:
  interval_seconds: 5
  windows_event_logs: ["System", "Application", "Security"]
  files:
    - path: "C:/logs/app.log"
      source_id: "app-01"
      source_type: "app"
```

## Quick demo (no real log sources)

Generate synthetic attack traffic and feed it through the whole pipeline:

```powershell
python -m siem simulate --scenario multi_stage
# or the packaged end-to-end attack-chain demo:
python -m siem demo
```

Then open the dashboard - you will see the alerts and a correlated
**critical** incident.

## Running the test suite

```powershell
pip install -r requirements-dev.txt
pytest
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Permission denied` binding syslog port 514 | Use a port ≥ 1024 (`SIEM_SYSLOG_UDP_PORT=5514`) |
| `database is locked` | Ensure only one writer process; WAL mode is enabled by default |
| Dashboard login loops | Your `web.secret_key` changed between restarts; sign in again |
| `ModuleNotFoundError: siem` | Run `pip install -e .` from the project root |
