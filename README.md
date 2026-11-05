# SIEM Log Correlation Engine

A lightweight, rule-based SIEM log correlation engine for Small and Medium-sized
Organizations (SMOs). It ingests logs, applies Sigma-compatible detection rules,
correlates related alerts into incidents, and presents everything in a web
dashboard — all with a zero-config SQLite backend.

## Features

- **Log Ingestion** — syslog over UDP/TCP (RFC 3164 & 5424) and rotation-aware file tailing (text/JSON/CSV)
- **Log Shipper Agent** — `siem-agent`: a dependency-light forwarder for remote hosts (files + Windows Event Log) with a crash-safe disk spool and HTTP batch ingestion (`POST /api/ingest`)
- **Parsing & Normalization** — a unified event schema with UTC timestamps and best-effort field detection
- **Rule Engine** — Sigma-compatible YAML rules with condition expressions and stateful thresholds (timeframe + threshold + group-by)
- **Correlation** — sliding-window grouping of related alerts into incidents, plus multi-stage kill-chain escalation
- **SOAR-Lite** - YAML playbooks that preview or run local command/email responses for Critical incidents; dry-run and dedupe by default
- **Alerting** — log-file and email notifications, rate limiting, de-duplication, and realtime WebSocket push
- **Live System Monitor** — an admin "Start Monitoring" button that collects this machine's logs (Windows Event Log + configured files) on demand
- **Web Dashboard** — Flask + Flask-SocketIO + Tailwind CSS, with roles (admin/analyst/viewer), REST API and audit log
- **Storage** — SQLite in WAL mode with idempotent migrations and retention policies
- **CLI & Simulator** — a full `siem` command plus synthetic attack scenarios for demos and testing
- **Windows Desktop App** — a native pywebview window and system tray, packaged with PyInstaller and shipped as a one-step Inno Setup installer; no Python or browser required

## Tech Stack

Python 3.10+ · Flask · Flask-SocketIO · SQLAlchemy · SQLite · PyYAML · Tailwind CSS

## Quick Start

```powershell
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt
pip install -e .

# 3. Configure environment (optional)
Copy-Item .env.example .env

# 4. Initialise the database
python scripts/setup_db.py

# 5. Create a dashboard user
python scripts/create_user.py create --username admin --password "change-me" --role admin

# 6. Run ingestion + correlation + dashboard
python -m siem run --web
```

Open <http://localhost:5000> and sign in.

To run the native desktop shell from a checkout: `pip install -e ".[desktop]"`
then `python -m siem.desktop`.

### Try it without any log sources

```powershell
# Generate a multi-stage attack and run it through the full pipeline
python -m siem simulate --scenario multi_stage
```

Then open the dashboard to see the alerts and a correlated **critical**
incident.

### Monitor this machine

In the dashboard open the **Monitor** tab (sidebar) and press **Start
Monitoring**. SIEM reads the Windows Event Log (System, Application, Security)
and any files listed under `monitoring.files`, runs them through the detection
rules, and streams new findings to your dashboards in real time. Reading the
Security channel requires administrator rights.

## Windows desktop app

Build the native app and installer (requires Python 3.10+ and optionally
[Inno Setup 6 or 7](https://jrsoftware.org/isinfo.php)):

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\build-desktop.ps1
# -> dist\SIEM\SIEM.exe
# -> installer\Output\SIEM-Setup-1.0.0.exe
```

Run `SIEM-Setup-*.exe` on the target machine. The app opens as a native window,
keeps running in the system tray when closed, and stores its data in
`%LOCALAPPDATA%\SIEM`. The first run shows the generated admin credentials and
writes them to `FIRST_RUN_ADMIN.txt`; change the password after signing in.
The installer registers an elevated per-user logon task so Security event log
monitoring works without a UAC prompt on every launch.

Alternatively run the portable folder directly with `dist\SIEM\SIEM.exe`. See
[Installation](docs/installation.md#windows-desktop-app-recommended).

## SOAR-Lite automated response

Critical incidents can trigger local playbooks from
[`config/playbooks.yaml`](config/playbooks.yaml). The bundled playbook is a
safe dry-run: it renders the firewall command and SOC email without executing
them. Review `logs/siem.log` for `SOAR dry-run:` previews, then set
`dry_run: false` when ready.

```yaml
enabled: true
dry_run: true
max_runs_per_incident: 1
playbooks:
  - id: "critical-block-source"
    match:
      severities: ["critical"]
    actions:
      - type: "command"
        command: ["iptables", "-I", "INPUT", "-s", "{src_ip}", "-j", "DROP"]
        require: ["src_ip"]
```

Actions run after the incident is stored and notifications are sent; failures
never interrupt detection. See [SOAR-Lite Playbooks](docs/soar.md).

## Download portal

The Vercel-ready landing page and installer download live in
[`web/download-portal`](web/download-portal). Deploy that directory as a static
site, then upload `installer\Output\SIEM-Setup-<version>.exe` and update
`downloads/version.json` with the current hash. See
[Deployment](docs/deployment.md#vercel-download-portal).

## Docker

```bash
export SIEM_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export SIEM_ADMIN_PASSWORD='change-me'
docker compose up -d --build
```

Dashboard on <http://localhost:5000>, syslog on UDP/TCP **514**. For a split
engine + gunicorn web topology, use `docker-compose.prod.yml`. See
[Deployment](docs/deployment.md) for details.

For a bare-metal production install add the WSGI server:

```powershell
pip install -r requirements-prod.txt   # gunicorn
python -m siem serve                    # dashboard behind a TLS reverse proxy
```

## CLI

```powershell
python -m siem status                      # show event/alert/incident counts
python -m siem run --web                   # ingestion + correlation + dashboard
python -m siem run                         # engine only (no web server)
python -m siem web                         # dashboard only (dev server)
python -m siem serve                       # dashboard only (gunicorn, production)
python -m siem notify test                 # verify email/logfile notifications

python -m siem simulate --scenario all     # run every attack scenario
python -m siem simulate --scenario port_scan --count 3 --seed 42
python -m siem simulate --scenario multi_stage --write data/samples/multi_stage.log
python -m siem demo                        # multi-stage demo -> critical incident

python -m siem ingest path\to\app.log --source-id server-01 --source-type ssh
python -m siem rules list                  # list loaded rules
python -m siem rules validate              # validate all rule files
python -m siem alerts list --severity high --limit 20
python -m siem db init                     # initialise/upgrade the database
python -m siem db reset                    # delete and recreate a fresh database
python -m siem user list                   # manage dashboard users
```

### Log shipper agent (remote hosts)

```powershell
siem-agent test-connection --config agent.yaml   # probe server health + ingest
siem-agent run --config agent.yaml               # run in the foreground
siem-agent install --config agent.yaml           # start at boot (task/systemd)
siem-agent uninstall                             # remove the boot service
```

See `config/agent.yaml.example` and [docs/deployment.md](docs/deployment.md).

### Attack scenarios

`normal`, `port_scan`, `ssh_bruteforce`, `ssh_root_login`, `web_exploit`,
`directory_scan`, `admin_access`, `suspicious_outbound`, `ddos_flood`,
`multi_stage`.

## Project Structure

```
src/siem/          Core application
  core/            Config, logging, constants, security
  ingestion/       Syslog server, file tailer, queue, source factory
  parsing/         Parsers (syslog/JSON/CSV/plaintext) and normalization
  engine/          Rule loader/matcher, condition AST, state, correlator
  alerting/        Notifiers, notification manager, rate limiter
  soar/            SOAR-Lite playbook loader, matcher, actions, engine
  storage/         SQLAlchemy models, migrations, repositories, retention
  monitoring/      Local system monitor (Windows Event Log + file collectors)
  pipeline.py      End-to-end orchestrator (sync + streaming)
  web/             Flask app, auth/RBAC, routes, templates, static assets
  desktop/         Native shell: first-run bootstrap, waitress server, tray
  cli/             `siem` command and subcommands
  simulators/      Synthetic log generator and attack scenarios
config/            Default YAML configuration (seeded into the data root)
rules/builtin/     Pre-loaded detection + correlation rules
rules/custom/      User-defined rules
data/              SQLite database and samples (source mode)
logs/              Application logs (source mode)
tests/             Unit, integration and web tests
scripts/           setup_db.py, create_user.py, run_demo.py, reset_fresh_db.py
                   (thin compatibility wrappers around packaged commands)
packaging/         PyInstaller entry scripts/specs and build-desktop.ps1
installer/         install.ps1, uninstall.ps1, run.ps1, build.ps1, SIEM.iss
docs/              Full documentation
web/download-portal/  Vercel static landing page + installer download

Frozen desktop data root: %LOCALAPPDATA%\SIEM (override with SIEM_HOME)
```

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [SOAR-Lite Playbooks](docs/soar.md)
- [Writing Rules](docs/rules.md)
- [REST API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)

## Testing

```powershell
pip install -e ".[dev]"
pytest

# Desktop-path tests (waitress server thread) need the desktop extra
pip install -e ".[dev,desktop]"
pytest
```

## License

MIT License — see [LICENSE](LICENSE).
