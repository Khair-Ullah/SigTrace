# Deployment

## Vercel download portal

`web/download-portal` is a static landing page with no build step. It contains:

```text
web/download-portal/
  index.html          Landing page + download CTA
  styles.css          Theme and responsive layout
  app.js              Hash/size metadata + reveal animation
  vercel.json         Static headers and clean URLs
  downloads/
    SIEM-Setup-1.0.0.exe
    version.json      Version, filename, byte size and SHA-256
    README.txt        Install and safety notes
```

Deploy it as its own Vercel project:

```bash
cd web/download-portal
npx vercel --prod
```

Or import the repository in Vercel and set **Root Directory** to
`web/download-portal` with **Framework Preset** `Other`. No build command or
output directory is required.

For each release, copy the new installer into `downloads/`, then update
`downloads/version.json`:

```json
{
  "version": "1.0.0",
  "file": "SIEM-Setup-1.0.0.exe",
  "size_bytes": 20424043,
  "sha256": "<sha256>"
}
```

The page reads this file at runtime and updates the visible hash, download
links and file size. Use `Get-FileHash <installer> -Algorithm SHA256` on
Windows. `vercel.json` marks `.exe` downloads as attachments and disables
long-lived caching for `version.json`.

## Docker (recommended)

The repository ships a `Dockerfile` and a `docker-compose.yml`.

### Build

```bash
docker build -t siem-log-correlator:1.0.0 .
```

### Run with docker compose

```bash
# Optionally provide an initial admin + secret
export SIEM_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export SIEM_ADMIN_USER=admin
export SIEM_ADMIN_PASSWORD='change-me'

docker compose up -d --build
```

Then open <http://localhost:5000>. The container entrypoint:

1. initialises/upgrades the SQLite schema (`scripts/setup_db.py`),
2. creates the admin user from `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` if set,
3. starts `siem run --web`.

Create additional users at any time:

```bash
docker compose exec siem python scripts/create_user.py create \
    --username analyst --password 'secret' --role analyst
```

### Running the image directly

```bash
docker run -d --name siem \
  -p 5000:5000 -p 514:5514/udp -p 514:5514/tcp \
  -e SIEM_SECRET_KEY='change-me' \
  -e SIEM_SYSLOG_UDP_PORT=5514 -e SIEM_SYSLOG_TCP_PORT=5514 \
  -v siem-data:/app/data -v siem-logs:/app/logs \
  siem-log-correlator:1.0.0
```

> The container runs as a **non-root** user (`uid 10001`), so it binds syslog to
> the unprivileged port **5514**; compose maps host `514 → 5514`.

### Ports and volumes

| Host | Container | Purpose |
| --- | --- | --- |
| `5000` | `5000` | Web dashboard + REST API |
| `514/udp` | `5514/udp` | Syslog UDP |
| `514/tcp` | `5514/tcp` | Syslog TCP |

| Volume | Mount | Contents |
| --- | --- | --- |
| `siem-data` | `/app/data` | SQLite database |
| `siem-logs` | `/app/logs` | Alert log and application logs |
| `./config` (ro) | `/app/config` | Configuration |
| `./rules/custom` | `/app/rules/custom` | Custom rules (live-editable) |

### Container environment variables

| Variable | Purpose |
| --- | --- |
| `SIEM_SECRET_KEY` | Flask session secret — **change it** |
| `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` / `SIEM_ADMIN_ROLE` | Bootstrap an admin on startup |
| `SIEM_SYSLOG_UDP_PORT` / `SIEM_SYSLOG_TCP_PORT` | Syslog ports inside the container |
| `SIEM_WEB_HOST` / `SIEM_WEB_PORT` | Dashboard bind address/port |
| `SIEM_WEB_WORKERS` | Gunicorn worker count (`serve`) |
| `SIEM_COOKIE_SECURE` | `true` to send the session cookie only over HTTPS |
| `SIEM_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `SIEM_DATABASE_URL` | Override the SQLite URL |

See [Configuration](configuration.md) for the full list.

### Health check

The image defines a `HEALTHCHECK` against `GET /api/health` (which is public).

```bash
docker compose ps          # STATUS shows (healthy)
```

## Production topology (recommended)

Run the **engine** and the **web dashboard** as two processes that share the
SQLite database:

```bash
python -m siem run            # engine: syslog + files -> detect -> correlate -> store
python -m siem serve          # dashboard + API, served by gunicorn (gthread)
```

`siem serve` requires the production dependency:

```bash
pip install -r requirements-prod.txt      # gunicorn
```

Or use the split Docker stack:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

> Keep **one** gunicorn worker (`web.workers: 1`): Flask-SocketIO keeps
> connection state in-process. Scale out with a message queue rather than more
> web workers.

## Running without Docker

```bash
python -m siem run --web          # all-in-one (dev server) — simplest for demos
python -m siem run                # engine only (no web server)
python -m siem web                # dashboard only (dev server)
python -m siem serve              # dashboard only (gunicorn, production)
```

### Behind a reverse proxy (TLS termination)

When serving over HTTPS, set `SIEM_COOKIE_SECURE=true` (or `web.cookie_secure:
true`) so the session cookie is only sent over TLS. Example nginx server block:

```nginx
server {
    listen 443 ssl http2;
    server_name siem.example.com;

    ssl_certificate     /etc/ssl/certs/siem.crt;
    ssl_certificate_key /etc/ssl/private/siem.key;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Socket.IO / WebSocket support
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

Redirect plain HTTP to HTTPS with a second `server { listen 80; return 301 https://$host$request_uri; }`
block.

### systemd (bare-metal, Linux)

```ini
[Unit]
Description=SIEM Log Correlator
After=network-online.target

[Service]
User=siem
WorkingDirectory=/opt/siem
Environment=SIEM_SECRET_KEY=change-me
ExecStart=/opt/siem/venv/bin/python -m siem run --web
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Sending logs to the engine

Point your devices/apps at the host on UDP/TCP **514** (or the port you mapped):

```bash
# rsyslog example
*.* @siem-host:514
```

Or tail files by adding entries under `ingestion.files.sources` in
`config/config.yaml` (see [Configuration](configuration.md)).

## Agent-based ingestion (siem-agent)

For hosts you cannot point at syslog (Windows boxes, remote servers behind
NAT), install the lightweight agent. It tails files / reads the Windows Event
Log, spools records to disk (crash-safe) and ships them in batches to the
server's HTTP ingest API.

### 1. Create an ingest token on the server

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put it in the server's environment (`SIEM_INGEST_TOKENS=agent-01:<token>`) or
`ingestion.http.tokens` in `config/config.yaml`, then restart the server.

### 2. Configure the agent

Copy `config/agent.yaml.example` to `agent.yaml` on the target host and set:

```yaml
server:
  url: http://siem-host:5000
  token: <same token as above>
sources:
  files:
    - path: /var/log/syslog
      source_id: syslog
      source_type: syslog
  windows:
    enabled: true            # Windows hosts only
```

### 3. Verify and run

```bash
siem-agent test-connection --config agent.yaml   # probes health + ingest
siem-agent run --config agent.yaml               # foreground
siem-agent install --config agent.yaml           # start at boot
```

- **Windows:** `install` registers a scheduled task (`ONSTART`, runs as
  SYSTEM) — no extra dependencies required.
- **Linux:** `install` writes a systemd unit (use sudo, or follow the printed
  instructions to copy the generated file yourself).

Delivery is **at-least-once**: unacknowledged batches are re-sent after a
crash or network outage; the spool caps disk use (`spool.max_mb`, default
500 MB, oldest dropped first).

## Backup and maintenance

- **Database:** back up the `data/` volume. SQLite is in WAL mode, so copy the
  database together with its `-wal`/`-shm` files (or use `sqlite3 .backup`).
- **Retention:** configured via `retention.*` and applied by
  `StorageService.run_retention()`.
- **Upgrades:** pull the new image and `docker compose up -d --build`;
  migrations run automatically on startup.
- **Secret rotation:** changing `web.secret_key` invalidates existing sessions
  (users simply sign in again).

## Operations checklist

- [ ] Set a strong `SIEM_SECRET_KEY`
- [ ] Create admin + analyst users (avoid sharing accounts)
- [ ] Map syslog ports / configure file sources
- [ ] Review `rules/custom/` and enable/disable rules as needed
- [ ] Configure email notifications if desired (`alerting.email`)
- [ ] Schedule backups of the `data/` volume
