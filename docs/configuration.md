# Configuration

All settings live in [`config/config.yaml`](../config/config.yaml) and can be
overridden with environment variables (loaded from `.env`).

## Precedence

1. `config/config.yaml` (or the file in `$SIEM_CONFIG`)
2. Environment variables / `.env`

Environment variables always win.

## `system`

| Key | Default | Description |
| --- | --- | --- |
| `name` | `SIEM Log Correlator` | Display name |
| `version` | `1.0.0` | Reported version |
| `log_level` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

## `database`

| Key | Default | Description |
| --- | --- | --- |
| `url` | `sqlite:///data/siem.db` | SQLAlchemy URL (relative paths resolve to the data root; the desktop app writes an absolute path) |
| `echo` | `false` | Log all SQL statements |
| `auto_migrate` | `true` | Apply migrations on engine startup |

## `ingestion`

### `ingestion.syslog`

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Listen for syslog over UDP/TCP |
| `host` | `0.0.0.0` | Bind address |
| `udp_port` | `514` | UDP port (use ≥ 1024 without root) |
| `tcp_port` | `514` | TCP port |
| `source_id` | `syslog` | Source identifier attached to events |
| `source_type` | `syslog` | Source type label |

Supports **RFC 3164** and **RFC 5424**.

### `ingestion.files`

| Key | Default | Description |
| --- | --- | --- |
| `read_from_beginning` | `false` | Read existing content on start (vs. tail only) |
| `tail_interval_seconds` | `0.5` | Safety-net poll interval |
| `sources` | `data/logs/pfsense.log`, `data/logs/ufw.log` | List of files to tail |

Each entries in `sources`:

```yaml
ingestion:
  files:
    sources:
      - path: "C:/logs/auth.log"
        source_id: "server-01"
        source_type: "ssh"
      - path: "data/samples/firewall.log"
        source_id: "fw-01"
        source_type: "firewall"
```

File tailing follows **log rotation** (rename and truncate) and reads
line-by-line, tolerating partially written lines.

### Firewall sources (pfSense / OPNsense, UFW / iptables)

The parser understands both pfSense/OPNsense `filterlog` payloads and
iptables/UFW `key=value` lines (e.g. `[UFW BLOCK] IN=eth0 SRC=... DPT=22`).
Denied traffic becomes `event_type: firewall_deny`, permitted traffic
`firewall_allow`, so the built-in `port_scan`, `ddos_pattern` and
`suspicious_outbound` rules apply without extra configuration.

**pfSense / OPNsense (recommended, real time):** forward remote syslog to this
host and keep the syslog ingestor enabled (see above).

1. *Status → System Logs → Settings*.
2. Enable *Remote Logging*, set the SIEM host, port `514` (UDP or TCP), and
   select the **Firewall** facility.
3. Optionally copy/export `filter.log` to `data/logs/pfsense.log` (the default
   file source) — the same `filterlog` format is parsed.

**Linux UFW / iptables (real time):** either log directly to this SIEM over
syslog (port `514`), or have `rsyslog` write to a file. Example
`/etc/rsyslog.d/10-ufw.conf`:

```
:msg,contains,"[UFW " /var/log/ufw.log
& stop
```

Then point `ingestion.files.sources` (or `monitoring.files`) at
`/var/log/ufw.log` with `source_type: firewall`.

The defaults in `config/config.yaml` tail `data/logs/pfsense.log` and
`data/logs/ufw.log`; files that do not exist yet are watched and read once they
appear. Sample lines are available in `data/samples/`.

## `rules`

| Key | Default | Description |
| --- | --- | --- |
| `builtin_path` | `rules/builtin` | Built-in detection rules |
| `custom_path` | `rules/custom` | Your own rules |
| `auto_reload` | `true` | Reload rules when files change |

## `correlation`

| Key | Default | Description |
| --- | --- | --- |
| `window_seconds` | `300` | Sliding window for grouping alerts into incidents |
| `min_alerts_for_incident` | `2` | Alerts needed to open an incident |
| `match_fields` | `[src_ip, user_name, dst_ip]` | Attributes used to correlate alerts |
| `correlation_rules_path` | `rules/builtin/correlation` | Multi-stage chain definitions |

## `retention`

| Key | Default | Description |
| --- | --- | --- |
| `events_days` | `30` | Delete raw events older than N days |
| `alerts_days` | `90` | Delete alerts **and notifications** older than N days |
| `incidents_days` | `365` | Delete closed incidents older than N days |
| `interval_hours` | `24` | While `siem run` is active, run cleanup every N hours (`0` disables) |

The background scheduler prunes automatically during `siem run`. You can also
run it manually via `storage.run_retention()` (which delegates to
`retention.cleanup(dry_run=...)`).

## `monitoring`

Powers the dashboard **Monitor** tab, which collects logs from the local host
on demand (an admin presses *Start Monitoring*).

| Key | Default | Description |
| --- | --- | --- |
| `interval_seconds` | `5` | How often each source is polled |
| `max_events_per_poll` | `50` | Max Windows Event Log entries read per channel per poll |
| `windows_event_logs` | `["System","Application","Security"]` | Windows Event Log channels to watch (Windows only; `Security` needs admin) |
| `files` | `data/logs/{pfsense,ufw}.log` | Extra files to tail: `{path, source_id, source_type}` |
| `read_from_beginning` | `false` | For file sources, read existing content on the first poll |

Windows Event Log entries are mapped to canonical `event_type` values (e.g.
`4625` → `failed_login`) and severities, so the built-in rules apply to them.
On non-Windows hosts only `monitoring.files` sources are used.

## `alerting`

### `alerting.email` (SMTP)

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Turn email notifications on |
| `smtp_host` / `smtp_port` | `smtp.gmail.com` / `587` | SMTP server |
| `use_tls` | `true` | STARTTLS |
| `username` / `password` | `""` | SMTP credentials |
| `from_address` | `""` | Sender address |
| `to_addresses` | `[]` | Recipients |
| `min_severity` | `high` | Only notify at/above this severity |

### `alerting.logfile`

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Append alerts as JSON lines |
| `path` | `logs/alerts.log` | Destination file |
| `min_severity` | `medium` | Severity threshold |

### Rate limiting & de-duplication

| Key | Default | Description |
| --- | --- | --- |
| `alerting.rate_limit.max_per_minute` | `60` | Global notification cap |
| `alerting.dedup_window_seconds` | `300` | Suppress identical alerts within this window |

Deduplication key: `rule_id | src_ip | user_name`.

> A **WebSocket** channel (Socket.IO, namespace `/realtime`) is always active
> for locally connected dashboard clients; it is not configured here.

## `soar`

SOAR-Lite loads playbooks from `config/playbooks.yaml`. See
[SOAR-Lite Playbooks](soar.md) for the full schema, placeholders and safety
guidance.

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable playbook evaluation for incidents |
| `playbooks_path` | `config/playbooks.yaml` | Optional playbook file override (relative to the data root) |

The playbook file itself controls `dry_run`, `max_runs_per_incident` and the
individual command/email actions:

```yaml
enabled: true
dry_run: true
max_runs_per_incident: 1
```

The engine is skipped entirely when no playbook file exists or `soar.enabled`
is `false`. Invalid playbook YAML disables the engine for the current process
and writes the validation error to the application log; detection continues.

## `web`

| Key | Default | Description |
| --- | --- | --- |
| `host` | `0.0.0.0` | Dashboard bind address |
| `port` | `5000` | Dashboard port |
| `secret_key` | `CHANGE_ME_IN_PRODUCTION` | Flask session signing key — **change it** (an ephemeral random key is generated if unset) |
| `session_timeout_minutes` | `30` | Idle session lifetime |
| `debug` | `false` | Flask debug mode |
| `csrf_enabled` | `true` | CSRF protection for state-changing requests |
| `socketio_cors` | `*` | Allowed origins for Socket.IO |
| `cookie_secure` | `false` | Send the session cookie only over HTTPS (set `true` behind TLS) |
| `workers` | `1` | Gunicorn worker count for `siem serve` (keep `1` for Socket.IO) |
| `threads` | `8` | Gunicorn threads per worker for `siem serve` |

Session cookies are always `HttpOnly` with `SameSite=Lax`.

Generate a strong secret key:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

## Environment variables

| Variable | Maps to |
| --- | --- |
| `SIEM_HOME` | Writable data root (default: repo root in source mode, `%LOCALAPPDATA%\SIEM` in the desktop app) |
| `SIEM_CONFIG` | Path to the YAML config file |
| `SIEM_PLAYBOOKS` | Path to the SOAR playbook file (overrides `soar.playbooks_path`) |
| `SIEM_ADMIN_USER` | First-run desktop admin username (default `admin`) |
| `SIEM_ADMIN_PASSWORD` | First-run desktop admin password (random if unset) |
| `SIEM_DATABASE_URL` | `database.url` |
| `SIEM_SECRET_KEY` | `web.secret_key` |
| `SIEM_SYSLOG_UDP_PORT` | `ingestion.syslog.udp_port` |
| `SIEM_SYSLOG_TCP_PORT` | `ingestion.syslog.tcp_port` |
| `SIEM_WEB_HOST` | `web.host` |
| `SIEM_WEB_PORT` | `web.port` |
| `SIEM_WEB_WORKERS` | `web.workers` |
| `SIEM_COOKIE_SECURE` | `web.cookie_secure` |
| `SIEM_LOG_LEVEL` | `system.log_level` |
