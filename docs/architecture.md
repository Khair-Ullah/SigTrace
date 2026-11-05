# Architecture

The SIEM Log Correlation Engine is a single Python application composed of
loosely coupled components. Data flows from log sources through a
parse → detect → correlate → store → notify pipeline, with a web dashboard for
triage.

## Component overview

```
                     ┌──────────────── ingestion ────────────────┐
 syslog (UDP/TCP) ──▶│ SyslogServer                              │
 log files        ──▶│ FileTailer  (rotation-safe)               │──▶ LogQueue
 simulator        ──▶│ LogSimulator                              │
                     └───────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────── parsing ──────────────────┐
                     │ Parser registry (syslog/RFC3164+5424,     │
                     │ JSON, CSV, plaintext) + Normalizer        │──▶ Event
                     └───────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌────────────── rule engine ────────────────┐
                     │ RuleLoader → RuleMatcher → Condition eval │
                     │ StateManager (thresholds/timeframes)      │
                     └───────────────────────────────────────────┘
                                        │ Alert
                                        ▼
                     ┌─────────────── correlator ────────────────┐
                     │ Correlator (sliding window, match fields) │
                     │ CorrelationRuleLoader (multi-stage)       │──▶ Incident
                     └───────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────── storage ──────────────────┐
                     │ StorageService → repositories → SQLite    │
                     │ (WAL mode, migrations, retention)         │
                     └───────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────── alerting ─────────────────┐
                     │ NotificationManager (logfile, email)      │
                     │ RateLimiter • dedup • Socket.IO push      │──▶ dashboard
                     └───────────────────────────────────────────┘
```

## Modules

| Package | Responsibility |
| --- | --- |
| `siem.core` | Config loading (YAML + env), logging, constants, security (hashing), exceptions |
| `siem.ingestion` | `SyslogServer`, `FileTailer`, `LogQueue`, source factory |
| `siem.parsing` | Parser registry (`syslog`, `json`, `csv`, `plaintext`), normalizer, field detectors |
| `siem.engine` | Rule loader/validator/matcher, condition AST, state manager, correlator, correlation rules |
| `siem.alerting` | Notifiers (logfile, email), notification manager, rate limiter, dedup |
| `siem.soar` | Playbook loader/validator, incident matcher, command/email actions, deduplicating engine |
| `siem.storage` | SQLAlchemy models, migrations, `StorageService`, repositories, retention |
| `siem.pipeline` | `Pipeline` — wires every stage together (sync + streaming) |
| `siem.web` | Flask app, auth/RBAC, stats, serializers, Socket.IO, routes, templates |
| `siem.cli` | `siem` command: `db` (`init`/`reset`), `status`, `run`, `simulate`, `demo`, `ingest`, `rules`, `alerts`, `web`, `user` |
| `siem.simulators` | Synthetic log generator and attack scenarios |

## The Pipeline

`siem.pipeline.Pipeline` orchestrates the flow and is used by both the CLI and
tests:

- **Synchronous mode** — `ingest_file()`, `ingest_lines()`,
  `ingest_simulated()`, `process_raw()` push records straight through.
- **Streaming mode** — `run(block=True)` starts ingestors (syslog/files) that
  feed a `LogQueue`; a consumer thread drains the queue, and the rule engine
  hot-reloads rules via `_on_rules_changed`.
- Emits alerts through an optional `on_alert` callback (the web dashboard wires
  this to the Socket.IO broadcast) and persists everything via the
  `StorageService`.

`PipelineStats` tracks `records`, `parsed`, `parse_failures`, `alerts`,
`incidents_created`, `notifications_sent`, `soar_runs`, `soar_actions`,
`soar_failures`, `errors`.

## Detection model

1. **Normalization** flattens each log line into a dict of canonical fields.
2. **Rule matching** evaluates each enabled rule's selections and `condition`
   expression (`and`/`or`/`not`, parens, `N of <pattern>` quantifiers) with
   Sigma field modifiers (`contains`, `startswith`, `endswith`, `re`, `cased`).
3. **Stateful rules** (`timeframe` + `threshold` + `group-by`) count matches per
   entity in the `StateManager` before firing.
4. A match produces an **Alert**.

## Correlation model

Alerts sharing any of the configured `correlation.match_fields` (default
`src_ip`, `user_name`, `dst_ip`) within `correlation.window_seconds` are grouped
into an **Incident** once at least `min_alerts_for_incident` alerts accumulate.
Each alert is **classified** into attack categories (`discovery`,
`credential_access`, `initial_access`, `impact`, `command_and_control`) from its
`attack.*` tags. A matching **correlation rule** (all stages observed) escalates
the incident to the rule's `escalate_to` severity (default `critical`).

## Automated response (SOAR-Lite)

After an incident is persisted and normal notifications are dispatched, the
pipeline calls `PlaybookEngine.evaluate(incident, alert)`. The engine:

- loads `config/playbooks.yaml` once at startup and validates every playbook;
- matches incident severity, rules, categories, correlation rule and alert count;
- claims a `(playbook_id, incident_id)` slot, capped by
  `max_runs_per_incident` for the process lifetime;
- renders command arguments and email fields from incident/alert context;
- runs command actions without a shell by default, or sends email through the
  existing `alerting.email` SMTP configuration;
- returns `PlaybookRun` results on `ProcessedAlert.playbook_runs` and aggregate
  counters under `Pipeline.summary()["soar"]`.

The engine is fail-open: an invalid file, modifier error or action failure is
logged and never aborts detection, correlation or persistence. The default
playbook is `dry_run: true`, so the response is previewed in `logs/siem.log`
rather than executed.

## Storage

- SQLite in **WAL mode** with foreign keys enabled; a schema-version table
  drives idempotent migrations (`siem/storage/migrations/`).
- Tables: `events`, `alerts` (linked to incidents via `alerts.incident_id`),
  `incidents`, `rules`, `correlation_state`, `notifications`, `users`,
  `config`, `audit_log`, and the `schema_migrations` bookkeeping table.
- A nightly-style **retention** job (`StorageService.run_retention`) prunes old
  events, alerts/notifications and closed incidents per the `retention` config.

## Web layer

- **Flask + Flask-Login** session auth with three roles
  (`viewer` < `analyst` < `admin`) and CSRF protection.
- **Flask-SocketIO** pushes realtime alert/incident updates to connected
  dashboards on the `/realtime` namespace.
- Server-rendered **Jinja** templates styled with Tailwind CSS, plus an optional
  JSON API for integrations.
- Every state-changing action is recorded in the **audit log**.

## Concurrency

- The streaming consumer runs on a worker thread; storage uses a
  connection-per-session factory.
- `SyslogServer` uses a thread (TCP) and a datagram thread (UDP); `FileTailer`
  polls with a short interval and follows rotation.
- The web app pushes updates through the Socket.IO server, which is safe to
  call from the pipeline callback thread.
