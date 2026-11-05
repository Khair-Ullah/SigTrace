# SOAR-Lite Playbooks

SOAR-Lite adds small, local automated responses to the correlation pipeline.
When a playbook matches an incident, SIEM can preview or run a command and send
an email. It is deliberately not a general-purpose automation platform: there
is no remote executor, no plugin marketplace and no hidden cloud dependency.

The bundled playbook is **safe by default**:

```yaml
enabled: true
dry_run: true
max_runs_per_incident: 1
```

Matching Critical incidents are evaluated, but actions are previewed instead of
executed. Review the preview in `logs/siem.log`, then opt in explicitly.

## Where playbooks live

| Mode | Path |
| --- | --- |
| Desktop app | `%LOCALAPPDATA%\SIEM\config\playbooks.yaml` |
| Source checkout | `config/playbooks.yaml` |
| Override | `soar.playbooks_path`, `SIEM_PLAYBOOKS`, or `PlaybookEngine(path=...)` |

The desktop bootstrap copies the bundled file into the writable config folder
on first run and never overwrites an existing file. Keep `playbooks.yaml` under
version control if you manage it centrally, then distribute it with your normal
configuration process.

`config/config.yaml` has a matching switch:

```yaml
soar:
  enabled: true
  # playbooks_path: "config/playbooks.yaml"
```

`soar.enabled: false` disables the engine without deleting playbooks. A
per-playbook `enabled: false` disables only that playbook.

## Execution model

1. The pipeline parses a log, the rule engine creates an alert, and the
   correlator creates or updates an incident.
2. The incident is persisted and normal notifications are sent.
3. The playbook engine evaluates each enabled playbook.
4. A matching playbook runs at most `max_runs_per_incident` times for that
   incident. The counter is in memory and resets when SIEM restarts.
5. Failures are recorded in the run result and logged. They never stop
   detection, correlation or notification processing.

SOAR runs only when an incident exists. A first alert that does not yet meet
`correlation.min_alerts_for_incident` has no incident and therefore no
response.

## File schema

```yaml
version: 1
enabled: true
dry_run: true
max_runs_per_incident: 1

playbooks:
  - id: "critical-block-source"
    name: "Block critical source IP"
    description: "Block the source at the host firewall."
    enabled: true
    match:
      severities: ["critical"]
      min_alert_count: 1
    actions:
      - name: "Block source"
        type: "command"
        command: ["iptables", "-I", "INPUT", "-s", "{src_ip}", "-j", "DROP"]
        require: ["src_ip"]
        shell: false
        timeout_seconds: 15
        continue_on_error: true
```

### Top-level keys

| Key | Default | Description |
| --- | --- | --- |
| `version` | `1` | Document version (informational) |
| `enabled` | `true` | Master switch for this file |
| `dry_run` | `true` | Preview actions instead of executing them |
| `max_runs_per_incident` | `1` | Per-playbook limit for one incident |

### Playbook keys

| Key | Required | Description |
| --- | --- | --- |
| `id` | yes | Unique, stable identifier |
| `name` | no | Display name (defaults to `id`) |
| `description` | no | Operator-facing purpose |
| `enabled` | no | Default `true` |
| `match` | no | Incident conditions; defaults to Critical only |
| `actions` | yes | One or more command/email actions |

### Match conditions

All configured conditions must pass. Omitted conditions are ignored, except
`severities`, which defaults to `["critical"]`.

| Key | Description |
| --- | --- |
| `severities` | Incident severities (`critical`, `high`, `medium`, `low`) |
| `rule_ids` | Rule IDs observed on the current alert |
| `rule_names` | Rule names present on the incident |
| `categories` | Attack categories present on the incident |
| `correlation_rule_ids` | IDs of the matching correlation rule |
| `min_alert_count` | Minimum number of alerts in the incident |

An empty list is treated as "no restriction". To match all severities
explicitly, use `severities: ["critical", "high", "medium", "low"]`.

### Command actions

| Key | Default | Description |
| --- | --- | --- |
| `type` | required | `command` |
| `command` | required | String or list of arguments |
| `require` | `[]` | Context fields that must be non-empty |
| `shell` | `false` | Pass a string command through the shell |
| `timeout_seconds` | `15` | Kill the process after this many seconds |
| `working_directory` | data root | Working directory for the command |
| `continue_on_error` | `true` | Continue with the next action after a failure |

Use a list for production commands. Lists are split into argv and are not
interpreted by a shell, which avoids quoting and injection problems:

```yaml
command: ["iptables", "-I", "INPUT", "-s", "{src_ip}", "-j", "DROP"]
```

Use a string with `shell: true` only when you intentionally need shell syntax:

```yaml
command: "iptables -I INPUT -s {src_ip} -j DROP && logger 'SIEM blocked {src_ip}'"
shell: true
```

A command succeeds when its exit code is `0`. Non-zero exits mark the action
failed; `stderr` is captured in the result and the application log.

### Email actions

| Key | Default | Description |
| --- | --- | --- |
| `type` | required | `email` |
| `to` | required | One or more recipient addresses |
| `cc` | `[]` | Carbon-copy recipients |
| `subject` | built-in | Rendered subject line |
| `body` | built-in | Rendered plain-text body |
| `from_address` | alerting email | Overrides the configured sender |
| `require` | `[]` | Context fields that must be non-empty |
| `continue_on_error` | `true` | Continue with the next action after a failure |

Email actions reuse `alerting.email` SMTP settings, so email must be enabled and
credentials must be configured:

```yaml
alerting:
  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 587
    use_tls: true
    username: "siem@example.com"
    password: "CHANGE_ME"
    from_address: "siem@example.com"
```

When execution is enabled and `alerting.email.enabled` is false, email actions
are skipped with an explicit reason. Dry-run still previews the email.

## Template placeholders

Every command argument, subject and body supports these placeholders:

| Placeholder | Value |
| --- | --- |
| `{incident_id}` | Incident identifier |
| `{title}` | Incident title |
| `{description}` | Incident description |
| `{severity}` | Incident severity |
| `{status}` | Incident status |
| `{src_ip}` | Incident source IP |
| `{dst_ip}` | Destination IP from the current alert |
| `{user_name}` | Incident user name |
| `{alert_count}` | Number of alerts in the incident |
| `{categories}` | Sorted attack categories |
| `{rule_names}` | Sorted rule names |
| `{correlation_rule_id}` | Matching correlation rule |
| `{first_seen}` / `{last_seen}` | Incident timestamps |
| `{alert_id}` / `{rule_id}` / `{rule_name}` | Current alert fields |
| `{alert_description}` | Current alert description |
| `{timestamp}` | Current alert timestamp |
| `{playbook_id}` / `{playbook_name}` | Matched playbook |

Unknown placeholders are left unchanged. Use `require` to skip an action when a
value such as `src_ip` is empty:

```yaml
require: ["src_ip"]
```

## Safe rollout

1. Keep `dry_run: true` and restart SIEM after editing playbooks.
2. Run a demo incident:
   `python -m siem simulate --scenario multi_stage`.
3. Inspect `logs/siem.log` for lines beginning with `SOAR dry-run:`.
4. Confirm the rendered command, source IP and recipients.
5. Set `dry_run: false` only for the playbook you have reviewed.
6. Keep `max_runs_per_incident: 1` unless you have a deliberate reason to
   repeat a response.
7. Test the command outside SIEM with the exact argv and a harmless source IP
   before enabling it.

The desktop app runs as an elevated user through its logon task. Firewall
commands therefore have the permissions they need, but that also means a
misconfigured playbook can make host-level changes. Treat `playbooks.yaml` as a
privileged configuration file.

## Observability

The engine records aggregate counters in `Pipeline.summary()["soar"]`:

```text
evaluations, runs, completed, partial, failed, skipped, dry_run,
actions, actions_success, actions_dry_run, actions_skipped, actions_failed
```

Each processed alert also carries `playbook_runs` with per-action status,
detail, output and recipients. Currently these results are in-process only;
they are not written to the SQLite schema.

Recommended log searches:

```powershell
Select-String -Path "$env:LOCALAPPDATA\SIEM\logs\siem.log" -Pattern "SOAR"
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No playbook runs | Incident severity, `soar.enabled`, playbook `enabled`, and `match` conditions |
| Run status is `dry_run` | Set top-level `dry_run: false` after reviewing the preview |
| Email action is `skipped` | `alerting.email.enabled` must be `true` |
| Command action is `skipped` | A field in `require` is empty, or the action is disabled |
| Playbook not loaded | Check YAML syntax and the `playbooks.yaml` path in the log |
| Action failed | Inspect `stderr`/exit code and test the command manually |
| Duplicate responses | Lower `max_runs_per_incident`; counters reset on restart |

Invalid YAML or an invalid action disables the engine for that process and logs
the validation error. Detection continues normally.
