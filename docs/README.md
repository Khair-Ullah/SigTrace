# SIEM Log Correlation Engine — Documentation

A lightweight, rule-based SIEM log correlation engine for Small and
Medium-sized Organizations (SMOs).

| Document | Description |
| --- | --- |
| [Installation](installation.md) | Requirements, local setup and first run |
| [Configuration](configuration.md) | Every `config.yaml` option and environment override |
| [Writing Rules](rules.md) | Sigma-compatible detection rules and correlation rules |
| [SOAR-Lite Playbooks](soar.md) | Automated command/email responses for Critical incidents |
| [REST API](api.md) | JSON endpoints for the dashboard and integrations |
| [Architecture](architecture.md) | Component design and data flow |
| [Deployment](deployment.md) | Docker, docker compose and operations |

## At a glance

```text
log sources ─▶ ingestion ─▶ parsing ─▶ rule engine ─▶ correlation ─▶ storage
   (syslog, files)          (normalize)  (detect)       (incidents)     (SQLite)
                                                                    │
                                                          alerting ─┴─▶ email / log / WebSocket
                                                                    │
                                                            web dashboard + REST API
```

Critical incidents can also trigger [SOAR-Lite playbooks](soar.md), which preview or run local command/email responses after the incident is stored.
