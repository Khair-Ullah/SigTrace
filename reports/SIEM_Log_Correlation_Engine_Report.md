# SIEM Log Correlation Engine - Project Report

**Project Title:** SIEM Log Correlation Engine  
**Submitted By:** Student Group  
**Course:** Cyber Security / Information Security  
**Date:** October 2026  
**Project Type:** Academic Mini-SOC Project

## Table of Contents

- [1. Abstract](#1-abstract)
- [2. Introduction](#2-introduction)
- [3. Objectives](#3-objectives)
- [4. Literature Review](#4-literature-review)
- [5. System Requirements](#5-system-requirements)
- [6. Technology Stack](#6-technology-stack)
- [7. System Architecture](#7-system-architecture)
- [8. Modules Description](#8-modules-description)
- [9. Implementation Details](#9-implementation-details)
- [10. Syslog Integration & Network Log Monitoring](#10-syslog-integration--network-log-monitoring)
- [11. Real-Time Capability Analysis](#11-real-time-capability-analysis)
- [12. Mini-SOC vs Full Enterprise SOC Comparison](#12-mini-soc-vs-full-enterprise-soc-comparison)
- [13. Testing](#13-testing)
- [14. Limitations](#14-limitations)
- [15. Future Enhancements](#15-future-enhancements)
- [16. Conclusion](#16-conclusion)
- [17. References](#17-references)
- [18. Appendix](#18-appendix)

## 1. Abstract

The SIEM Log Correlation Engine is a lightweight, Python-based Security Information and Event Management (SIEM) system developed to collect, parse, normalize, correlate and analyze security logs in real-time. It provides a web-based dashboard for visualization, alerting and incident management. The system is capable of ingesting logs via Syslog (UDP/TCP), HTTP API and file tailing, making it suitable for monitoring network devices such as firewalls, routers and Linux servers in a lab environment. This project demonstrates the core functionality of a Mini-SOC.

## 2. Introduction

With the increasing number of cyber-attacks, organizations need centralized log monitoring to detect malicious activities. A SIEM collects logs from multiple sources, applies detection rules, correlates events and generates alerts. Commercial SIEMs are expensive, complex and resource-heavy. This project aims to build an affordable, educational SIEM focusing on core concepts like log ingestion, parsing, rule-based detection, correlation, alerting and visualization.

## 3. Objectives

- To design and implement a centralized log collection system
- To parse and normalize logs from heterogeneous sources
- To implement a rule-based detection engine
- To correlate multiple related alerts into incidents
- To provide real-time alerts via web dashboard using Socket.IO
- To support Syslog for network device log ingestion
- To demonstrate Mini-SOC capabilities for academic purposes

## 4. Literature Review

| Tool | Description | Remarks |
|---|---|---|
| Splunk | Enterprise SIEM with advanced analytics | Powerful but expensive |
| ELK Stack (Elasticsearch, Logstash, Kibana) | Open-source log analytics platform | Scalable but requires more setup |
| Wazuh | Open-source XDR/SIEM | Feature rich, good for HIDS/EDR integration |
| Graylog | Log management platform | Focused more on log aggregation than correlation |

This project focuses on simplicity and clarity of SIEM fundamentals rather than enterprise scale.

## 5. System Requirements

### Hardware Requirements
- Processor: Intel Core i3 or higher
- RAM: 4GB minimum (8GB recommended)
- Storage: 500MB free space
- Network: LAN/Wi-Fi for syslog testing

### Software Requirements
- OS: Windows 10/11, Linux (Ubuntu/Kali) or macOS
- Python: 3.10+
- Web Browser: Chrome, Firefox, Edge
- Terminal/PowerShell

## 6. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Backend | Python 3.10, Flask | Web framework & core logic |
| Real-time | Flask-SocketIO | Live alerts/notifications |
| Database | SQLite (SQLAlchemy ORM) | Event/Alert/Incident storage |
| Parsing | Custom Parsers (Syslog, JSON, Plaintext, pfSense) | Log normalization |
| Rules Engine | YAML-based Sigma-like rules | Threat detection |
| Correlation | Custom Correlator | Group related alerts |
| Frontend | HTML, Tailwind CSS, JavaScript | Dashboard UI |
| Config | PyYAML, python-dotenv | Configuration management |

## 7. System Architecture

The system follows a layered architecture:

1. **Ingestion Layer** - Receives logs via Syslog (UDP/TCP), HTTP POST /api/ingest, File tailing
2. **Parsing Layer** - Detects format and extracts fields (src_ip, dst_ip, user, event_type, severity)
3. **Normalization Layer** - Converts to unified NormalizedEvent schema
4. **Detection Layer (Rule Engine)** - Matches events against YAML rules
5. **Correlation Layer** - Correlates alerts based on time window and fields
6. **Storage Layer** - Persists events, alerts, incidents in SQLite
7. **Alerting Layer** - Notifies via dashboard, logs, and realtime sockets
8. **Presentation Layer (Web UI)** - Dashboard, Events, Alerts, Incidents, Monitor, Rules

## 8. Modules Description

| Module | Description |
|---|---|
| `siem/ingestion/` | Syslog receiver, HTTP ingest, file sources |
| `siem/parsing/` | Format detection, parsers, normalizer |
| `siem/engine/` | Rule loader, rule engine, correlator |
| `siem/pipeline/` | End-to-end event processing pipeline |
| `siem/storage/` | Models, repositories, migrations, service layer |
| `siem/alerting/` | Notification manager and channels |
| `siem/web/` | Flask app, routes, auth, realtime, templates, static files |
| `siem/monitoring/` | Local system monitoring (Windows EventLog/File tailing) |
| `scripts/` | DB setup, user creation, demo/reset utilities |

## 9. Implementation Details

- **Migrations:** Schema versioning via SQL migration files (001-005)
- **Authentication:** Role-based access (admin/analyst/viewer) with hashed passwords (Werkzeug)
- **Security:** CSRF protection, secure session cookies, secret key handling via .env
- **Realtime:** Socket.IO namespace `/realtime` for pushing alerts/incidents
- **Configuration:** Hierarchical config via `config/config.yaml` with env overrides

## 10. Syslog Integration & Network Log Monitoring

To monitor network devices in real-time, use the engine mode.

### Prerequisites
- SIEM machine IP known (e.g., 192.168.1.100)
- Network connectivity between device and SIEM
- Port allowed through firewall

### Steps

1. **Configure port** in `config/config.yaml`:
```yaml
ingestion:
  syslog:
    enabled: true
    udp_port: 5514
    tcp_port: 5514
    host: "0.0.0.0"
```

2. **Start engine with web dashboard:**
```powershell
cd F:\SIEM
python -m siem run --web
```

3. **Configure network device (Example: pfSense/OPNsense)**
   - Navigate to Status > System Logs > Settings (or equivalent)
   - Remote Logging: Enable
   - Remote log servers: `192.168.1.100:5514`
   - Protocol: UDP
   - Log everything relevant to Security/Firewall

4. **Verify**
   - Open dashboard: `http://localhost:5000` -> Login
   - Go to `Events` tab to see incoming logs
   - Go to `Alerts` tab if rules match
   - Go to `Incidents` tab for correlated alerts

### Quick Test from CLI
```powershell
python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'<34>Oct 20 12:00:00 test sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2',('127.0.0.1',5514)); s.close()"
```

## 11. Real-Time Capability Analysis

| Aspect | Assessment | Explanation |
|---|---|---|
| Syslog Reception | Real-time/Near Real-time | UDP/TCP listener processes packets on arrival |
| Rule Matching | Near Real-time | Events evaluated immediately after parsing |
| Correlation | Near Real-time | Time-window based correlation runs with alerts |
| Dashboard Updates | Real-time | Socket.IO pushes alerts/incidents instantly |
| File Tailing | Near Real-time | Polls files at configured intervals |
| Local Monitor Tab | Near Real-time | Polls every few seconds |

**Verdict:** The project is **real-time capable for lab use**. For practical purposes it behaves as near real-time with minimal latency suitable for demonstration and testing.

## 12. Mini-SOC vs Full Enterprise SOC Comparison

| Capability | Mini-SOC (This Project) | Enterprise SOC (Splunk/Wazuh/QRadar) |
|---|---|---|
| Log Collection | Yes (Syslog/HTTP/File) | Yes (Agents, Syslog, API, Cloud, OT) |
| Parsing/Normalization | Yes (Basic) | Yes (Advanced CIM/Universal Normalization) |
| Rule-based Detection | Yes | Yes + Advanced Analytics |
| Correlation | Yes (Basic) | Yes (Complex multi-source) |
| Incident Management | Yes (Basic) | Yes (Advanced Case Mgmt, Playbooks) |
| Real-time Alerting | Yes | Yes |
| Threat Intelligence | Limited/None | Yes (Integrated Feeds) |
| SOAR Automation | No | Yes |
| UEBA | No | Yes |
| Scalability (High EPS) | Limited (SQLite/Threading) | High (Distributed) |
| Compliance Reporting | Minimal | Extensive |
| Cost | Free | Expensive (License + Infra) |

## 13. Testing

### Test 1: Syslog Brute Force Simulation
Send multiple failed login attempts from same IP within short window to trigger brute force rule.

### Test 2: Web Dashboard Access
Login with created admin user, verify all tabs load correctly.

### Test 3: Realtime Alerts
Trigger an alert and observe toast notification + page updates.

### Test 4: Horizontal Scrolling Fix
Verify Events/Alerts/Incidents tables scroll horizontally on smaller screens/larger columns.

## 14. Limitations

- **Database:** SQLite is not suitable for very high event throughput
- **Concurrency:** Uses threading model, not fully async at scale
- **Syslog Security:** No TLS encryption for syslog transport
- **Authentication:** Basic role system, lacks MFA
- **Threat Intel:** No external IOC integration
- **Log Archival:** Limited long-term storage strategy
- **Windows Syslog:** Port 514 requires elevated privileges
- **Scalability:** Designed for educational/lab environments

## 15. Future Enhancements

- Migrate to PostgreSQL or TimescaleDB for better performance
- Add TLS support for Syslog (RFC 5425)
- Integrate Threat Intelligence feeds (AbuseIPDB, MISP)
- Implement MITRE ATT&CK Navigator style mapping
- Add Email/SMS/Teams alerting channels
- Implement SOAR-like automated response actions
- Add advanced dashboards with charts and statistics
- Enable log forwarding and load balancing
- Add API key management and audit trails
- Implement report generation in PDF/CSV

## 16. Conclusion

This project successfully demonstrates the core concepts of a SIEM system. It achieves log collection, parsing, detection, correlation, alerting and visualization in a unified platform. While not a replacement for commercial enterprise SIEMs, it effectively serves as a **Mini-SOC** solution for learning, lab environments and academic demonstrations. With further enhancements, it can be extended towards a more production-like lightweight SIEM.

## 17. References

- NIST SP 800-92: Guide to Computer Security Log Management - https://csrc.nist.gov/publications/detail/sp/800-92/final
- MITRE ATT&CK Framework - https://attack.mitre.org/
- RFC 5424 - The Syslog Protocol - https://www.rfc-editor.org/rfc/rfc5424
- Sigma Rules Project - https://github.com/SigmaHQ/sigma
- OWASP Logging Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Flask Documentation - https://flask.palletsprojects.com/
- SQLAlchemy Documentation - https://www.sqlalchemy.org/

## 18. Appendix

### A. Installation
```powershell
git clone <repo-url> F:\SIEM
cd F:\SIEM
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### B. Database Setup & Reset
```powershell
python scripts/setup_db.py --force
python scripts/reset_fresh_db.py  # safe reset
```

### C. User Management
```powershell
python scripts/create_user.py create --username admin --password <password> --role admin
python scripts/create_user.py list
```

### D. Running the System
```powershell
# Web only
python -m siem web

# Engine + Web Dashboard (Recommended for network logs)
python -m siem run --web

# Production style
python -m siem serve
```

### E. Environment Variables (.env)
Copy `.env.example` to `.env` and configure `SIEM_SECRET_KEY`, `SIEM_INGEST_TOKENS` etc.

### F. Access
- URL: `http://localhost:5000`
- Default workflow: Create user -> Login -> Start engine -> Send syslog -> Monitor Events/Alerts/Incidents
