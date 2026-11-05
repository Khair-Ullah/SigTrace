"""Notification channels: email, log-file and callback (FR-48..FR-50)."""
from __future__ import annotations

import json
import smtplib
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Optional

from siem.alerting.notification import (
    STATUS_FAILED,
    STATUS_SENT,
    STATUS_SKIPPED,
    NotificationResult,
)
from siem.core.config import Config, get_config
from siem.core.constants import SEVERITY_ORDER
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.engine.models import Alert, Incident

log = get_logger("alerting.notifiers")

SendCallback = Callable[[Alert, Optional[Incident]], None]


class BaseNotifier:
    """Base class for a single notification channel."""

    channel = "base"
    min_severity = "low"

    def accepts(self, alert: Alert) -> bool:
        """True if the alert meets this channel's severity threshold."""
        return (
            SEVERITY_ORDER.get(alert.severity, 0)
            >= SEVERITY_ORDER.get(self.min_severity, 0)
        )

    def send(self, alert: Alert, incident: Optional[Incident] = None) -> NotificationResult:
        raise NotImplementedError


def _summary(alert: Alert, incident: Optional[Incident]) -> str:
    lines = [
        f"Rule      : {alert.rule_name}",
        f"Severity  : {alert.severity.upper()}",
        f"Time      : {alert.timestamp.isoformat()}",
    ]
    if alert.src_ip:
        lines.append(f"Source IP : {alert.src_ip}")
    if alert.dst_ip:
        lines.append(f"Dest IP   : {alert.dst_ip}")
    if alert.user_name:
        lines.append(f"User      : {alert.user_name}")
    lines.append(f"Count     : {alert.count}")
    if incident is not None:
        lines.append(f"Incident  : {incident.title} ({incident.incident_id})")
    if alert.description:
        lines.append(f"Details   : {alert.description}")
    return "\n".join(lines)


class EmailNotifier(BaseNotifier):
    """Send alerts over SMTP (starttls)."""

    channel = "email"

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.enabled = bool(self.config.get("alerting.email.enabled", False))
        self.min_severity = self.config.get("alerting.email.min_severity", "high")
        self.host = self.config.get("alerting.email.smtp_host", "localhost")
        self.port = int(self.config.get("alerting.email.smtp_port", 587))
        self.use_tls = bool(self.config.get("alerting.email.use_tls", True))
        self.username = self.config.get("alerting.email.username", "")
        self.password = self.config.get("alerting.email.password", "")
        self.from_address = self.config.get("alerting.email.from_address", "")
        self.to_addresses = list(self.config.get("alerting.email.to_addresses", []) or [])

    def send(self, alert: Alert, incident: Optional[Incident] = None) -> NotificationResult:
        if not self.enabled:
            return NotificationResult(self.channel, STATUS_SKIPPED, alert.alert_id,
                                      detail="email disabled")
        if not self.to_addresses:
            return NotificationResult(self.channel, STATUS_SKIPPED, alert.alert_id,
                                      detail="no recipients configured")

        msg = self._build_message(alert, incident)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=15) as server:
                if self.use_tls:
                    server.starttls()
                if self.username:
                    server.login(self.username, self.password)
                server.send_message(msg)
        except Exception as e:  # network/auth errors must not crash the pipeline
            log.warning("Email notification failed for alert %s: %s", alert.alert_id, e)
            return NotificationResult(self.channel, STATUS_FAILED, alert.alert_id,
                                      recipients=list(self.to_addresses), detail=str(e))

        return NotificationResult(self.channel, STATUS_SENT, alert.alert_id,
                                  recipients=list(self.to_addresses))

    def _build_message(self, alert: Alert, incident: Optional[Incident]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = f"[SIEM][{alert.severity.upper()}] {alert.rule_name}"
        msg["From"] = self.from_address or self.username or "siem@localhost"
        msg["To"] = ", ".join(self.to_addresses)
        msg.set_content(_summary(alert, incident))
        return msg


class LogFileNotifier(BaseNotifier):
    """Append one JSON line per alert to a log file."""

    channel = "logfile"

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.enabled = bool(self.config.get("alerting.logfile.enabled", True))
        self.min_severity = self.config.get("alerting.logfile.min_severity", "medium")
        path = self.config.get("alerting.logfile.path", "logs/alerts.log")
        p = Path(path)
        self.path = p if p.is_absolute() else self.config.project_root / p

    def send(self, alert: Alert, incident: Optional[Incident] = None) -> NotificationResult:
        if not self.enabled:
            return NotificationResult(self.channel, STATUS_SKIPPED, alert.alert_id,
                                      detail="logfile disabled")
        record = {
            "timestamp": utcnow().isoformat(),
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "user_name": alert.user_name,
            "count": alert.count,
            "tags": alert.rule_tags,
            "incident_id": incident.incident_id if incident else alert.incident_id,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as e:
            log.warning("Logfile notification failed for alert %s: %s", alert.alert_id, e)
            return NotificationResult(self.channel, STATUS_FAILED, alert.alert_id,
                                      detail=str(e))
        return NotificationResult(self.channel, STATUS_SENT, alert.alert_id,
                                  recipients=[str(self.path)])


class CallbackNotifier(BaseNotifier):
    """Invoke in-process callbacks (used by the web dashboard / tests)."""

    channel = "callback"

    def __init__(self, callbacks: list[SendCallback], channel: str = "callback",
                 min_severity: str = "low"):
        self.callbacks = list(callbacks)
        self.channel = channel
        self.min_severity = min_severity

    def send(self, alert: Alert, incident: Optional[Incident] = None) -> NotificationResult:
        try:
            for cb in self.callbacks:
                cb(alert, incident)
        except Exception as e:
            return NotificationResult(self.channel, STATUS_FAILED, alert.alert_id,
                                      detail=str(e))
        return NotificationResult(self.channel, STATUS_SENT, alert.alert_id)


def build_default_notifiers(config: Optional[Config] = None) -> list[BaseNotifier]:
    """Construct the default channel list from configuration."""
    config = config or get_config()
    return [EmailNotifier(config), LogFileNotifier(config)]
