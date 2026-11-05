"""Tests for notification channels."""
import json
from datetime import datetime
from pathlib import Path

from siem.alerting.notification import STATUS_FAILED, STATUS_SENT, STATUS_SKIPPED
from siem.alerting.notifiers import (
    CallbackNotifier,
    EmailNotifier,
    LogFileNotifier,
)
from siem.core.config import Config
from siem.engine.models import Alert

T0 = datetime(2026, 10, 17, 10, 0, 0)


def alert(severity="high", **kw):
    base = dict(alert_id="a1", rule_id="r1", rule_name="Brute Force",
                timestamp=T0, severity=severity, src_ip="1.2.3.4", count=5)
    base.update(kw)
    return Alert(**base)


def make_config(tmp_path, **alerting):
    base = {
        "email": {"enabled": False, "min_severity": "high", "to_addresses": []},
        "logfile": {"enabled": True, "path": str(tmp_path / "alerts.log"),
                    "min_severity": "medium"},
    }
    base.update(alerting)
    return Config({"alerting": base}, project_root=tmp_path)


# -- logfile ---------------------------------------------------------------
def test_logfile_writes_json_line(tmp_path):
    notifier = LogFileNotifier(make_config(tmp_path))
    result = notifier.send(alert())
    assert result.status == STATUS_SENT

    path = tmp_path / "alerts.log"
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["rule_name"] == "Brute Force"
    assert record["severity"] == "high"
    assert record["src_ip"] == "1.2.3.4"


def test_logfile_disabled(tmp_path):
    cfg = make_config(tmp_path, logfile={"enabled": False, "path": str(tmp_path / "a.log")})
    result = LogFileNotifier(cfg).send(alert())
    assert result.status == STATUS_SKIPPED


def test_logfile_accepts_by_severity(tmp_path):
    n = LogFileNotifier(make_config(tmp_path))  # min_severity medium
    assert n.accepts(alert(severity="medium")) is True
    assert n.accepts(alert(severity="high")) is True
    assert n.accepts(alert(severity="low")) is False


# -- callback --------------------------------------------------------------
def test_callback_invoked():
    seen = []
    n = CallbackNotifier([lambda a, i: seen.append(a.alert_id)])
    result = n.send(alert())
    assert result.status == STATUS_SENT
    assert seen == ["a1"]


def test_callback_failure_captured():
    def boom(a, i):
        raise RuntimeError("nope")
    result = CallbackNotifier([boom]).send(alert())
    assert result.status == STATUS_FAILED
    assert "nope" in result.detail


# -- email -----------------------------------------------------------------
class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=15):
        self.host, self.port = host, port
        self.sent = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)


def test_email_disabled(tmp_path, monkeypatch):
    result = EmailNotifier(make_config(tmp_path)).send(alert())
    assert result.status == STATUS_SKIPPED


def test_email_sends(tmp_path, monkeypatch):
    import smtplib
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    cfg = make_config(tmp_path, email={
        "enabled": True, "smtp_host": "mail.example.com", "smtp_port": 587,
        "use_tls": True, "from_address": "siem@example.com",
        "to_addresses": ["soc@example.com"], "min_severity": "high",
    })
    result = EmailNotifier(cfg).send(alert(severity="critical"))

    assert result.status == STATUS_SENT
    assert result.recipients == ["soc@example.com"]
    assert len(FakeSMTP.instances) == 1
    msg = FakeSMTP.instances[0].sent[0]
    assert msg["Subject"] == "[SIEM][CRITICAL] Brute Force"
    assert msg["To"] == "soc@example.com"


def test_email_failure_when_no_recipients(tmp_path):
    cfg = make_config(tmp_path, email={"enabled": True, "to_addresses": []})
    result = EmailNotifier(cfg).send(alert())
    assert result.status == STATUS_SKIPPED


def test_email_smtp_error(tmp_path, monkeypatch):
    import smtplib

    def boom(*a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(smtplib, "SMTP", boom)
    cfg = make_config(tmp_path, email={
        "enabled": True, "to_addresses": ["x@y.z"], "min_severity": "low",
    })
    result = EmailNotifier(cfg).send(alert())
    assert result.status == STATUS_FAILED
    assert "refused" in result.detail
