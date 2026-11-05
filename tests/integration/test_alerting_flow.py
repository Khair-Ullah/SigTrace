"""Integration: detection -> correlation -> notification delivery (FR-47..FR-52)."""
import json
from datetime import datetime, timedelta

from siem.alerting.manager import AlertNotifier
from siem.alerting.notifiers import CallbackNotifier, EmailNotifier, LogFileNotifier
from siem.core.config import Config
from siem.engine.correlation_rules import CorrelationRuleLoader
from siem.engine.correlator import Correlator
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.parsing.models import NormalizedEvent
from siem.storage.repositories import NotificationRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)
ATTACKER = "203.0.113.9"


def _ev(ts, **kw) -> NormalizedEvent:
    base = dict(
        event_id=kw.pop("event_id", f"e-{ts.timestamp()}-{kw.get('event_type')}"),
        timestamp=ts,
        source_id="test",
        source_type=kw.pop("source_type", "custom"),
        raw_log=kw.pop("raw_log", ""),
    )
    base.update(kw)
    return NormalizedEvent(**base)


def _run_attack():
    engine = RuleEngine(RuleLoader().load())
    correlator = Correlator(correlation_rules=CorrelationRuleLoader().load())
    alerts, incident = [], None

    for i in range(20):  # discovery / port scan
        for a in engine.evaluate(_ev(T0 + timedelta(seconds=i * 0.1),
                                     event_type="firewall_deny", src_ip=ATTACKER,
                                     dst_ip="10.0.0.5", dst_port=i, source_type="firewall")):
            alerts.append(a)
            incident = correlator.correlate(a).incident or incident

    for i in range(5):  # credential access / brute force
        for a in engine.evaluate(_ev(T0 + timedelta(seconds=10 + i),
                                     event_type="failed_login", src_ip=ATTACKER,
                                     user_name="admin", source_type="ssh")):
            alerts.append(a)
            incident = correlator.correlate(a).incident or incident

    for a in engine.evaluate(_ev(T0 + timedelta(seconds=20),
                                 event_type="successful_login", user_name="root",
                                 src_ip=ATTACKER, source_type="ssh")):
        alerts.append(a)
        incident = correlator.correlate(a).incident or incident

    return alerts, incident


def test_attack_alerts_are_notified_and_logged(tmp_path, session_factory):
    alerts, incident = _run_attack()
    assert incident is not None and incident.severity == "critical"
    assert len(alerts) >= 3

    log_path = tmp_path / "alerts.log"
    callback_seen = []
    cfg = Config(
        {"alerting": {
            "email": {"enabled": False},
            "logfile": {"enabled": True, "path": str(log_path), "min_severity": "low"},
            "rate_limit": {"max_per_minute": 1000},
            "dedup_window_seconds": 0,
        }},
        project_root=tmp_path,
    )
    repo = NotificationRepository(session_factory)
    notifier = AlertNotifier(
        cfg,
        notifiers=[LogFileNotifier(cfg), CallbackNotifier(
            [lambda a, i: callback_seen.append((a.alert_id, i.incident_id if i else None))])],
        notification_repo=repo,
    )

    for alert in alerts:
        results = notifier.notify(alert, incident)
        assert all(r.status in ("sent", "skipped") for r in results)

    # every alert delivered on the callback channel at least once
    assert len(callback_seen) == len(alerts)
    assert all(iid == incident.incident_id for _, iid in callback_seen)

    # persisted with the incident link (one row per channel per alert)
    rows = repo.query(incident_id=incident.incident_id)
    assert len(rows) == len(alerts) * 2
    assert {r["status"] for r in rows} == {"sent"}
    assert repo.count(channel="callback") == len(alerts)
    assert repo.count(channel="logfile") == len(alerts)

    # log file holds one JSON record per alert
    lines = [json.loads(x) for x in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == len(alerts)
    assert {rec["incident_id"] for rec in lines} == {incident.incident_id}


def test_email_channel_routing(tmp_path):
    """Critical alerts route to email; low-severity ones do not."""
    from siem.engine.models import Alert

    def al(sev):
        return Alert(alert_id="a", rule_id="r", rule_name="R", timestamp=T0,
                     severity=sev, src_ip="1.2.3.4", count=1)

    cfg = Config(
        {"alerting": {"email": {"enabled": True, "min_severity": "high",
                                "to_addresses": []}}},
        project_root=tmp_path,
    )
    email = EmailNotifier(cfg)
    assert email.accepts(al("critical")) is True
    assert email.accepts(al("low")) is False
