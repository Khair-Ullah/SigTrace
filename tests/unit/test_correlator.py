"""Tests for alert correlation and incident generation (Phase 5)."""
from datetime import datetime, timedelta
from pathlib import Path

from siem.core.config import Config
from siem.engine.correlation_rules import build_correlation_rule
from siem.engine.correlator import Correlator, classify_alert
from siem.engine.models import Alert

T0 = datetime(2026, 10, 17, 10, 0, 0)


def make_alert(ts, rule_name="Rule", severity="medium", src_ip=None,
               user_name=None, dst_ip=None, tags=None, aid=None):
    return Alert(
        alert_id=aid or f"AL-{ts.timestamp()}-{rule_name}",
        rule_id="r-" + rule_name,
        rule_name=rule_name,
        timestamp=ts,
        severity=severity,
        src_ip=src_ip,
        user_name=user_name,
        dst_ip=dst_ip,
        rule_tags=list(tags or []),
    )


def make_config(**corr):
    base = {"window_seconds": 300, "min_alerts_for_incident": 2,
            "match_fields": ["src_ip", "user_name", "dst_ip"]}
    base.update(corr)
    return Config({"correlation": base}, project_root=Path("."))


def test_single_alert_is_pending():
    c = Correlator(make_config())
    result = c.correlate(make_alert(T0, "Rule A", src_ip="1.2.3.4"))
    assert result.action == "pending"
    assert result.incident is None
    assert c.incidents == []


def test_two_related_alerts_create_incident():
    c = Correlator(make_config())
    c.correlate(make_alert(T0, "Rule A", "high", src_ip="1.2.3.4"))
    result = c.correlate(make_alert(T0 + timedelta(seconds=10), "Rule B", "medium",
                                    src_ip="1.2.3.4"))
    assert result.action == "created"
    inc = result.incident
    assert inc.alert_count == 2
    assert inc.severity == "high"          # highest of the group
    assert inc.src_ip == "1.2.3.4"
    assert len(c.incidents) == 1


def test_third_related_alert_updates_incident():
    c = Correlator(make_config())
    c.correlate(make_alert(T0, "Rule A", src_ip="1.2.3.4"))
    inc = c.correlate(make_alert(T0 + timedelta(seconds=5), "Rule B",
                                 src_ip="1.2.3.4")).incident
    result = c.correlate(make_alert(T0 + timedelta(seconds=20), "Rule C",
                                    "critical", src_ip="1.2.3.4"))
    assert result.action == "updated"
    assert result.incident.incident_id == inc.incident_id
    assert result.incident.alert_count == 3
    assert result.incident.severity == "critical"


def test_unrelated_alerts_stay_separate():
    c = Correlator(make_config())
    c.correlate(make_alert(T0, "A", src_ip="1.1.1.1"))
    c.correlate(make_alert(T0, "B", src_ip="2.2.2.2"))
    assert c.incidents == []
    assert len(c._pending) == 2


def test_alerts_outside_window_do_not_merge():
    c = Correlator(make_config(window_seconds=60))
    c.correlate(make_alert(T0, "A", src_ip="1.1.1.1"))
    result = c.correlate(make_alert(T0 + timedelta(seconds=120), "B", src_ip="1.1.1.1"))
    assert result.action == "pending"
    assert c.incidents == []


def test_min_alerts_enforced():
    c = Correlator(make_config(min_alerts_for_incident=3))
    assert c.correlate(make_alert(T0, "A", src_ip="1.1.1.1")).action == "pending"
    assert c.correlate(make_alert(T0 + timedelta(seconds=1), "B",
                                  src_ip="1.1.1.1")).action == "pending"
    result = c.correlate(make_alert(T0 + timedelta(seconds=2), "C", src_ip="1.1.1.1"))
    assert result.action == "created"
    assert result.incident.alert_count == 3


def test_match_on_user_name_when_no_ip():
    c = Correlator(make_config())
    c.correlate(make_alert(T0, "A", user_name="alice"))
    result = c.correlate(make_alert(T0 + timedelta(seconds=1), "B", user_name="alice"))
    assert result.action == "created"
    assert result.incident.user_name == "alice"


def test_classify_alert_from_tags():
    alert = make_alert(T0, "x", tags=["attack.discovery", "attack.t1046"])
    assert classify_alert(alert) == {"discovery"}


def test_classify_alert_from_name_heuristic():
    alert = make_alert(T0, "SSH Brute Force Attack Detection")
    assert "credential_access" in classify_alert(alert)


def test_multistage_escalates_via_correlation_rule():
    chain = build_correlation_rule(Path("mem.yml"), {
        "type": "correlation",
        "title": "Multi-Stage Intrusion",
        "stages": ["discovery", "credential_access", "initial_access"],
        "escalate_to": "critical",
        "title_template": "Multi-Stage Intrusion from {primary}",
    })
    c = Correlator(make_config(), correlation_rules=[chain])
    c.correlate(make_alert(T0, "Port Scan", "high", src_ip="9.9.9.9",
                           tags=["attack.discovery"]))
    c.correlate(make_alert(T0 + timedelta(seconds=5), "SSH Brute Force", "high",
                           src_ip="9.9.9.9", tags=["attack.credential_access"]))
    result = c.correlate(make_alert(T0 + timedelta(seconds=10), "Successful Root Login",
                                    "medium", src_ip="9.9.9.9",
                                    tags=["attack.initial_access"]))
    inc = result.incident
    assert inc.severity == "critical"
    assert "Multi-Stage Intrusion" in inc.title
    assert inc.correlation_rule_id == chain.rule_id
