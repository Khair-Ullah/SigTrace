"""Integration: detection rules + correlator produce a multi-stage incident."""
from datetime import datetime, timedelta

from siem.engine.correlation_rules import CorrelationRuleLoader
from siem.engine.correlator import Correlator
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.parsing.models import NormalizedEvent

T0 = datetime(2026, 10, 17, 10, 0, 0)
ATTACKER = "203.0.113.7"


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


def _build():
    engine = RuleEngine(RuleLoader().load())
    correlator = Correlator(correlation_rules=CorrelationRuleLoader().load())
    return engine, correlator


def test_builtin_correlation_rules_load():
    loader = CorrelationRuleLoader()
    rules = loader.load()
    assert loader.last_errors == []
    assert len(rules) >= 2


def test_multistage_attack_produces_critical_incident():
    engine, correlator = _build()
    incident = None

    # Stage 1: reconnaissance -> port scan (20 firewall denies / 10s)
    for i in range(20):
        for alert in engine.evaluate(_ev(
                T0 + timedelta(seconds=i * 0.1), event_type="firewall_deny",
                src_ip=ATTACKER, dst_ip="10.0.0.5", dst_port=i,
                source_type="firewall")):
            incident = correlator.correlate(alert).incident or incident

    # Stage 2: credential access -> SSH brute force (5 fails / 60s)
    for i in range(5):
        for alert in engine.evaluate(_ev(
                T0 + timedelta(seconds=10 + i), event_type="failed_login",
                src_ip=ATTACKER, user_name="admin", source_type="ssh")):
            incident = correlator.correlate(alert).incident or incident

    # Stage 3: successful root login -> initial access
    for alert in engine.evaluate(_ev(
            T0 + timedelta(seconds=20), event_type="successful_login",
            user_name="root", src_ip=ATTACKER, source_type="ssh")):
        incident = correlator.correlate(alert).incident or incident

    assert incident is not None
    assert incident.alert_count >= 3
    assert incident.severity == "critical"
    assert "Multi-Stage" in incident.title
    assert {"discovery", "credential_access", "initial_access"} <= incident.categories
    assert incident.correlation_rule_id is not None
    assert correlator.stats["incidents_created"] == 1


def test_unrelated_sources_not_correlated():
    engine, correlator = _build()
    for src in (ATTACKER, "198.51.100.2"):
        for alert in engine.evaluate(_ev(
                T0, event_type="web_access", src_ip=src, source_type="web",
                message="GET /x?id=1 UNION SELECT password FROM users")):
            correlator.correlate(alert)
    # each source produced a single, unrelated alert -> no incident yet
    assert correlator.incidents == []
