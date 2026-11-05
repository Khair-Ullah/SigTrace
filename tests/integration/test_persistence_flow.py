"""Integration: pipeline output persists and round-trips through the DB."""
from datetime import datetime, timedelta

from siem.engine.correlation_rules import CorrelationRuleLoader
from siem.engine.correlator import Correlator
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.parsing.models import NormalizedEvent
from siem.storage.service import StorageService

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


def _run_pipeline():
    rules = RuleLoader().load()
    engine = RuleEngine(rules)
    correlator = Correlator(correlation_rules=CorrelationRuleLoader().load())

    events, alerts, incidents = [], [], []

    def feed(ev):
        events.append(ev)
        for alert in engine.evaluate(ev):
            alerts.append(alert)
            result = correlator.correlate(alert)
            if result.incident and result.incident not in incidents:
                incidents.append(result.incident)

    for i in range(20):  # port scan
        feed(_ev(T0 + timedelta(seconds=i * 0.1), event_type="firewall_deny",
                 src_ip=ATTACKER, dst_ip="10.0.0.5", dst_port=i,
                 source_type="firewall"))
    for i in range(5):   # brute force
        feed(_ev(T0 + timedelta(seconds=10 + i), event_type="failed_login",
                 src_ip=ATTACKER, user_name="admin", source_type="ssh"))
    feed(_ev(T0 + timedelta(seconds=20), event_type="successful_login",  # access
             user_name="root", src_ip=ATTACKER, source_type="ssh"))

    return rules, events, alerts, incidents


def test_pipeline_persists_and_links(fk_session_factory):
    from siem.storage.service import StorageService

    storage = StorageService(session_factory=fk_session_factory)
    rules, events, alerts, incidents = _run_pipeline()

    summary = storage.save_pipeline(
        rules=rules, events=events, alerts=alerts, incidents=incidents
    )
    assert summary == {
        "events": len(events), "alerts": len(alerts),
        "incidents": len(incidents), "rules": len(rules),
    }

    # events persisted
    assert storage.events.count() == len(events)
    assert storage.events.count(event_type="firewall_deny") == 20

    # alerts persisted with tags/count intact
    assert storage.alerts.count() == len(alerts)
    top = storage.alerts.query(severity="high")[0]
    assert top.rule_tags  # MITRE tags round-tripped

    # incident persisted and escalated
    assert storage.incidents.count() == 1
    stored_inc = storage.incidents.get(incidents[0].incident_id)
    assert stored_inc.severity == "critical"
    assert stored_inc.categories == {"discovery", "credential_access", "initial_access"}

    # alerts are linked to the incident
    assert storage.alerts.count(incident_id=incidents[0].incident_id) == len(alerts)

    # rules persisted
    assert storage.rules.count() == len(rules)


def test_storage_service_retention_summary(storage: StorageService):
    storage.persist_events([_ev(T0, event_id="old")])
    summary = storage.run_retention(dry_run=True)
    assert set(summary) == {"events", "alerts", "incidents", "notifications"}
