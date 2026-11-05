"""Tests for DashboardStats aggregation."""
from datetime import timedelta

from siem.core.utils import utcnow
from siem.engine.models import Alert, Incident
from siem.parsing.models import NormalizedEvent
from siem.web.stats import DashboardStats


def _alert(i=0, severity="high", src_ip="1.1.1.1"):
    return Alert(alert_id=f"a{i}", rule_id="r1", rule_name="R", timestamp=utcnow(),
                 severity=severity, src_ip=src_ip, count=1)


def _event(i=0, ts=None):
    return NormalizedEvent(event_id=f"e{i}", timestamp=ts or utcnow(),
                           source_id="s", source_type="syslog", raw_log="x")


def _incident(i=0, status="open", severity="high"):
    now = utcnow()
    return Incident(incident_id=f"INC-{i}", title="T", severity=severity,
                    first_seen=now, last_seen=now, status=status)


def test_summary_counts(storage):
    storage.events.add_many([_event(i) for i in range(3)])
    storage.alerts.add_many([_alert(0, "high"), _alert(1, "critical")])
    storage.incidents.upsert(_incident(0, "open"))
    stats = DashboardStats(storage)

    summary = stats.summary()
    assert summary["events"] == 3
    assert summary["alerts"] == 2
    assert summary["alerts_unacknowledged"] == 2
    assert summary["incidents"] == 1
    assert summary["incidents_open"] == 1
    assert summary["severity"]["high"] == 1
    assert summary["severity"]["critical"] == 1
    assert summary["severity"]["low"] == 0


def test_top_src_ips(storage):
    storage.alerts.add_many([
        _alert(0, src_ip="9.9.9.9"), _alert(1, src_ip="9.9.9.9"),
        _alert(2, src_ip="8.8.8.8"),
    ])
    top = DashboardStats(storage).top_src_ips(limit=5)
    assert top[0] == {"src_ip": "9.9.9.9", "count": 2}


def test_timeline_buckets(storage):
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    storage.events.add_many([
        _event(0, now), _event(1, now),
        _event(2, now - timedelta(hours=1)),
    ])
    timeline = DashboardStats(storage).timeline(hours=3)
    assert len(timeline) == 3
    assert timeline[-1]["count"] == 2  # current hour
    assert timeline[-2]["count"] == 1  # previous hour
