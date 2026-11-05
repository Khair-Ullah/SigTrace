"""Tests for the retention/cleanup manager (FR-45)."""
from datetime import datetime, timedelta
from pathlib import Path

from siem.core.config import Config
from siem.engine.models import Alert, Incident
from siem.parsing.models import NormalizedEvent
from siem.storage.repositories import AlertRepository, EventRepository, IncidentRepository
from siem.storage.retention import RetentionManager

NOW = datetime(2026, 10, 17, 10, 0, 0)
DAYS = timedelta(days=1)


def _config():
    return Config(
        {"retention": {"events_days": 30, "alerts_days": 90, "incidents_days": 365}},
        project_root=Path("."),
    )


def _event(eid, ts):
    return NormalizedEvent(event_id=eid, timestamp=ts, source_id="s",
                           source_type="ssh", raw_log="r")


def _alert(aid, ts):
    return Alert(alert_id=aid, rule_id="r", rule_name="x", timestamp=ts,
                 severity="high")


def _incident(iid, ts, status):
    return Incident(incident_id=iid, title="t", severity="high",
                    first_seen=ts, last_seen=ts, status=status, alert_count=2)


def _seed(session_factory):
    ev = EventRepository(session_factory)
    al = AlertRepository(session_factory)
    inc = IncidentRepository(session_factory)

    ev.add_many([
        _event("old-e", NOW - 40 * DAYS),   # expired (>30d)
        _event("new-e", NOW - 1 * DAYS),    # kept
    ])
    al.add_many([
        _alert("old-a", NOW - 100 * DAYS),  # expired (>90d)
        _alert("new-a", NOW - 1 * DAYS),    # kept
    ])
    inc.upsert(_incident("old-closed", NOW - 400 * DAYS, "closed"))  # expired
    inc.upsert(_incident("old-open", NOW - 400 * DAYS, "open"))      # kept (active)
    inc.upsert(_incident("new-closed", NOW - 1 * DAYS, "closed"))    # kept


def test_dry_run_reports_without_deleting(session_factory):
    _seed(session_factory)
    mgr = RetentionManager(_config(), session_factory)
    summary = mgr.cleanup(now=NOW, dry_run=True)

    assert summary == {"events": 1, "alerts": 1, "incidents": 1, "notifications": 0}
    assert EventRepository(session_factory).count() == 2  # still present


def test_cleanup_deletes_expired(session_factory):
    _seed(session_factory)
    mgr = RetentionManager(_config(), session_factory)
    summary = mgr.cleanup(now=NOW)

    assert summary == {"events": 1, "alerts": 1, "incidents": 1, "notifications": 0}
    assert EventRepository(session_factory).get("old-e") is None
    assert EventRepository(session_factory).get("new-e") is not None
    assert AlertRepository(session_factory).get("old-a") is None
    assert IncidentRepository(session_factory).get("old-closed") is None
    assert IncidentRepository(session_factory).get("old-open") is not None
