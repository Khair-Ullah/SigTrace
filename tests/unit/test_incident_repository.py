"""Tests for IncidentRepository."""
from datetime import datetime, timedelta

from siem.engine.models import Incident
from siem.storage.repositories import IncidentRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)


def inc(i=0, **kw):
    base = dict(
        incident_id=f"INC-{i}",
        title="Multi-Stage Intrusion",
        severity="critical",
        first_seen=T0 + timedelta(seconds=i),
        last_seen=T0 + timedelta(seconds=i),
        status="open",
        src_ip="10.0.0.1",
        alert_count=3,
        alert_ids=[f"a{i}"],
        categories={"discovery", "credential_access"},
        correlation_rule_id="corr-1",
    )
    base.update(kw)
    return Incident(**base)


def test_upsert_insert_and_update(session_factory):
    repo = IncidentRepository(session_factory)
    repo.upsert(inc(0))
    got = repo.get("INC-0")
    assert got.alert_count == 3
    assert got.categories == {"discovery", "credential_access"}
    assert got.correlation_rule_id == "corr-1"

    updated = inc(0)
    updated.alert_count = 5
    updated.severity = "critical"
    updated.last_seen = T0 + timedelta(seconds=30)
    repo.upsert(updated)
    assert repo.count() == 1
    assert repo.get("INC-0").alert_count == 5


def test_query_by_status_severity(session_factory):
    repo = IncidentRepository(session_factory)
    repo.upsert(inc(0, status="open", severity="high"))
    repo.upsert(inc(1, status="closed", severity="critical"))
    assert repo.count(status="open") == 1
    assert repo.count(severity="critical") == 1
    assert len(repo.query(status="closed")) == 1


def test_update_status(session_factory):
    repo = IncidentRepository(session_factory)
    repo.upsert(inc(0))
    assert repo.update_status("INC-0", "investigating") == 1
    assert repo.get("INC-0").status == "investigating"


def test_delete_older_than_only_closed(session_factory):
    repo = IncidentRepository(session_factory)
    repo.upsert(inc(0, status="open", last_seen=T0))
    repo.upsert(inc(1, status="closed", last_seen=T0))
    # both are old, but only the closed one should be removed
    removed = repo.delete_older_than(T0 + timedelta(seconds=1), only_closed=True)
    assert removed == 1
    assert repo.get("INC-0") is not None
    assert repo.get("INC-1") is None
