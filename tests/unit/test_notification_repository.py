"""Tests for NotificationRepository."""
from datetime import datetime, timedelta

from siem.alerting.notification import NotificationResult
from siem.storage.repositories import NotificationRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)


def make_result(n=0, **kw):
    base = dict(channel="email", status="sent", alert_id=f"a{n}",
                incident_id=f"i{n}", recipients=["soc@example.com"],
                detail="", created_at=T0)
    base.update(kw)
    return NotificationResult(**base)


def test_add_and_query(session_factory):
    repo = NotificationRepository(session_factory)
    nid = repo.add(make_result(0))
    assert isinstance(nid, int)

    rows = repo.query()
    assert len(rows) == 1
    assert rows[0]["alert_id"] == "a0"
    assert rows[0]["recipients"] == ["soc@example.com"]
    assert rows[0]["status"] == "sent"


def test_filters(session_factory):
    repo = NotificationRepository(session_factory)
    repo.add(make_result(0, channel="email", status="sent"))
    repo.add(make_result(1, channel="logfile", status="failed"))
    repo.add(make_result(2, channel="email", status="failed"))

    assert len(repo.query(channel="email")) == 2
    assert len(repo.query(status="failed")) == 2
    assert len(repo.query(channel="email", status="failed")) == 1
    assert len(repo.query(alert_id="a1")) == 1
    assert len(repo.query(incident_id="i2")) == 1


def test_count(session_factory):
    repo = NotificationRepository(session_factory)
    repo.add(make_result(0, channel="email", status="sent"))
    repo.add(make_result(1, channel="email", status="failed"))
    assert repo.count() == 2
    assert repo.count(channel="email") == 2
    assert repo.count(status="sent") == 1


def test_delete_older_than(session_factory):
    repo = NotificationRepository(session_factory)
    repo.add(make_result(0, created_at=T0 - timedelta(days=10)))
    repo.add(make_result(1, created_at=T0))
    removed = repo.delete_older_than(T0 - timedelta(days=1))
    assert removed == 1
    assert repo.count() == 1


def test_query_since(session_factory):
    repo = NotificationRepository(session_factory)
    repo.add(make_result(0, created_at=T0 - timedelta(days=5)))
    repo.add(make_result(1, created_at=T0))
    rows = repo.query(since=T0 - timedelta(days=1))
    assert len(rows) == 1
    assert rows[0]["alert_id"] == "a1"
