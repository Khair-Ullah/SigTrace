"""Tests for EventRepository."""
from datetime import datetime, timedelta

from siem.parsing.models import NormalizedEvent
from siem.storage.repositories import EventRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)


def ev(i=0, **kw):
    base = dict(
        event_id=f"e{i}",
        timestamp=T0 + timedelta(seconds=i),
        source_id="src-1",
        source_type="ssh",
        raw_log=f"raw {i}",
        event_type="failed_login",
        severity="medium",
        src_ip="10.0.0.1",
    )
    base.update(kw)
    return NormalizedEvent(**base)


def test_add_and_get(session_factory):
    repo = EventRepository(session_factory)
    repo.add(ev(0))
    got = repo.get("e0")
    assert got is not None
    assert got.event_id == "e0"
    assert got.event_type == "failed_login"
    assert got.src_ip == "10.0.0.1"


def test_add_many_and_count(session_factory):
    repo = EventRepository(session_factory)
    assert repo.add_many([ev(i) for i in range(5)]) == 5
    assert repo.count() == 5


def test_add_many_ignores_duplicates(session_factory):
    repo = EventRepository(session_factory)
    repo.add_many([ev(0), ev(1)])
    repo.add_many([ev(0), ev(1)])  # duplicate ids
    assert repo.count() == 2


def test_query_filters(session_factory):
    repo = EventRepository(session_factory)
    repo.add_many([
        ev(0, event_type="failed_login", src_ip="1.1.1.1"),
        ev(1, event_type="web_access", src_ip="2.2.2.2"),
        ev(2, event_type="failed_login", src_ip="1.1.1.1", severity="high"),
    ])
    assert repo.count(event_type="failed_login") == 2
    assert repo.count(src_ip="2.2.2.2") == 1
    assert len(repo.query(event_type="failed_login", src_ip="1.1.1.1")) == 2
    assert len(repo.query(severity="high")) == 1


def test_query_time_range_and_order(session_factory):
    repo = EventRepository(session_factory)
    repo.add_many([ev(i) for i in range(10)])
    rows = repo.query(start=T0 + timedelta(seconds=3),
                      end=T0 + timedelta(seconds=6), order_desc=False)
    assert [r.event_id for r in rows] == ["e3", "e4", "e5", "e6"]


def test_message_search(session_factory):
    repo = EventRepository(session_factory)
    repo.add(ev(0, message="UNION SELECT password"))
    repo.add(ev(1, message="normal request"))
    assert len(repo.query(message_contains="union select")) == 1


def test_delete_older_than(session_factory):
    repo = EventRepository(session_factory)
    repo.add_many([ev(i) for i in range(10)])
    removed = repo.delete_older_than(T0 + timedelta(seconds=5))
    assert removed == 5
    assert repo.count() == 5
