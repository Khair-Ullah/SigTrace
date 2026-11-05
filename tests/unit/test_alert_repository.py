"""Tests for AlertRepository."""
from datetime import datetime, timedelta

from siem.engine.models import Alert
from siem.storage.repositories import AlertRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)


def al(i=0, **kw):
    base = dict(
        alert_id=f"a{i}",
        rule_id="rule-1",
        rule_name="Brute Force",
        timestamp=T0 + timedelta(seconds=i),
        severity="high",
        src_ip="10.0.0.1",
        event_ids=[f"e{i}"],
        count=5,
        description="desc",
        rule_tags=["attack.credential_access"],
    )
    base.update(kw)
    return Alert(**base)


def test_add_and_get_roundtrip(session_factory):
    repo = AlertRepository(session_factory)
    repo.add(al(0))
    got = repo.get("a0")
    assert got.alert_id == "a0"
    assert got.count == 5
    assert got.event_ids == ["e0"]
    assert got.rule_tags == ["attack.credential_access"]
    assert got.description == "desc"


def test_add_many_and_count(session_factory):
    repo = AlertRepository(session_factory)
    assert repo.add_many([al(i) for i in range(4)]) == 4
    assert repo.count() == 4


def test_query_by_severity_and_src(session_factory):
    repo = AlertRepository(session_factory)
    repo.add_many([
        al(0, severity="high", src_ip="1.1.1.1"),
        al(1, severity="critical", src_ip="1.1.1.1"),
        al(2, severity="low", src_ip="2.2.2.2"),
    ])
    assert repo.count(severity="high") == 1
    assert repo.count(src_ip="1.1.1.1") == 2
    assert len(repo.query(severity="critical")) == 1


def test_set_incident_and_link(session_factory):
    repo = AlertRepository(session_factory)
    repo.add_many([al(0), al(1), al(2)])
    assert repo.set_incident("a0", "INC-1") == 1
    assert repo.link_incident(["a1", "a2"], "INC-1") == 2
    assert repo.count(incident_id="INC-1") == 3
    assert repo.get("a0").incident_id == "INC-1"


def test_acknowledge(session_factory):
    repo = AlertRepository(session_factory)
    repo.add(al(0))
    assert repo.get("a0").acknowledged is False
    repo.acknowledge("a0")
    assert repo.get("a0").acknowledged is True
    assert repo.count(acknowledged=True) == 1


def test_delete_older_than(session_factory):
    repo = AlertRepository(session_factory)
    repo.add_many([al(i) for i in range(6)])
    removed = repo.delete_older_than(T0 + timedelta(seconds=3))
    assert removed == 3
