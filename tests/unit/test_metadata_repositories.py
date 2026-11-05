"""Tests for Rule, Config, Audit and State repositories."""
from datetime import datetime, timedelta
from pathlib import Path

from siem.engine.rule_loader import build_rule
from siem.storage.repositories import (
    AuditRepository,
    ConfigRepository,
    RuleRepository,
    StateRepository,
)

RAW = """
title: SSH Brute Force
id: rule-brute
level: high
detection:
  selection:
    event_type: failed_login
  condition: selection
"""

T0 = datetime(2026, 10, 17, 10, 0, 0)


def _rule():
    import yaml
    data = yaml.safe_load(RAW)
    return build_rule(Path("brute.yml"), data, RAW)


def test_rule_sync_insert_and_update(session_factory):
    repo = RuleRepository(session_factory)
    rule = _rule()
    assert repo.sync([rule]) == 1
    assert repo.count() == 1

    got = repo.get("rule-brute")
    assert got["title"] == "SSH Brute Force"
    assert got["level"] == "high"
    assert got["is_enabled"] is True

    rule.title = "SSH Brute Force v2"
    repo.sync([rule])
    assert repo.count() == 1
    assert repo.get("rule-brute")["title"] == "SSH Brute Force v2"


def test_rule_set_enabled(session_factory):
    repo = RuleRepository(session_factory)
    repo.sync([_rule()])
    assert repo.set_enabled("rule-brute", False) == 1
    assert repo.get("rule-brute")["is_enabled"] is False


def test_config_repository(session_factory):
    repo = ConfigRepository(session_factory)
    repo.set("foo", "bar")
    assert repo.get("foo") == "bar"
    assert repo.get("missing", "default") == "default"

    repo.set("threshold", 42)
    assert repo.get_int("threshold") == 42
    assert repo.get_int("missing", 7) == 7

    repo.set("foo", "baz")
    assert repo.get("foo") == "baz"
    assert repo.all()["foo"] == "baz"


def test_audit_repository(session_factory):
    repo = AuditRepository(session_factory)
    log_id = repo.record("login", details="admin logged in", user_id=1,
                         ip_address="10.0.0.9")
    assert log_id > 0
    recent = repo.recent()
    assert recent[0]["action"] == "login"
    assert recent[0]["ip_address"] == "10.0.0.9"


def test_state_repository(session_factory):
    repo = StateRepository(session_factory)
    repo.upsert("rule-brute", "1.2.3.4", T0, 3)
    repo.upsert("rule-brute", "1.2.3.4", T0, 5)   # update
    repo.upsert("rule-scan", "5.6.7.8", T0, 1)

    rows = repo.load_all()
    assert len(rows) == 2
    brute = next(r for r in rows if r["rule_id"] == "rule-brute")
    assert brute["event_count"] == 5

    assert repo.delete("rule-scan", "5.6.7.8") == 1
    assert repo.count() == 1
    assert repo.delete_older_than(T0 + timedelta(seconds=1)) == 1
