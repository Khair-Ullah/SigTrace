"""Tests for the sliding-window state manager."""
from datetime import datetime, timedelta

from siem.engine.state_manager import StateManager


def test_increment_within_window():
    sm = StateManager()
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    for i in range(3):
        count, ids = sm.increment("r1", "1.2.3.4", t0 + timedelta(seconds=i), 60, f"e{i}")
    assert count == 3
    assert ids == ["e0", "e1", "e2"]


def test_old_entries_pruned():
    sm = StateManager()
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    sm.increment("r1", "1.2.3.4", t0, 60, "a")
    # 90 seconds later the first entry falls outside the 60s window
    count, ids = sm.increment("r1", "1.2.3.4", t0 + timedelta(seconds=90), 60, "b")
    assert count == 1
    assert ids == ["b"]


def test_group_isolation():
    sm = StateManager()
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    sm.increment("r1", "1.1.1.1", t0, 60, "a")
    c1, _ = sm.increment("r1", "1.1.1.1", t0, 60, "b")
    c2, _ = sm.increment("r1", "2.2.2.2", t0, 60, "c")
    assert c1 == 2
    assert c2 == 1


def test_reset():
    sm = StateManager()
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    sm.increment("r1", "x", t0, 60, "a")
    sm.reset("r1", "x")
    assert sm.count("r1", "x") == 0


def test_prune_all():
    sm = StateManager()
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    sm.increment("r1", "x", t0, 60, "a")
    removed = sm.prune(t0 + timedelta(seconds=600), max_window_seconds=300)
    assert removed == 1
    assert sm.bucket_count == 0
