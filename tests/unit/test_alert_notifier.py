"""Tests for the AlertNotifier manager (FR-47..FR-52)."""
from datetime import datetime, timedelta
from pathlib import Path

from siem.alerting.manager import AlertNotifier
from siem.alerting.notification import (
    STATUS_DUPLICATE,
    STATUS_RATE_LIMITED,
    STATUS_SENT,
)
from siem.alerting.notifiers import CallbackNotifier
from siem.core.config import Config
from siem.engine.models import Alert
from siem.storage.repositories import NotificationRepository

T0 = datetime(2026, 10, 17, 10, 0, 0)


def al(i=0, severity="high", src_ip="1.2.3.4", **kw):
    base = dict(alert_id=f"a{i}", rule_id="r1", rule_name="Brute Force",
                timestamp=T0, severity=severity, src_ip=src_ip, count=5)
    base.update(kw)
    return Alert(**base)


def make_config(**alerting):
    base = {
        "rate_limit": {"max_per_minute": 60},
        "dedup_window_seconds": 300,
    }
    base.update(alerting)
    return Config({"alerting": base}, project_root=Path("."))


def collector():
    seen = []
    return seen, CallbackNotifier([lambda a, i: seen.append(a.alert_id)], min_severity="low")


def test_dispatches_to_channels():
    seen, cb = collector()
    mgr = AlertNotifier(make_config(), notifiers=[cb])
    results = mgr.notify(al())
    assert results[0].status == STATUS_SENT
    assert seen == ["a0"]


def test_severity_filter_skips():
    seen, cb = collector()
    cb.min_severity = "high"
    mgr = AlertNotifier(make_config(), notifiers=[cb])
    results = mgr.notify(al(severity="low"))
    assert results[0].status == "skipped"
    assert seen == []


def test_dedup_within_window():
    seen, cb = collector()
    mgr = AlertNotifier(make_config(dedup_window_seconds=300), notifiers=[cb])
    mgr.notify(al(), now=T0)
    results = mgr.notify(al(), now=T0 + timedelta(seconds=30))
    assert results[0].status == STATUS_DUPLICATE
    assert seen == ["a0"]  # not delivered again


def test_dedup_expires():
    seen, cb = collector()
    mgr = AlertNotifier(make_config(dedup_window_seconds=60), notifiers=[cb])
    mgr.notify(al(), now=T0)
    mgr.notify(al(), now=T0 + timedelta(seconds=120))
    assert seen == ["a0", "a0"]


def test_dedup_key_includes_identity():
    seen, cb = collector()
    mgr = AlertNotifier(make_config(), notifiers=[cb])
    mgr.notify(al(src_ip="1.1.1.1"), now=T0)
    mgr.notify(al(src_ip="2.2.2.2"), now=T0)  # different source
    assert len(seen) == 2


def test_rate_limit():
    seen, cb = collector()
    mgr = AlertNotifier(make_config(rate_limit={"max_per_minute": 2}), notifiers=[cb])
    assert mgr.notify(al(0, src_ip="1.1.1.1"), now=T0)[0].status == STATUS_SENT
    assert mgr.notify(al(1, src_ip="2.2.2.2"), now=T0)[0].status == STATUS_SENT
    result = mgr.notify(al(2, src_ip="3.3.3.3"), now=T0)[0]
    assert result.status == STATUS_RATE_LIMITED
    assert len(seen) == 2


def test_results_persisted(session_factory):
    repo = NotificationRepository(session_factory)
    _, cb = collector()
    mgr = AlertNotifier(make_config(), notifiers=[cb], notification_repo=repo)
    mgr.notify(al(0), now=T0)
    mgr.notify(al(0), now=T0 + timedelta(seconds=1))  # duplicate (not recorded)

    rows = repo.query()
    assert repo.count() == 1
    assert rows[0]["channel"] == "callback"
    assert rows[0]["status"] == STATUS_SENT


def test_stats():
    _, cb = collector()
    mgr = AlertNotifier(make_config(), notifiers=[cb])
    mgr.notify(al(0))
    mgr.notify(al(0))  # duplicate
    assert mgr.stats["notifications"] == 2
    assert mgr.stats["sent"] == 1
    assert mgr.stats["duplicates"] == 1
