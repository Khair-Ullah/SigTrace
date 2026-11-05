"""Shared builders for web tests."""
from __future__ import annotations

from siem.core.utils import utcnow
from siem.engine.models import Alert, Incident, Rule
from siem.parsing.models import NormalizedEvent


def make_alert(alert_id="a1", **kw) -> Alert:
    base = dict(
        alert_id=alert_id,
        rule_id=kw.pop("rule_id", "r1"),
        rule_name=kw.pop("rule_name", "Test Rule"),
        timestamp=kw.pop("timestamp", utcnow()),
        severity=kw.pop("severity", "high"),
        src_ip=kw.pop("src_ip", "1.2.3.4"),
        count=kw.pop("count", 3),
    )
    base.update(kw)
    return Alert(**base)


def make_incident(incident_id="INC-1", **kw) -> Incident:
    now = utcnow()
    base = dict(
        incident_id=incident_id,
        title=kw.pop("title", "Multi-Stage Intrusion"),
        severity=kw.pop("severity", "critical"),
        first_seen=kw.pop("first_seen", now),
        last_seen=kw.pop("last_seen", now),
        status=kw.pop("status", "open"),
        alert_count=kw.pop("alert_count", 2),
        src_ip=kw.pop("src_ip", "1.2.3.4"),
    )
    base.update(kw)
    return Incident(**base)


def make_event(event_id="e1", **kw) -> NormalizedEvent:
    base = dict(
        event_id=event_id,
        timestamp=kw.pop("timestamp", utcnow()),
        source_id=kw.pop("source_id", "s1"),
        source_type=kw.pop("source_type", "syslog"),
        raw_log=kw.pop("raw_log", "raw"),
        message=kw.pop("message", "hello world"),
        event_type=kw.pop("event_type", "failed_login"),
    )
    base.update(kw)
    return NormalizedEvent(**base)


def make_rule(rule_id="r1", **kw) -> Rule:
    base = dict(
        rule_id=rule_id,
        title=kw.pop("title", "Test Rule"),
        condition=kw.pop("condition", "selection"),
        selections=kw.pop("selections", {"selection": True}),
        detection=kw.pop("detection", {}),
        level=kw.pop("level", "high"),
        raw_yaml=kw.pop("raw_yaml", "title: Test Rule"),
        file_path=kw.pop("file_path", "rules/test.yml"),
    )
    base.update(kw)
    return Rule(**base)
