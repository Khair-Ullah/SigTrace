"""Tests for the rule engine orchestrator."""
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import build_rule
from siem.parsing.models import NormalizedEvent


def make_rule(yaml_str: str):
    data = yaml.safe_load(yaml_str)
    return build_rule(Path("mem.yml"), data, yaml_str)


def make_event(ts=None, **kw) -> NormalizedEvent:
    base = dict(
        event_id=kw.pop("event_id", "e1"),
        timestamp=ts or datetime(2026, 10, 17, 10, 0, 0),
        source_id="src",
        source_type=kw.pop("source_type", "ssh"),
        raw_log=kw.pop("raw_log", "raw"),
    )
    base.update(kw)
    return NormalizedEvent(**base)


def test_stateless_rule_fires():
    rule = make_rule("""
title: Root Login
detection:
  selection:
    event_type: successful_login
    user_name: root
  condition: selection
level: medium
""")
    engine = RuleEngine([rule])
    alerts = engine.evaluate(make_event(event_type="successful_login", user_name="root",
                                        src_ip="1.2.3.4"))
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Root Login"
    assert alerts[0].severity == "medium"
    assert alerts[0].src_ip == "1.2.3.4"


def test_stateless_rule_no_match():
    rule = make_rule("""
title: Root Login
detection:
  selection:
    user_name: root
  condition: selection
""")
    engine = RuleEngine([rule])
    assert engine.evaluate(make_event(user_name="alice")) == []


def test_stateful_threshold_fires_once():
    rule = make_rule("""
title: SSH Brute Force
detection:
  selection:
    event_type: failed_login
  condition: selection
  timeframe: 60s
  threshold: 5
  group-by:
    - src_ip
level: high
""")
    engine = RuleEngine([rule])
    t0 = datetime(2026, 10, 17, 10, 0, 0)

    for i in range(4):
        alerts = engine.evaluate(make_event(
            ts=t0 + timedelta(seconds=i), event_type="failed_login", src_ip="9.9.9.9"))
        assert alerts == []

    # 5th event crosses the threshold
    alerts = engine.evaluate(make_event(
        ts=t0 + timedelta(seconds=4), event_type="failed_login", src_ip="9.9.9.9"))
    assert len(alerts) == 1
    assert alerts[0].count == 5

    # after firing, the bucket is reset -> no immediate re-fire
    alerts = engine.evaluate(make_event(
        ts=t0 + timedelta(seconds=5), event_type="failed_login", src_ip="9.9.9.9"))
    assert alerts == []


def test_stateful_groups_are_independent():
    rule = make_rule("""
title: Brute Force
detection:
  selection:
    event_type: failed_login
  condition: selection
  timeframe: 60s
  threshold: 3
  group-by: [src_ip]
level: high
""")
    engine = RuleEngine([rule])
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    total = 0
    for ip in ("1.1.1.1", "2.2.2.2"):
        for i in range(3):
            total += len(engine.evaluate(make_event(
                ts=t0 + timedelta(seconds=i), event_type="failed_login", src_ip=ip)))
    assert total == 2  # one alert per group


def test_engine_stats():
    rule = make_rule("""
title: r
detection:
  selection:
    event_type: x
  condition: selection
""")
    engine = RuleEngine([rule])
    engine.evaluate(make_event(event_type="x"))
    engine.evaluate(make_event(event_type="y"))
    assert engine.stats["events_evaluated"] == 2
    assert engine.stats["rule_matches"] == 1
    assert engine.stats["alerts_generated"] == 1
