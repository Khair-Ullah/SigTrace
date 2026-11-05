"""Integration test: load builtin rules and detect simulated attacks."""
from datetime import datetime, timedelta

from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.parsing.models import NormalizedEvent


def _ev(ts, **kw) -> NormalizedEvent:
    base = dict(
        event_id=kw.pop("event_id", f"e-{ts.timestamp()}"),
        timestamp=ts,
        source_id="test",
        source_type=kw.pop("source_type", "custom"),
        raw_log=kw.pop("raw_log", ""),
    )
    base.update(kw)
    return NormalizedEvent(**base)


def test_builtin_rules_load_cleanly():
    loader = RuleLoader()
    rules = loader.load()
    assert len(rules) >= 9, f"expected >=9 builtin rules, got {len(rules)}"
    assert loader.last_errors == [], loader.last_errors


def test_ssh_bruteforce_detected():
    engine = RuleEngine(RuleLoader().load())
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    alerts = []
    for i in range(5):
        alerts += engine.evaluate(_ev(
            t0 + timedelta(seconds=i), event_type="failed_login",
            src_ip="203.0.113.9", user_name="admin", source_type="ssh"))
    assert any("Brute Force" in a.rule_name for a in alerts)


def test_sql_injection_detected():
    engine = RuleEngine(RuleLoader().load())
    alerts = engine.evaluate(_ev(
        datetime(2026, 10, 17, 10, 0, 0), event_type="web_access",
        message='GET /x?id=1 UNION SELECT password FROM users', src_ip="1.2.3.4"))
    assert any("Web Exploit" in a.rule_name for a in alerts)


def test_port_scan_detected():
    engine = RuleEngine(RuleLoader().load())
    t0 = datetime(2026, 10, 17, 10, 0, 0)
    alerts = []
    for i in range(20):
        alerts += engine.evaluate(_ev(
            t0 + timedelta(seconds=i * 0.1), event_type="firewall_deny",
            src_ip="10.0.0.66", dst_ip="10.0.0.1", dst_port=i, source_type="firewall"))
    assert any("Port Scan" in a.rule_name for a in alerts)


def test_root_login_detected():
    engine = RuleEngine(RuleLoader().load())
    alerts = engine.evaluate(_ev(
        datetime(2026, 10, 17, 10, 0, 0), event_type="successful_login",
        user_name="root", src_ip="1.2.3.4"))
    assert any("Root" in a.rule_name for a in alerts)
