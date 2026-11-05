"""Tests for correlation-rule loading and the built-in chain definitions."""
from siem.engine.correlation_rules import (
    CorrelationRuleLoader,
    build_correlation_rule,
)
from siem.engine.rule_loader import RuleLoader
from pathlib import Path


def test_loads_builtin_correlation_rules():
    loader = CorrelationRuleLoader()
    rules = loader.load()
    assert loader.last_errors == []
    assert len(rules) >= 2
    titles = {r.title for r in rules}
    assert any("Multi-Stage" in t for t in titles)


def test_build_correlation_rule_parses_stages():
    rule = build_correlation_rule(
        Path("mem.yml"),
        {
            "type": "correlation",
            "title": "Chain",
            "stages": ["Discovery", "Credential_Access"],
            "escalate_to": "critical",
            "window": "10m",
        },
    )
    assert rule.stages == ["discovery", "credential_access"]
    assert rule.escalate_to == "critical"
    assert rule.window == 600


def test_correlation_files_skipped_by_detection_loader():
    """type: correlation files must not appear as detection rules."""
    loader = RuleLoader()
    rules = loader.load()
    assert loader.last_errors == []
    assert all(str(r.file_path).find("correlation") == -1 for r in rules)
