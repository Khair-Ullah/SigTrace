"""Tests for rule validation."""
from siem.engine.rule_validator import validate_rule

VALID = {
    "title": "Test Rule",
    "logsource": {"category": "authentication"},
    "detection": {
        "selection": {"event_type": "failed_login"},
        "condition": "selection",
    },
    "level": "high",
}


def test_valid_rule():
    assert validate_rule(VALID) == []


def test_missing_title():
    data = {**VALID, "title": ""}
    assert any("title" in e for e in validate_rule(data))


def test_missing_detection():
    data = {"title": "X", "level": "low"}
    errors = validate_rule(data)
    assert any("detection" in e for e in errors)


def test_missing_condition():
    data = {"title": "X", "detection": {"selection": {"a": 1}}}
    assert any("condition" in e for e in validate_rule(data))


def test_unknown_selection_reference():
    data = {"title": "X", "detection": {"selection": {"a": 1}, "condition": "nope"}}
    assert any("unknown selection" in e for e in validate_rule(data))


def test_threshold_requires_timeframe():
    data = {
        "title": "X",
        "detection": {"selection": {"a": 1}, "condition": "selection", "threshold": 5},
    }
    assert any("timeframe" in e for e in validate_rule(data))


def test_timeframe_without_threshold():
    data = {
        "title": "X",
        "detection": {"selection": {"a": 1}, "condition": "selection", "timeframe": "60s"},
    }
    assert any("threshold" in e for e in validate_rule(data))


def test_invalid_level():
    data = {**VALID, "level": "super-critical"}
    assert any("level" in e for e in validate_rule(data))


def test_quantifier_pattern_must_match():
    data = {
        "title": "X",
        "detection": {"selection": {"a": 1}, "condition": "1 of missing_*"},
    }
    assert any("matches no selection" in e for e in validate_rule(data))
