"""Tests for the rule loader (discovery, validation, build)."""
from siem.core.config import Config
from siem.engine.rule_loader import RuleLoader

GOOD_RULE = """
title: Good Rule
id: 11111111-1111-1111-1111-111111111111
logsource:
  category: test
detection:
  selection:
    event_type: failed_login
  condition: selection
level: high
"""

BAD_RULE = """
title: Bad Rule
detection:
  condition: selection
"""


def _config(tmp_path, builtin: str, custom: str) -> Config:
    return Config(
        {"rules": {"builtin_path": builtin, "custom_path": custom}},
        project_root=tmp_path,
    )


def test_loads_valid_and_skips_invalid(tmp_path):
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    (builtin / "good.yml").write_text(GOOD_RULE, encoding="utf-8")
    (builtin / "bad.yml").write_text(BAD_RULE, encoding="utf-8")

    loader = RuleLoader(_config(tmp_path, str(builtin), str(tmp_path / "custom")))
    rules = loader.load()

    assert len(rules) == 1
    assert rules[0].title == "Good Rule"
    assert rules[0].level == "high"
    assert loader.last_errors  # bad rule recorded an error


def test_empty_directory_returns_no_rules(tmp_path):
    loader = RuleLoader(_config(tmp_path, str(tmp_path / "b"), str(tmp_path / "c")))
    assert loader.load() == []
    assert loader.last_errors == []


def test_stateful_fields_parsed(tmp_path):
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    (builtin / "threshold.yml").write_text("""
title: Threshold Rule
detection:
  selection:
    event_type: failed_login
  condition: selection
  timeframe: 60s
  threshold: 5
  group-by:
    - src_ip
level: high
""", encoding="utf-8")

    loader = RuleLoader(_config(tmp_path, str(builtin), str(tmp_path / "c")))
    rules = loader.load()
    assert rules[0].timeframe == 60
    assert rules[0].threshold == 5
    assert rules[0].group_by == ["src_ip"]
    assert rules[0].is_stateful is True
