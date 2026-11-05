"""Tests for the stateless rule matcher."""
from pathlib import Path

import yaml

from siem.engine.rule_loader import build_rule
from siem.engine.rule_matcher import match_rule


def make_rule(yaml_str: str):
    data = yaml.safe_load(yaml_str)
    return build_rule(Path("mem.yml"), data, yaml_str)


def test_exact_match():
    rule = make_rule("""
title: r
detection:
  selection:
    event_type: failed_login
  condition: selection
""")
    assert match_rule(rule, {"event_type": "failed_login"}) is True
    assert match_rule(rule, {"event_type": "successful_login"}) is False


def test_case_insensitive_default():
    rule = make_rule("""
title: r
detection:
  selection:
    event_type: FAILED_LOGIN
  condition: selection
""")
    assert match_rule(rule, {"event_type": "failed_login"}) is True


def test_wildcard():
    rule = make_rule("""
title: r
detection:
  selection:
    event_type: 'failed_*'
  condition: selection
""")
    assert match_rule(rule, {"event_type": "failed_login"}) is True
    assert match_rule(rule, {"event_type": "success_login"}) is False


def test_list_is_or():
    rule = make_rule("""
title: r
detection:
  selection:
    dst_port:
      - 22
      - 3389
  condition: selection
""")
    assert match_rule(rule, {"dst_port": 22}) is True
    assert match_rule(rule, {"dst_port": 3389}) is True
    assert match_rule(rule, {"dst_port": 80}) is False


def test_contains_startswith_endswith():
    rule = make_rule("""
title: r
detection:
  sel_contains:
    message|contains: 'union select'
  sel_start:
    action|startswith: '/admin'
  sel_end:
    action|endswith: '.php'
  condition: sel_contains or sel_start or sel_end
""")
    assert match_rule(rule, {"message": "GET x UNION SELECT y"}) is True
    assert match_rule(rule, {"action": "/admin/login"}) is True
    assert match_rule(rule, {"action": "index.php"}) is True
    assert match_rule(rule, {"message": "clean", "action": "/home"}) is False


def test_regex_modifier():
    rule = make_rule("""
title: r
detection:
  selection:
    src_ip|re: '^10\\.0\\.0\\.'
  condition: selection
""")
    assert match_rule(rule, {"src_ip": "10.0.0.5"}) is True
    assert match_rule(rule, {"src_ip": "192.168.1.1"}) is False


def test_condition_and_not():
    rule = make_rule("""
title: r
detection:
  selection:
    event_type: web_access
  filter:
    http_status: 200
  condition: selection and not filter
""")
    assert match_rule(rule, {"event_type": "web_access", "http_status": 404}) is True
    assert match_rule(rule, {"event_type": "web_access", "http_status": 200}) is False


def test_quantifier_one_of():
    rule = make_rule("""
title: r
detection:
  selection_a:
    event_type: x
  selection_b:
    event_type: y
  condition: 1 of selection_*
""")
    assert match_rule(rule, {"event_type": "y"}) is True
    assert match_rule(rule, {"event_type": "z"}) is False
