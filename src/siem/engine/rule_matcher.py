"""Stateless rule matching with Sigma field modifiers (FR-20, FR-21)."""
from __future__ import annotations

import fnmatch
import re
from typing import Any

from siem.engine import condition as cond
from siem.engine.models import Rule


def _split_modifiers(key: str) -> tuple[str, set[str]]:
    parts = key.split("|")
    return parts[0], {p.lower() for p in parts[1:]}


def _value_matches(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    cased = "cased" in modifiers

    if expected is None:
        return actual is None
    if actual is None:
        return False

    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        try:
            return re.search(str(expected), str(actual), flags) is not None
        except re.error:
            return False

    a = str(actual)
    e = str(expected)
    if not cased:
        a = a.lower()
        e = e.lower()

    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def match_field(flat: dict, key: str, value: Any) -> bool:
    field, modifiers = _split_modifiers(key)
    actual = flat.get(field)

    if isinstance(value, list):
        results = [_value_matches(actual, v, modifiers) for v in value]
        if "all" in modifiers:
            return all(results) if results else False
        return any(results)

    return _value_matches(actual, value, modifiers)


def match_selection(flat: dict, selection: Any) -> bool:
    """Match a single selection (dict = AND, list = OR)."""
    if isinstance(selection, list):
        for element in selection:
            if isinstance(element, dict) and match_selection(flat, element):
                return True
            if isinstance(element, str) and _value_matches(flat.get("message"), element, set()):
                return True
        return False

    if isinstance(selection, dict):
        if not selection:
            return False
        return all(match_field(flat, k, v) for k, v in selection.items())

    return False


def match_rule(rule: Rule, flat: dict) -> bool:
    """Evaluate all selections and the condition expression for a rule."""
    if rule.condition_ast is None:
        return False

    results = {
        name: match_selection(flat, selection)
        for name, selection in rule.selections.items()
    }
    return cond.evaluate(rule.condition_ast, results, list(rule.selections.keys()))
