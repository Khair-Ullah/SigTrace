"""Tests for the condition expression parser/evaluator."""
import pytest

from siem.engine import condition as cond


def _eval(expr, results, names=None):
    names = names or list(results.keys())
    ast = cond.parse(expr)
    return cond.evaluate(ast, results, names)


def test_single_ref():
    assert _eval("selection", {"selection": True}) is True
    assert _eval("selection", {"selection": False}) is False


def test_and_or_not():
    r = {"a": True, "b": False}
    assert _eval("a and b", r) is False
    assert _eval("a or b", r) is True
    assert _eval("not b", r) is True
    assert _eval("a and not b", r) is True


def test_parentheses():
    r = {"a": True, "b": False, "c": True}
    assert _eval("(a or b) and c", r) is True
    assert _eval("a and (b or c)", r) is True
    assert _eval("(a and b) or c", r) is True


def test_one_of_wildcard():
    r = {"selection_1": False, "selection_2": True, "filter": False}
    assert _eval("1 of selection_*", r) is True
    assert _eval("all of selection_*", r) is False


def test_all_of_them():
    r = {"a": True, "b": True, "c": True}
    assert _eval("all of them", r) is True
    r2 = {"a": True, "b": False}
    assert _eval("all of them", r2) is False


def test_n_of():
    r = {"s1": True, "s2": True, "s3": False}
    assert _eval("2 of s*", r) is True
    assert _eval("3 of s*", r) is False


def test_invalid_condition_raises():
    with pytest.raises(cond.ConditionError):
        cond.parse("a and")
    with pytest.raises(cond.ConditionError):
        cond.parse("(a or b")


def test_referenced_names():
    ast = cond.parse("selection and not filter and 1 of extra_*")
    refs, patterns = cond.referenced_names(ast)
    assert refs == {"selection", "filter"}
    assert patterns == ["extra_*"]
