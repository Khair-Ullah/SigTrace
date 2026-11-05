"""Detection condition expression parser and evaluator.

Supports Sigma-style conditions:
  - selection names:            selection
  - boolean operators:          selection1 and not filter1
  - parentheses:                (a or b) and not c
  - quantifiers:                1 of selection*, all of them, 2 of filter*
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


class ConditionError(ValueError):
    """Raised when a condition expression cannot be parsed."""


def tokenize(condition: str) -> list[str]:
    return _TOKEN_RE.findall(condition or "")


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def next(self) -> str:
        if self.i >= len(self.tokens):
            raise ConditionError("unexpected end of condition")
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Any:
        node = self._parse_or()
        if self.i != len(self.tokens):
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while (self.peek() or "").lower() == "or":
            self.next()
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_not()
        while (self.peek() or "").lower() == "and":
            self.next()
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self) -> Any:
        if (self.peek() or "").lower() == "not":
            self.next()
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        tok = self.peek()
        if tok == "(":
            self.next()
            node = self._parse_or()
            if self.peek() != ")":
                raise ConditionError("missing closing parenthesis")
            self.next()
            return node

        # quantifier: <count> of <pattern>   (count = number or 'all')
        if tok is not None and (tok.isdigit() or tok.lower() == "all"):
            if self.i + 1 < len(self.tokens) and self.tokens[self.i + 1].lower() == "of":
                count = tok.lower()
                self.next()  # count
                self.next()  # of
                pattern = self.next()
                pattern = pattern.lower() if pattern.lower() in ("them",) else pattern
                return ("quant", count, pattern)

        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.next()
        return ("ref", tok)


def parse(condition: str) -> Any:
    """Parse a condition string into an AST."""
    tokens = tokenize(condition)
    if not tokens:
        raise ConditionError("empty condition")
    return _Parser(tokens).parse()


def evaluate(node: Any, results: dict[str, bool], names: list[str]) -> bool:
    """Evaluate an AST against selection results."""
    kind = node[0]
    if kind == "ref":
        return bool(results.get(node[1], False))
    if kind == "and":
        return evaluate(node[1], results, names) and evaluate(node[2], results, names)
    if kind == "or":
        return evaluate(node[1], results, names) or evaluate(node[2], results, names)
    if kind == "not":
        return not evaluate(node[1], results, names)
    if kind == "quant":
        _, count, pattern = node
        if pattern == "them":
            matched = list(names)
        else:
            matched = [n for n in names if fnmatch.fnmatchcase(n.lower(), pattern.lower())]
        if not matched:
            return False
        values = [bool(results.get(n, False)) for n in matched]
        if count == "all":
            return all(values)
        try:
            required = int(count)
        except ValueError:
            return False
        return sum(1 for v in values if v) >= required
    raise ConditionError(f"unknown node type {kind!r}")


def referenced_names(node: Any) -> tuple[set[str], list[str]]:
    """Return (explicit selection refs, quantifier patterns) from an AST."""
    refs: set[str] = set()
    patterns: list[str] = []

    def walk(n: Any) -> None:
        kind = n[0]
        if kind == "ref":
            refs.add(n[1])
        elif kind in ("and", "or"):
            walk(n[1])
            walk(n[2])
        elif kind == "not":
            walk(n[1])
        elif kind == "quant":
            if n[2] != "them":
                patterns.append(n[2])

    walk(node)
    return refs, patterns
