"""Automatic log format detection (FR-10)."""
from __future__ import annotations

import json

from siem.parsing import regex_patterns as rp
from siem.parsing.parsers import pfsense_parser

FORMAT_JSON = "json"
FORMAT_SYSLOG = "syslog"
FORMAT_CSV = "csv"
FORMAT_PLAINTEXT = "plaintext"

_ALL_FORMATS = {FORMAT_JSON, FORMAT_SYSLOG, FORMAT_CSV, FORMAT_PLAINTEXT}

# Accepted aliases for explicit format hints
_FORMAT_ALIASES = {
    "json": FORMAT_JSON,
    "syslog": FORMAT_SYSLOG,
    "csv": FORMAT_CSV,
    "text": FORMAT_PLAINTEXT,
    "plaintext": FORMAT_PLAINTEXT,
    "plain": FORMAT_PLAINTEXT,
    "log": FORMAT_PLAINTEXT,
}


def normalize_format_hint(hint: str | None) -> str | None:
    if not hint:
        return None
    return _FORMAT_ALIASES.get(hint.strip().lower())


def _looks_like_json(s: str) -> bool:
    if s[0] not in "{[":
        return False
    try:
        json.loads(s)
        return True
    except (ValueError, TypeError):
        return False


def _looks_like_csv(s: str) -> bool:
    # At least 3 comma-separated fields, stable field count is unknown for a
    # single line, so we use a conservative heuristic.
    if s.count(",") < 2:
        return False
    fields = s.split(",")
    if len(fields) < 3:
        return False
    # Reject if it clearly looks like a key=value log line
    if "=" in s and "," not in s.split("=")[0]:
        return False
    # Accept if at least one field is a bare token (no spaces) -> typical CSV
    non_empty = [f for f in fields if f.strip()]
    return len(non_empty) >= 3


def detect_format(raw: str, format_hint: str | None = None) -> str:
    """Return one of json/syslog/csv/plaintext for a raw log line."""
    hint = normalize_format_hint(format_hint)
    if hint in _ALL_FORMATS:
        return hint

    s = (raw or "").strip()
    if not s:
        return FORMAT_PLAINTEXT

    if _looks_like_json(s):
        return FORMAT_JSON
    if rp.SYSLOG_PRI.match(s):
        return FORMAT_SYSLOG
    # pfSense/OPNsense filterlog is comma-separated but not a generic CSV:
    # route it to the plaintext path so the dedicated parser runs.
    if pfsense_parser.is_filterlog(s):
        return FORMAT_PLAINTEXT
    if _looks_like_csv(s):
        return FORMAT_CSV
    return FORMAT_PLAINTEXT
