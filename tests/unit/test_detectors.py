"""Tests for log format detection."""
import pytest

from siem.parsing.detectors import detect_format


@pytest.mark.parametrize("raw,expected", [
    ('{"src_ip": "1.2.3.4", "action": "login"}', "json"),
    ('<134>Oct 16 14:32:11 host sshd[1]: hello', "syslog"),
    ('<34>1 2026-10-16T14:32:11Z host app - - - hi', "syslog"),
    ("1.2.3.4,admin,login,success", "csv"),
    ("Denied TCP connection from 1.2.3.4 to 5.6.7.8:22", "plaintext"),
    ("plain message with no structure", "plaintext"),
    ("", "plaintext"),
])
def test_detect_format(raw, expected):
    assert detect_format(raw) == expected


def test_format_hint_overrides():
    assert detect_format("anything", format_hint="json") == "json"
    assert detect_format("anything", format_hint="CSV") == "csv"
    assert detect_format("anything", format_hint="plain") == "plaintext"
