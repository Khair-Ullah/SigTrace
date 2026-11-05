"""Tests for syslog RFC 3164 / RFC 5424 parsers."""
from siem.parsing.parsers import syslog_parser


def test_rfc3164_with_tag():
    raw = "<134>Oct 16 14:32:11 webhost sshd[123]: Failed password for admin from 1.2.3.4"
    fields = syslog_parser.parse(raw)
    assert fields["host"] == "webhost"
    assert fields["app"] == "sshd"
    assert fields["procid"] == "123"
    assert fields["message"].startswith("Failed password")
    assert fields["syslog_facility"] == 16   # local0
    assert fields["syslog_severity"] == 6    # info
    assert fields["severity"] == "low"


def test_rfc3164_severity_critical():
    raw = "<34>Oct 16 14:32:11 host kernel: disk failure"
    fields = syslog_parser.parse(raw)
    assert fields["severity"] == "critical"  # severity 2


def test_rfc5424():
    raw = "<34>1 2026-10-16T14:32:11.123Z mymachine su 1234 ID47 - BOM message"
    fields = syslog_parser.parse(raw)
    assert fields["host"] == "mymachine"
    assert fields["app"] == "su"
    assert fields["msgid"] == "ID47"
    assert fields["message"] == "BOM message"
    assert fields["severity"] == "critical"


def test_not_syslog_returns_none():
    assert syslog_parser.parse("just a plain line") is None
