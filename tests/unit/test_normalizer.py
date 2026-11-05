"""Tests for the normalizer (severity, timestamps, field mapping)."""
from datetime import datetime, timezone

import pytest

from siem.ingestion.base import RawLogRecord
from siem.parsing.normalizer import coerce_severity, normalize, parse_timestamp


def _record(raw="raw line", source_id="s1", source_type="ssh"):
    return RawLogRecord(raw=raw, source_id=source_id, source_type=source_type)


@pytest.mark.parametrize("value,expected", [
    (None, "low"),
    ("critical", "critical"),
    ("ERROR", "high"),
    ("warning", "medium"),
    ("info", "low"),
    (2, "critical"),
    (3, "high"),
    (4, "medium"),
    (6, "low"),
    ("7", "low"),
    ("nonsense", "low"),
])
def test_coerce_severity(value, expected):
    assert coerce_severity(value) == expected


def test_parse_timestamp_iso_utc():
    dt = parse_timestamp("2026-10-16T14:32:11.123Z")
    assert dt == datetime(2026, 10, 16, 14, 32, 11, 123000)


def test_parse_timestamp_with_offset():
    dt = parse_timestamp("2026-10-16T14:32:11+05:00")
    assert dt == datetime(2026, 10, 16, 9, 32, 11)


def test_parse_timestamp_epoch():
    dt = parse_timestamp(0)
    assert dt == datetime(1970, 1, 1, 0, 0, 0)


def test_parse_timestamp_fallback_default():
    default = datetime(2020, 1, 1)
    assert parse_timestamp("not-a-date", default) == default


def test_normalize_maps_aliases_and_generates_uuid():
    fields = {
        "source_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "username": "admin",
        "level": "high",
        "event_type": "failed_login",
        "timestamp": "2026-10-16T14:32:11Z",
    }
    event = normalize(fields, _record())
    assert event.src_ip == "1.2.3.4"
    assert event.dst_ip == "5.6.7.8"
    assert event.user_name == "admin"
    assert event.severity == "high"
    assert event.event_type == "failed_login"
    assert event.timestamp == datetime(2026, 10, 16, 14, 32, 11)
    assert len(event.event_id) == 36  # UUID


def test_normalize_defaults_message_and_timestamp():
    event = normalize({}, _record(raw="hello world"))
    assert event.message == "hello world"
    assert event.severity == "low"
    assert event.timestamp is not None


def test_normalize_extra_fields_preserved():
    event = normalize({"host": "web-01", "pid": 42}, _record())
    assert event.extra == {"host": "web-01", "pid": 42}
