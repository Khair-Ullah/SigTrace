"""Tests for the agent Windows Event Log collector (parsing + cursor)."""
from __future__ import annotations

import json

from siem_agent.collector.windows_events import (
    WindowsEventCollector,
    _parse_wevtutil_xml,
)

SAMPLE_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Channel>Security</Channel>
    <Computer>HOST1.example.com</Computer>
    <EventRecordID>1001</EventRecordID>
    <TimeCreated SystemTime="2026-10-18T10:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
  <RenderingInfo xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <Message>An account failed to log on.</Message>
  </RenderingInfo>
</Event>
"""


def test_parse_wevtutil_xml_basic():
    events = _parse_wevtutil_xml(SAMPLE_XML)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_id"] == "4625"
    assert ev["provider"] == "Microsoft-Windows-Security-Auditing"
    assert ev["channel"] == "Security"
    assert ev["record_id"] == "1001"
    assert ev["timestamp"] == "2026-10-18T10:00:00.0000000Z"
    assert ev["user_name"] == "alice"
    assert ev["src_ip"] == "10.0.0.5"
    assert ev["message"] == "An account failed to log on."


def test_parse_wevtutil_xml_multiple_concatenated():
    raw = SAMPLE_XML + "\n" + SAMPLE_XML.replace("1001", "1002")
    events = _parse_wevtutil_xml(raw)
    assert [e["record_id"] for e in events] == ["1001", "1002"]


def test_parse_wevtutil_xml_empty():
    assert _parse_wevtutil_xml("") == []
    assert _parse_wevtutil_xml("   ") == []


def _collector(tmp_path, records, fail_on_emit=False):
    def emit(record: dict) -> bool:
        if fail_on_emit:
            return False
        records.append(record)
        return True

    return WindowsEventCollector(
        emit=emit,
        channels=["Security"],
        cursor_path=tmp_path / "winlog_cursor.json",
    )


def test_poll_channel_advances_cursor(tmp_path, monkeypatch):
    records: list[dict] = []
    collector = _collector(tmp_path, records)

    events = [
        {
            "record_id": "10",
            "event_id": "4624",
            "level": "0",
            "channel": "Security",
            "provider": "P",
            "message": "m1",
        },
        {
            "record_id": "11",
            "event_id": "4625",
            "level": "0",
            "channel": "Security",
            "provider": "P",
            "message": "m2",
        },
    ]
    monkeypatch.setattr(
        "siem_agent.collector.windows_events._parse_wevtutil_xml",
        lambda raw: list(events),
    )
    collector._wevtutil_query = lambda channel, count: "<xml/>"

    collector._poll_channel("Security")
    assert len(records) == 2
    assert collector._cursors["Security"] == 11
    payload = json.loads(records[0]["raw"])
    assert payload["windows_event_id"] == "4624"
    assert payload["event_type"] == "login_success"
    assert records[0]["format_hint"] == "json"
    assert records[0]["source_id"] == "winlog-security"

    # Cursor persisted.
    cursor = json.loads((tmp_path / "winlog_cursor.json").read_text(encoding="utf-8"))
    assert cursor["Security"] == 11

    # Polling again with same events ships nothing new.
    records.clear()
    collector._poll_channel("Security")
    assert records == []


def test_cursor_not_advanced_on_emit_failure(tmp_path, monkeypatch):
    records: list[dict] = []
    collector = _collector(tmp_path, records, fail_on_emit=True)

    events = [
        {
            "record_id": "5",
            "event_id": "1102",
            "level": "1",
            "channel": "Security",
            "provider": "P",
            "message": "cleared",
        },
    ]
    monkeypatch.setattr(
        "siem_agent.collector.windows_events._parse_wevtutil_xml",
        lambda raw: list(events),
    )
    collector._wevtutil_query = lambda channel, count: "<xml/>"

    collector._poll_channel("Security")
    assert records == []
    assert collector._cursors.get("Security") is None
    assert collector.stats["write_failures"] == 1
    assert not (tmp_path / "winlog_cursor.json").exists()


def test_cursor_reload_after_restart(tmp_path, monkeypatch):
    (tmp_path / "winlog_cursor.json").write_text(json.dumps({"Security": 100}), encoding="utf-8")

    records: list[dict] = []
    collector = _collector(tmp_path, records)
    assert collector._cursors["Security"] == 100

    events = [
        {
            "record_id": "101",
            "event_id": "4688",
            "level": "0",
            "channel": "Security",
            "provider": "P",
            "message": "proc",
        },
        {
            "record_id": "99",
            "event_id": "4688",
            "level": "0",
            "channel": "Security",
            "provider": "P",
            "message": "old",
        },
    ]
    monkeypatch.setattr(
        "siem_agent.collector.windows_events._parse_wevtutil_xml",
        lambda raw: list(events),
    )
    collector._wevtutil_query = lambda channel, count: "<xml/>"

    collector._poll_channel("Security")
    assert len(records) == 1  # only record_id 101
    assert collector._cursors["Security"] == 101


def test_events_sorted_by_record_id(tmp_path, monkeypatch):
    records: list[dict] = []
    collector = _collector(tmp_path, records)
    events = [
        {"record_id": "20", "event_id": "1", "channel": "Security"},
        {"record_id": "18", "event_id": "2", "channel": "Security"},
        {"record_id": "19", "event_id": "3", "channel": "Security"},
    ]
    monkeypatch.setattr(
        "siem_agent.collector.windows_events._parse_wevtutil_xml",
        lambda raw: list(events),
    )
    collector._wevtutil_query = lambda channel, count: "<xml/>"

    collector._poll_channel("Security")
    ids = [json.loads(r["raw"])["record_id"] for r in records]
    assert ids == ["18", "19", "20"]
