"""Tests for the interactive local-log Monitor (Phase 10)."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from siem.core.config import Config
from siem.monitoring.collectors import (
    FileSourceCollector,
    WindowsEventLogCollector,
    _parse_wevtutil_xml,
)
from siem.monitoring.system_monitor import SystemMonitor

SAMPLE_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-01-02T03:04:05.0000000Z"/>
    <EventRecordID>1001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>HOST01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">203.0.113.5</Data>
  </EventData>
  <RenderingInfo><Message>An account failed to log on.</Message></RenderingInfo>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7036</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-01-02T03:04:06.0000000Z"/>
    <EventRecordID>1002</EventRecordID>
    <Channel>System</Channel>
    <Computer>HOST01</Computer>
  </System>
</Event>
""".strip()


def _config(tmp_path: Path, monitoring: dict | None = None) -> Config:
    data = {
        "system": {"name": "test"},
        "rules": {"builtin_path": "rules/builtin", "custom_path": "rules/custom"},
    }
    if monitoring is not None:
        data["monitoring"] = monitoring
    return Config(data, project_root=tmp_path)


# -- collectors ------------------------------------------------------------

def test_parse_wevtutil_xml_fields():
    events = _parse_wevtutil_xml(SAMPLE_XML)
    assert len(events) == 2
    first = events[0]
    assert first["event_id"] == "4625"
    assert first["level"] == "2"
    assert first["channel"] == "Security"
    assert first["record_id"] == "1001"
    assert first["user_name"] == "alice"
    assert first["src_ip"] == "203.0.113.5"
    assert "failed to log on" in first["message"]


def test_windows_collector_maps_event_type_and_severity():
    collector = WindowsEventLogCollector(["Security"])
    events = _parse_wevtutil_xml(SAMPLE_XML)
    rec = collector._to_record(events[0])
    assert rec is not None
    assert rec.event_type == "failed_login"
    assert rec.severity == "high"
    assert rec.source_id == "winlog-security"
    assert "alice" in rec.summary
    assert '"event_type": "failed_login"' in rec.raw


def test_windows_collector_generic_event():
    collector = WindowsEventLogCollector(["System"])
    events = _parse_wevtutil_xml(SAMPLE_XML)
    rec = collector._to_record(events[1])
    assert rec is not None
    assert rec.event_type == "windows_event"
    assert rec.severity == "low"


def test_file_collector_tails_new_lines(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("pre-existing line\n")
    collector = FileSourceCollector(
        [{"path": str(log_file), "source_id": "app", "source_type": "app"}],
        read_from_beginning=False,
    )
    assert collector.poll() == []  # baseline on first poll

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("new line one\nnew line two\n")
    records = collector.poll()
    assert [r.raw for r in records] == ["new line one", "new line two"]
    assert records[0].source_id == "app"


def test_file_collector_read_from_beginning(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("line a\nline b\n")
    collector = FileSourceCollector(
        [{"path": str(log_file)}], read_from_beginning=True,
    )
    records = collector.poll()
    assert len(records) == 2


# -- SystemMonitor ---------------------------------------------------------

class _StubCollector:
    source_type = "stub"

    def __init__(self, records):
        self._records = records

    def poll(self):
        out, self._records = self._records, []
        return out

    def status(self):
        return {"name": "stub", "type": "stub", "collected": 0, "last_error": None}


class _StubPipeline:
    def __init__(self, alert_ids):
        self._alert_ids = alert_ids

    def process_raw(self, raw, source_id="manual", source_type="custom"):
        return [SimpleNamespace(alert=SimpleNamespace(alert_id=a), incident=None)
                for a in self._alert_ids]


def test_monitor_status_defaults(tmp_path):
    monitor = SystemMonitor(_config(tmp_path), storage=None)
    status = monitor.status()
    assert status["running"] is False
    assert status["processed"] == 0
    assert status["alerts"] == 0
    assert status["sources"] == []
    assert status["interval_seconds"] == 5


def test_monitor_builds_collectors_from_config(tmp_path):
    monitor = SystemMonitor(
        _config(tmp_path, {"windows_event_logs": ["System", "Application"]}),
        storage=None,
    )
    assert len(monitor.collectors) == 1
    assert monitor.collectors[0].source_type == "windows_event"


def test_monitor_poll_once_processes_and_counts(tmp_path):
    from siem.monitoring.collectors import MonitorRecord

    monitor = SystemMonitor(_config(tmp_path), storage=None)
    monitor.collectors = [
        _StubCollector([
            MonitorRecord(raw="a", source_id="s", source_type="stub"),
            MonitorRecord(raw="b", source_id="s", source_type="stub"),
        ])
    ]
    monitor._pipeline = _StubPipeline(["AL-1"])

    seen = []
    monitor.on_alert = lambda alert, incident: seen.append(alert.alert_id)

    total = monitor.poll_once()
    assert total == 2
    status = monitor.status()
    assert status["processed"] == 2
    assert status["alerts"] == 2
    assert status["last_poll"] is not None
    assert seen == ["AL-1", "AL-1"]

    recent = monitor.recent_events()
    assert len(recent) == 2
    assert recent[0]["alerts"] == 1
    assert recent[0]["source_id"] == "s"


def test_monitor_start_stop_lifecycle(tmp_path):
    monitor = SystemMonitor(
        _config(tmp_path, {"interval_seconds": 1,
                           "files": []}), storage=None,
    )
    monitor.collectors = [_StubCollector([])]
    monitor._pipeline = _StubPipeline([])
    status = monitor.start()
    assert status["running"] is True
    assert monitor.is_running() is True
    stop_status = monitor.stop()
    assert stop_status["running"] is False


def test_monitor_clear_recent(tmp_path):
    from siem.monitoring.collectors import MonitorRecord

    monitor = SystemMonitor(_config(tmp_path), storage=None)
    monitor._push_recent(MonitorRecord(raw="x", source_id="s",
                                       source_type="stub").as_recent())
    assert monitor.recent_events()
    monitor.clear_recent()
    assert monitor.recent_events() == []


# -- web API ---------------------------------------------------------------

def test_monitor_page_requires_login(client):
    resp = client.get("/monitor/")
    assert resp.status_code in (302, 303)


def test_monitor_page_renders(auth_client):
    resp = auth_client.get("/monitor/")
    assert resp.status_code == 200
    assert b"Live system monitor" in resp.data
    assert b"Start Monitoring" in resp.data


def test_monitor_api_status(auth_client):
    resp = auth_client.get("/monitor/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["running"] is False


def test_monitor_api_status_requires_login(client):
    resp = client.get("/monitor/api/status")
    assert resp.status_code == 401


def test_monitor_api_start_stop_admin(auth_client):
    started = auth_client.post("/monitor/api/start").get_json()
    assert started["running"] is True
    stopped = auth_client.post("/monitor/api/stop").get_json()
    assert stopped["running"] is False


def test_monitor_api_start_sets_cookie(auth_client):
    resp = auth_client.post("/monitor/api/start")
    assert resp.status_code == 200
    auth_client.post("/monitor/api/stop")


def test_monitor_api_start_requires_admin(web_app, client):
    storage = web_app.extensions["siem_storage"]
    storage.users.create("viewer", "viewer-pass", role="viewer")
    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    resp = client.post("/monitor/api/start")
    assert resp.status_code == 403


def test_monitor_clear_endpoint(auth_client):
    resp = auth_client.post("/monitor/api/clear")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True
