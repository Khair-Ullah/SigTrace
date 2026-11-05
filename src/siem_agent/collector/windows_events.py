"""Windows Event Log collector using the built-in ``wevtutil`` utility.

Self-contained duplicate of the server-side XML parsing (the agent must not
import the ``siem`` package). Emits compact JSON payloads with
``format_hint="json"`` so the server stores every field. A per-channel
RecordId cursor is persisted to ``<spool>/winlog_cursor.json`` so restarts
resume exactly where they left off (at-least-once on crash).
"""
from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from siem_agent.collector.base import BaseCollector, EmitFn

log = logging.getLogger("siem_agent.windows_events")

# Windows Event Log level -> SIEM severity
_WIN_LEVEL_SEVERITY = {
    "1": "critical",  # Critical
    "2": "high",  # Error
    "3": "medium",  # Warning
    "4": "low",  # Information
    "5": "low",  # Verbose
}

# Security-channel EventID -> canonical event_type (for rule matching)
_SECURITY_EVENT_TYPES = {
    "4624": "login_success",
    "4625": "failed_login",
    "4634": "logout",
    "4647": "logout",
    "4648": "explicit_logon",
    "4672": "privileged_logon",
    "4720": "user_created",
    "4726": "user_deleted",
    "4728": "group_member_added",
    "4732": "group_member_added",
    "4740": "account_locked",
    "4768": "kerberos_auth",
    "4769": "kerberos_auth",
    "4776": "credential_validation",
    "4688": "process_created",
    "7045": "service_installed",
    "1102": "audit_log_cleared",
}

# EventData keys that commonly hold a source address / account
_SRC_IP_KEYS = ("IpAddress", "SourceNetworkAddress", "ClientAddress", "SourceAddress")
_USER_KEYS = ("TargetUserName", "SubjectUserName", "AccountName", "User")


class WindowsEventCollector(BaseCollector):
    def __init__(
        self,
        emit: EmitFn,
        channels: list[str],
        cursor_path: Path,
        poll_interval: float = 5.0,
        max_events_per_poll: int = 100,
        state_dir: Optional[Path] = None,
    ):
        super().__init__(emit, name="windows-events")
        self.channels = [str(c) for c in channels]
        self.poll_interval = max(1.0, float(poll_interval))
        self.max_events = max(1, int(max_events_per_poll))
        self._cursor_path = Path(cursor_path)
        self._cursors: dict[str, int] = {}
        self._supported = platform.system().lower() == "windows"
        self.stats = {"events": 0, "polls": 0, "errors": 0, "write_failures": 0}
        self._load_cursors()

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if not self._supported:
            log.warning(
                "Windows Event Log collection is only supported on Windows; " "collector disabled"
            )
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="agent-winlog", daemon=True)
        self._thread.start()
        log.info("Windows Event Log collector watching channels: %s", ", ".join(self.channels))

    # -- main loop --------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop_event.is_set():
            for channel in self.channels:
                if self._stop_event.is_set():
                    break
                try:
                    self._poll_channel(channel)
                except Exception as e:
                    self.stats["errors"] += 1
                    log.warning("Failed to read channel %s: %s", channel, e)
            self.stats["polls"] += 1
            self._stop_event.wait(self.poll_interval)

    def _poll_channel(self, channel: str) -> None:
        out = self._wevtutil_query(channel, self.max_events)
        if not out.strip():
            return
        events = _parse_wevtutil_xml(out)
        events.sort(key=lambda e: int(e.get("record_id") or 0))

        last = self._cursors.get(channel, 0)
        fresh = [e for e in events if int(e.get("record_id") or 0) > last]
        for ev in fresh:
            record = self._to_record(ev, channel)
            if not self.emit(record):
                self.stats["write_failures"] += 1
                log.warning("Spool write failed; cursor held back for %s", channel)
                break  # cursor not advanced for the failed event: retried next poll
            self.stats["events"] += 1
            self._cursors[channel] = int(ev.get("record_id") or 0)
            self._save_cursors()

    # -- wevtutil ---------------------------------------------------------
    @staticmethod
    def _wevtutil_query(channel: str, count: int) -> str:
        cmd = ["wevtutil", "qe", channel, f"/c:{count}", "/rd:true", "/f:xml"]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=creationflags,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "wevtutil failed").strip())
        return proc.stdout

    # -- record building --------------------------------------------------
    def _to_record(self, ev: dict, channel: str) -> dict:
        event_id = str(ev.get("event_id") or "")
        event_type = _SECURITY_EVENT_TYPES.get(event_id, "windows_event")
        severity = _WIN_LEVEL_SEVERITY.get(str(ev.get("level") or "4"), "low")
        message = ev.get("message") or ev.get("event_data_text") or ""
        if not message:
            message = f"{ev.get('provider', 'Windows')} EventID={event_id}"

        payload = {
            "timestamp": ev.get("timestamp"),
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "user_name": ev.get("user_name"),
            "src_ip": ev.get("src_ip"),
            "windows_event_id": event_id,
            "channel": channel,
            "provider": ev.get("provider"),
            "computer": ev.get("computer"),
            "record_id": ev.get("record_id"),
        }
        raw = json.dumps({k: v for k, v in payload.items() if v not in (None, "")})
        return {
            "raw": raw,
            "source_id": f"winlog-{channel.lower()}",
            "source_type": "windows_event",
            "format_hint": "json",
        }

    # -- cursor persistence -----------------------------------------------
    def _load_cursors(self) -> None:
        try:
            with open(self._cursor_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self._cursors = {str(k): int(v) for k, v in loaded.items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as e:
            log.warning("Ignoring unreadable winlog cursor file: %s", e)

    def _save_cursors(self) -> None:
        try:
            self._cursor_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._cursor_path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._cursors, f)
            os.replace(tmp, self._cursor_path)
        except OSError as e:
            log.warning("Failed to persist winlog cursor: %s", e)


# -- Windows Event Log XML helpers (duplicate of server-side parsing) -----


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _strip_ns(elem: ET.Element) -> None:
    for el in elem.iter():
        el.tag = _local(el.tag)


def _parse_wevtutil_xml(raw: str) -> list[dict]:
    """Parse concatenated ``<Event>`` XML fragments into dicts."""
    text = raw.strip()
    if not text:
        return []
    wrapped = f"<events>{text}</events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        events = []
        for chunk in text.split("</Event>"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if not chunk.endswith("</Event>"):
                chunk += "</Event>"
            try:
                events.append(ET.fromstring(chunk))
            except ET.ParseError:
                continue
        root = ET.fromstring("<events></events>")
        for ev in events:
            root.append(ev)

    _strip_ns(root)
    parsed: list[dict] = []
    for ev in root.findall("Event"):
        parsed.append(_parse_event(ev))
    return parsed


def _parse_event(ev: ET.Element) -> dict:
    system = ev.find("System")
    data: dict = {}
    if system is not None:
        data["provider"] = _attr(system.find("Provider"), "Name")
        data["event_id"] = _text(system.find("EventID"))
        data["level"] = _text(system.find("Level"))
        data["channel"] = _text(system.find("Channel"))
        data["computer"] = _text(system.find("Computer"))
        data["record_id"] = _text(system.find("EventRecordID"))
        tc = system.find("TimeCreated")
        data["timestamp"] = _attr(tc, "SystemTime")

    event_data: dict[str, str] = {}
    ed = ev.find("EventData")
    if ed is not None:
        for item in ed.findall("Data"):
            name = item.get("Name")
            if name:
                event_data[name] = (item.text or "").strip()

    data["user_name"] = _first_present(event_data, _USER_KEYS)
    data["src_ip"] = _first_present(event_data, _SRC_IP_KEYS)
    for value in event_data.values():
        if data.get("src_ip") is None and _looks_like_ip(value):
            data["src_ip"] = value

    ri = ev.find("RenderingInfo")
    if ri is not None:
        data["message"] = _first_present(
            {el.tag: (el.text or "") for el in ri.iter()}, ("Message",)
        )
    else:
        data["message"] = None

    data["event_data_text"] = " ".join(f"{k}={v}" for k, v in event_data.items() if v)
    return data


def _text(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    return (elem.text or "").strip() or None


def _attr(elem: Optional[ET.Element], name: str) -> Optional[str]:
    if elem is None:
        return None
    value = elem.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _first_present(mapping: dict, keys) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if value and value not in ("-", "N/A"):
            return value
    return None


def _looks_like_ip(value: str) -> bool:
    if not value or value in ("-", "::1", "127.0.0.1"):
        return False
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in value and any(c in "0123456789abcdef" for c in value.lower())
