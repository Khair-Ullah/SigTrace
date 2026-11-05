"""Local system log collectors for the interactive Monitor (Phase 10).

Collectors turn platform-specific log sources into simple, uniform
``MonitorRecord`` objects that the :class:`~siem.monitoring.system_monitor.SystemMonitor`
feeds into the processing pipeline.

Two collectors are provided:

* :class:`WindowsEventLogCollector` - reads Windows Event Log channels via the
  built-in ``wevtutil`` utility (no extra dependencies).
* :class:`FileSourceCollector` - tails plain log files, tolerating rotation.
"""
from __future__ import annotations

import os
import platform
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from siem.core.logger import get_logger

log = get_logger("monitoring.collectors")

# Windows Event Log level -> SIEM severity
_WIN_LEVEL_SEVERITY = {
    "1": "critical",  # Critical
    "2": "high",      # Error
    "3": "medium",    # Warning
    "4": "low",       # Information
    "5": "low",       # Verbose
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


@dataclass
class MonitorRecord:
    """A single unit of collected log data ready for the pipeline."""

    raw: str
    source_id: str
    source_type: str
    summary: str = ""
    event_type: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[str] = None

    def as_recent(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "severity": self.severity,
            "summary": self.summary or self.raw[:180],
        }


@dataclass
class CollectorState:
    collected: int = 0
    last_error: Optional[str] = None


class BaseCollector:
    name = "base"
    source_type = "custom"

    def __init__(self) -> None:
        self.state = CollectorState()

    @property
    def label(self) -> str:
        return self.name

    def poll(self) -> list[MonitorRecord]:  # pragma: no cover - overridden
        raise NotImplementedError

    def status(self) -> dict:
        return {
            "name": self.label,
            "type": self.source_type,
            "collected": self.state.collected,
            "last_error": self.state.last_error,
        }


class WindowsEventLogCollector(BaseCollector):
    """Read new entries from one or more Windows Event Log channels."""

    name = "windows-event-log"
    source_type = "windows_event"

    def __init__(self, channels: list[str], max_per_poll: int = 50) -> None:
        super().__init__()
        self.channels = [str(c) for c in channels]
        self.max_per_poll = max(1, int(max_per_poll))
        self._last_record_id: dict[str, int] = {}
        self._supported = platform.system().lower() == "windows"

    @property
    def label(self) -> str:
        return f"Windows Event Log ({', '.join(self.channels)})"

    def poll(self) -> list[MonitorRecord]:
        if not self._supported:
            self.state.last_error = "only supported on Windows"
            return []

        records: list[MonitorRecord] = []
        for channel in self.channels:
            try:
                records.extend(self._poll_channel(channel))
            except Exception as e:  # a locked/unreadable channel must not stop others
                self.state.last_error = f"{channel}: {e}"
                log.warning("Monitor: failed to read channel %s: %s", channel, e)
        records.sort(key=lambda r: r.timestamp or "")
        self.state.collected += len(records)
        return records

    def _poll_channel(self, channel: str) -> list[MonitorRecord]:
        out = self._wevtutil_query(channel, self.max_per_poll)
        if not out.strip():
            return []

        events = _parse_wevtutil_xml(out)
        last = self._last_record_id.get(channel, 0)
        fresh = [e for e in events if int(e.get("record_id") or 0) > last]
        if not fresh:
            return []

        self._last_record_id[channel] = max(
            int(e.get("record_id") or 0) for e in fresh
        )

        collected: list[MonitorRecord] = []
        for ev in fresh:
            rec = self._to_record(ev)
            if rec is not None:
                collected.append(rec)
        return collected

    @staticmethod
    def _wevtutil_query(channel: str, count: int) -> str:
        cmd = ["wevtutil", "qe", channel, f"/c:{count}", "/rd:true", "/f:xml"]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            creationflags=creationflags,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "wevtutil failed").strip())
        return proc.stdout

    def _to_record(self, ev: dict) -> Optional[MonitorRecord]:
        channel = ev.get("channel") or "Unknown"
        event_id = str(ev.get("event_id") or "")
        event_type = _SECURITY_EVENT_TYPES.get(event_id)
        if event_type is None:
            event_type = "windows_event"

        # Prefer the human-readable message; fall back to EventData text.
        message = ev.get("message") or ev.get("event_data_text") or ""
        if not message:
            message = f"{ev.get('provider', 'Windows')} EventID={event_id}"

        severity = _WIN_LEVEL_SEVERITY.get(str(ev.get("level") or "4"), "low")

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
        import json

        raw = json.dumps({k: v for k, v in payload.items() if v not in (None, "")})

        summary = f"[{channel}] {ev.get('provider', '')} EventID={event_id}"
        if ev.get("user_name"):
            summary += f" user={ev['user_name']}"
        if ev.get("src_ip"):
            summary += f" src={ev['src_ip']}"

        return MonitorRecord(
            raw=raw,
            source_id=f"winlog-{channel.lower()}",
            source_type=self.source_type,
            summary=summary,
            event_type=event_type,
            severity=severity,
            timestamp=ev.get("timestamp"),
        )


class FileSourceCollector(BaseCollector):
    """Tail a set of files, following simple rotation/truncation."""

    name = "file-sources"
    source_type = "file"

    def __init__(self, sources: list[dict], read_from_beginning: bool = False,
                 project_root: Optional[Path] = None) -> None:
        super().__init__()
        self.project_root = project_root
        self.read_from_beginning = read_from_beginning
        self.sources = []
        for spec in sources or []:
            path = Path(str(spec.get("path", "")))
            if not path.is_absolute() and project_root is not None:
                path = project_root / path
            if str(path) == ".":
                continue
            self.sources.append({
                "path": path,
                "source_id": spec.get("source_id") or path.stem,
                "source_type": spec.get("source_type") or "file",
                "offset": 0,
                "primed": False,
            })

    @property
    def label(self) -> str:
        return f"Files ({len(self.sources)})"

    def poll(self) -> list[MonitorRecord]:
        records: list[MonitorRecord] = []
        for src in self.sources:
            try:
                records.extend(self._poll_file(src))
            except Exception as e:
                self.state.last_error = f"{src['path']}: {e}"
                log.warning("Monitor: failed to read file %s: %s", src["path"], e)
        self.state.collected += len(records)
        return records

    def _poll_file(self, src: dict) -> list[MonitorRecord]:
        path: Path = src["path"]
        if not path.exists():
            return []

        size = path.stat().st_size
        if not src["primed"]:
            src["offset"] = 0 if self.read_from_beginning else size
            src["primed"] = True
            if not self.read_from_beginning:
                return []
        if size < src["offset"]:  # truncated / rotated
            src["offset"] = 0

        out: list[MonitorRecord] = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(src["offset"])
            for line in f:
                line = line.rstrip("\r\n")
                if line.strip():
                    out.append(MonitorRecord(
                        raw=line,
                        source_id=src["source_id"],
                        source_type=src["source_type"],
                        summary=line[:180],
                    ))
            src["offset"] = f.tell()
        return out

    def status(self) -> dict:
        base = super().status()
        base["files"] = [str(s["path"]) for s in self.sources]
        return base


# -- Windows Event Log XML helpers ----------------------------------------

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
        # Some builds wrap output differently; try each Event individually.
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

    data["event_data_text"] = " ".join(
        f"{k}={v}" for k, v in event_data.items() if v
    )
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


__all__ = [
    "MonitorRecord",
    "BaseCollector",
    "WindowsEventLogCollector",
    "FileSourceCollector",
]
