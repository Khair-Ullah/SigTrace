"""Normalization: map parsed fields into the unified event schema (FR-11..FR-13, FR-16)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from dateutil import parser as dtparser

from siem.core.constants import SEVERITY_LOW, VALID_SEVERITIES
from siem.core.utils import generate_uuid, utcnow
from siem.ingestion.base import RawLogRecord
from siem.parsing.models import NormalizedEvent

# Map heterogeneous field names to the canonical schema
FIELD_ALIASES = {
    # source IP
    "src_ip": "src_ip", "source_ip": "src_ip", "src": "src_ip",
    "client_ip": "src_ip", "clientip": "src_ip", "source_address": "src_ip",
    "remote_addr": "src_ip", "remote_ip": "src_ip",
    # destination IP
    "dst_ip": "dst_ip", "dest_ip": "dst_ip", "destination_ip": "dst_ip",
    "dst": "dst_ip", "dest": "dst_ip", "server_ip": "dst_ip",
    # ports
    "src_port": "src_port", "source_port": "src_port", "sport": "src_port",
    "dst_port": "dst_port", "dest_port": "dst_port", "dport": "dst_port",
    "destination_port": "dst_port",
    # user
    "user": "user_name", "username": "user_name", "user_name": "user_name",
    "account": "user_name", "userid": "user_name", "user_id": "user_name",
    # action / type / message / severity / timestamp
    "action": "action", "result": "action",
    "event_type": "event_type", "eventtype": "event_type", "event": "event_type",
    "severity": "severity", "level": "severity", "priority": "severity",
    "message": "message", "msg": "message",
    "timestamp": "timestamp", "time": "timestamp", "ts": "timestamp",
    "@timestamp": "timestamp", "date": "timestamp", "timestamp_str": "timestamp",
}

_CANONICAL_KEYS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "user_name",
    "action", "event_type", "severity", "message", "timestamp",
}


def coerce_severity(value: Any, default: str = SEVERITY_LOW) -> str:
    """Map various severity representations to low/medium/high/critical."""
    if value is None:
        return default

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _syslog_severity(int(value))

    s = str(value).strip().lower()
    if not s:
        return default
    if s.isdigit():
        return _syslog_severity(int(s))

    mapping = {
        "critical": "critical", "crit": "critical", "fatal": "critical",
        "emergency": "critical", "alert": "critical", "severe": "critical",
        "high": "high", "error": "high", "err": "high",
        "medium": "medium", "med": "medium", "warning": "medium", "warn": "medium",
        "low": "low", "notice": "low", "info": "low", "informational": "low",
        "debug": "low", "trace": "low",
    }
    return mapping.get(s, default)


def _syslog_severity(num: int) -> str:
    if num <= 2:
        return "critical"
    if num == 3:
        return "high"
    if num == 4:
        return "medium"
    return "low"


def parse_timestamp(value: Any, default: Optional[datetime] = None) -> datetime:
    """Parse many timestamp formats into a naive UTC datetime."""
    default = default or utcnow()
    dt: Optional[datetime] = None

    if value is None or (isinstance(value, str) and not value.strip()):
        return default

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return default
    else:
        s = str(value).strip().rstrip("Z")
        try:
            dt = dtparser.isoparse(s)
        except (ValueError, OverflowError):
            try:
                dt = dtparser.parse(s, default=datetime(default.year, 1, 1))
            except (ValueError, OverflowError, TypeError):
                return default

    if dt is None:
        return default
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _to_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize(fields: dict, record: RawLogRecord) -> NormalizedEvent:
    """Build a NormalizedEvent from parsed fields and the source record."""
    canonical: dict[str, Any] = {}
    extra: dict[str, Any] = {}

    for key, value in fields.items():
        target = FIELD_ALIASES.get(str(key).lower())
        if target:
            canonical[target] = value
        else:
            extra[key] = value

    event_type = canonical.get("event_type")
    action = canonical.get("action")
    severity = coerce_severity(canonical.get("severity"))
    if severity not in VALID_SEVERITIES:
        severity = SEVERITY_LOW

    return NormalizedEvent(
        event_id=generate_uuid(),
        timestamp=parse_timestamp(canonical.get("timestamp"), record.received_at),
        source_id=record.source_id,
        source_type=record.source_type,
        raw_log=record.raw,
        message=str(canonical.get("message") or record.raw),
        src_ip=canonical.get("src_ip") or None,
        dst_ip=canonical.get("dst_ip") or None,
        src_port=_to_int(canonical.get("src_port")),
        dst_port=_to_int(canonical.get("dst_port")),
        user_name=canonical.get("user_name") or None,
        action=str(action) if action is not None else None,
        event_type=str(event_type) if event_type is not None else None,
        severity=severity,
        extra=extra,
    )
