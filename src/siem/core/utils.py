"""Helper utilities for the SIEM engine."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def generate_uuid() -> str:
    """Generate a UUID4 string for events/alerts/incidents."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Current UTC time as naive datetime (SQLite-friendly)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_utc_iso(dt: datetime) -> str:
    """Convert a datetime to UTC ISO-8601 string with Z suffix."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def parse_int(value: str | int | None, default: int = 0) -> int:
    """Safely parse an integer, returning default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
