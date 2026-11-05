"""Normalized event model (the unified schema produced by the parser)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

from siem.core.constants import SEVERITY_LOW
from siem.core.utils import to_utc_iso, utcnow


@dataclass
class NormalizedEvent:
    """A parsed and normalized log event ready for rule matching and storage."""

    event_id: str
    timestamp: datetime
    source_id: str
    source_type: str
    raw_log: str
    message: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user_name: Optional[str] = None
    action: Optional[str] = None
    event_type: Optional[str] = None
    severity: str = SEVERITY_LOW
    ingested_at: datetime = field(default_factory=utcnow)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_extra: bool = True) -> dict[str, Any]:
        """Return a plain dict for storage/serialization.

        The timestamp is emitted as a UTC ISO-8601 string with a trailing Z.
        """
        data = asdict(self)
        data["timestamp"] = to_utc_iso(self.timestamp)
        data["ingested_at"] = to_utc_iso(self.ingested_at)
        if not include_extra:
            data.pop("extra", None)
        return data

    def __repr__(self) -> str:  # concise logging
        return (
            f"NormalizedEvent(id={self.event_id[:8]}, ts={self.timestamp.isoformat()}, "
            f"src={self.src_ip}, type={self.event_type}, sev={self.severity})"
        )
