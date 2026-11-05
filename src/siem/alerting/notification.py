"""Notification result model (recorded in the notifications table)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from siem.core.utils import utcnow

# Notification statuses
STATUS_SENT = "sent"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_DUPLICATE = "duplicate"


@dataclass
class NotificationResult:
    """Outcome of delivering one alert over one channel."""

    channel: str
    status: str
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    recipients: list[str] = field(default_factory=list)
    detail: str = ""
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "status": self.status,
            "alert_id": self.alert_id,
            "incident_id": self.incident_id,
            "recipients": self.recipients,
            "detail": self.detail,
            "created_at": self.created_at,
        }
