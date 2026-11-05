"""Dashboard aggregation helpers (FR-55, FR-57)."""
from __future__ import annotations

from datetime import timedelta

from siem.core.constants import SEVERITY_ORDER, VALID_STATUSES
from siem.core.utils import utcnow
from siem.storage.service import StorageService


class DashboardStats:
    """Compute summary metrics for the dashboard from the repositories."""

    def __init__(self, storage: StorageService):
        self.storage = storage

    def severity_breakdown(self) -> dict[str, int]:
        counts = self.storage.alerts.severity_counts()
        return {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER}

    def status_breakdown(self) -> dict[str, int]:
        counts = self.storage.incidents.status_counts()
        return {status: counts.get(status, 0) for status in VALID_STATUSES}

    def summary(self) -> dict:
        return {
            "events": self.storage.events.count(),
            "alerts": self.storage.alerts.count(),
            "alerts_unacknowledged": self.storage.alerts.count(acknowledged=False),
            "incidents": self.storage.incidents.count(),
            "incidents_open": self.storage.incidents.count(status="open"),
            "rules": self.storage.rules.count(),
            "notifications": self.storage.notifications.count(),
            "users": self.storage.users.count(),
            "severity": self.severity_breakdown(),
            "status": self.status_breakdown(),
        }

    def top_src_ips(self, limit: int = 5, hours: int | None = None) -> list[dict]:
        start = None
        if hours:
            start = utcnow() - timedelta(hours=hours)
        return self.storage.alerts.top_src_ips(limit=limit, start=start)

    def timeline(self, hours: int = 24) -> list[dict]:
        """Event counts bucketed by hour for the last ``hours`` hours."""
        now = utcnow().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        buckets = []
        for i in range(hours):
            bucket_start = start + timedelta(hours=i)
            bucket_end = bucket_start + timedelta(hours=1) - timedelta(microseconds=1)
            buckets.append({
                "hour": bucket_start.isoformat(),
                "label": bucket_start.strftime("%H:00"),
                "count": self.storage.events.count(start=bucket_start, end=bucket_end),
            })
        return buckets
