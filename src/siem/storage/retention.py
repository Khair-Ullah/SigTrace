"""Data retention / cleanup (FR-45, FR-61).

Removes events, alerts and closed incidents older than the configured
retention windows.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, select

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.storage.models import Alert as OrmAlert
from siem.storage.models import Event as OrmEvent
from siem.storage.models import Incident as OrmIncident
from siem.storage.models import Notification as OrmNotification
from siem.storage.repositories.alert_repository import AlertRepository
from siem.storage.repositories.base import BaseRepository
from siem.storage.repositories.event_repository import EventRepository
from siem.storage.repositories.incident_repository import IncidentRepository
from siem.storage.repositories.notification_repository import NotificationRepository

log = get_logger("storage.retention")


class RetentionManager(BaseRepository):
    """Applies retention policies to keep the database bounded."""

    def __init__(self, config: Optional[Config] = None, session_factory=None):
        super().__init__(session_factory)
        self.config = config or get_config()
        self.events = EventRepository(session_factory)
        self.alerts = AlertRepository(session_factory)
        self.incidents = IncidentRepository(session_factory)
        self.notifications = NotificationRepository(session_factory)

    def _cutoff(self, now: datetime, days_key: str, default_days: int) -> datetime:
        days = int(self.config.get(days_key, default_days))
        return now - timedelta(days=days)

    def cleanup(self, now: Optional[datetime] = None, dry_run: bool = False) -> dict:
        """Delete expired records. Returns a per-table count summary."""
        now = now or utcnow()
        ev_cut = self._cutoff(now, "retention.events_days", 30)
        al_cut = self._cutoff(now, "retention.alerts_days", 90)
        in_cut = self._cutoff(now, "retention.incidents_days", 365)

        if dry_run:
            summary = {
                "events": self._count_older(OrmEvent, OrmEvent.timestamp, ev_cut),
                "alerts": self._count_older(OrmAlert, OrmAlert.timestamp, al_cut),
                "incidents": self._count_closed_before(in_cut),
                "notifications": self._count_older(
                    OrmNotification, OrmNotification.created_at, al_cut
                ),
            }
        else:
            summary = {
                "events": self.events.delete_older_than(ev_cut),
                "alerts": self.alerts.delete_older_than(al_cut),
                "incidents": self.incidents.delete_older_than(in_cut, only_closed=True),
                "notifications": self.notifications.delete_older_than(al_cut),
            }
            log.info("Retention cleanup removed %s", summary)
        return summary

    def _count_older(self, model, column, cutoff: datetime) -> int:
        with self.session_scope() as session:
            return int(session.execute(
                select(func.count()).select_from(model).where(column < cutoff)
            ).scalar_one())

    def _count_closed_before(self, cutoff: datetime) -> int:
        with self.session_scope() as session:
            return int(session.execute(
                select(func.count()).select_from(OrmIncident).where(
                    OrmIncident.last_seen < cutoff,
                    OrmIncident.status == "closed",
                )
            ).scalar_one())
