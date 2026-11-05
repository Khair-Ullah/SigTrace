"""Notification delivery log persistence (FR-50)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select

from siem.alerting.notification import NotificationResult
from siem.storage.models import Notification
from siem.storage.repositories.base import BaseRepository


def _dump_recipients(recipients: list[str] | None) -> str:
    return json.dumps(list(recipients or []))


def _load_recipients(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


class NotificationRepository(BaseRepository):
    """Record which alerts were delivered on which channels."""

    def add(self, result: NotificationResult) -> int:
        with self.session_scope() as session:
            row = Notification(
                alert_id=result.alert_id,
                incident_id=result.incident_id,
                channel=result.channel,
                recipients=_dump_recipients(result.recipients),
                status=result.status,
                detail=result.detail or None,
                created_at=result.created_at,
            )
            session.add(row)
            session.flush()
            return int(row.notification_id)

    def query(
        self,
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        channel: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self.session_scope() as session:
            stmt = select(Notification)
            if alert_id is not None:
                stmt = stmt.where(Notification.alert_id == alert_id)
            if incident_id is not None:
                stmt = stmt.where(Notification.incident_id == incident_id)
            if channel is not None:
                stmt = stmt.where(Notification.channel == channel)
            if status is not None:
                stmt = stmt.where(Notification.status == status)
            if since is not None:
                stmt = stmt.where(Notification.created_at >= since)
            stmt = stmt.order_by(Notification.created_at.desc()).limit(limit).offset(offset)
            rows = session.execute(stmt).scalars().all()
            return [self._to_dict(r) for r in rows]

    def count(
        self,
        channel: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        with self.session_scope() as session:
            stmt = select(func.count()).select_from(Notification)
            if channel is not None:
                stmt = stmt.where(Notification.channel == channel)
            if status is not None:
                stmt = stmt.where(Notification.status == status)
            return int(session.execute(stmt).scalar_one())

    def delete_older_than(self, cutoff: datetime) -> int:
        with self.session_scope() as session:
            result = session.execute(
                delete(Notification).where(Notification.created_at < cutoff)
            )
            return int(result.rowcount or 0)

    @staticmethod
    def _to_dict(row: Notification) -> dict:
        return {
            "notification_id": row.notification_id,
            "alert_id": row.alert_id,
            "incident_id": row.incident_id,
            "channel": row.channel,
            "recipients": _load_recipients(row.recipients),
            "status": row.status,
            "detail": row.detail,
            "created_at": row.created_at,
        }
