"""Audit-log persistence (FR-57)."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from siem.storage.models import AuditLog
from siem.storage.repositories.base import BaseRepository


class AuditRepository(BaseRepository):
    """Record user/system actions for accountability."""

    def record(
        self,
        action: str,
        details: Optional[str] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
    ) -> int:
        with self.session_scope() as session:
            row = AuditLog(
                action=action,
                details=details,
                user_id=user_id,
                ip_address=ip_address,
            )
            session.add(row)
            session.flush()
            return int(row.log_id)

    def recent(self, limit: int = 50) -> list[dict]:
        with self.session_scope() as session:
            rows = session.execute(
                select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
            ).scalars().all()
            return [
                {
                    "log_id": r.log_id,
                    "timestamp": r.timestamp,
                    "user_id": r.user_id,
                    "action": r.action,
                    "details": r.details,
                    "ip_address": r.ip_address,
                }
                for r in rows
            ]
