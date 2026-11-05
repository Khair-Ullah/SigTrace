"""Incident persistence (FR-43, FR-44, FR-54)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select, update

from siem.engine.models import Incident
from siem.storage.mappers import incident_to_orm, orm_to_incident
from siem.storage.models import Incident as OrmIncident
from siem.storage.repositories.base import BaseRepository


class IncidentRepository(BaseRepository):
    """Create/update and query correlated incidents."""

    def upsert(self, incident: Incident) -> str:
        """Insert a new incident or update the existing one (by id)."""
        with self.session_scope() as session:
            session.merge(incident_to_orm(incident))
        return incident.incident_id

    def add_many(self, incidents: list[Incident]) -> int:
        for incident in incidents:
            self.upsert(incident)
        return len(incidents)

    def get(self, incident_id: str) -> Optional[Incident]:
        with self.session_scope() as session:
            row = session.get(OrmIncident, incident_id)
            return orm_to_incident(row) if row else None

    def query(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        order_desc: bool = True,
    ) -> list[Incident]:
        with self.session_scope() as session:
            stmt = select(OrmIncident)
            if status is not None:
                stmt = stmt.where(OrmIncident.status == status)
            if severity is not None:
                stmt = stmt.where(OrmIncident.severity == severity)
            if src_ip is not None:
                stmt = stmt.where(OrmIncident.src_ip == src_ip)
            if user_name is not None:
                stmt = stmt.where(OrmIncident.user_name == user_name)
            if start is not None:
                stmt = stmt.where(OrmIncident.last_seen >= start)
            if end is not None:
                stmt = stmt.where(OrmIncident.last_seen <= end)
            order = (
                OrmIncident.last_seen.desc() if order_desc
                else OrmIncident.last_seen.asc()
            )
            stmt = stmt.order_by(order).limit(limit).offset(offset)
            rows = session.execute(stmt).scalars().all()
            return [orm_to_incident(r) for r in rows]

    def count(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        with self.session_scope() as session:
            stmt = select(func.count()).select_from(OrmIncident)
            if status is not None:
                stmt = stmt.where(OrmIncident.status == status)
            if severity is not None:
                stmt = stmt.where(OrmIncident.severity == severity)
            return int(session.execute(stmt).scalar_one())

    def update_status(self, incident_id: str, status: str) -> int:
        with self.session_scope() as session:
            result = session.execute(
                update(OrmIncident)
                .where(OrmIncident.incident_id == incident_id)
                .values(status=status)
            )
            return int(result.rowcount or 0)

    def delete_older_than(
        self, cutoff: datetime, only_closed: bool = True
    ) -> int:
        """Delete incidents last seen before ``cutoff``.

        By default only closed incidents are removed to avoid dropping active
        investigations.
        """
        with self.session_scope() as session:
            stmt = delete(OrmIncident).where(OrmIncident.last_seen < cutoff)
            if only_closed:
                stmt = stmt.where(OrmIncident.status == "closed")
            result = session.execute(stmt)
            return int(result.rowcount or 0)

    def status_counts(self) -> dict[str, int]:
        with self.session_scope() as session:
            rows = session.execute(
                select(OrmIncident.status, func.count())
                .group_by(OrmIncident.status)
            ).all()
            return {str(s): int(n) for s, n in rows}

    def severity_counts(self) -> dict[str, int]:
        with self.session_scope() as session:
            rows = session.execute(
                select(OrmIncident.severity, func.count())
                .group_by(OrmIncident.severity)
            ).all()
            return {str(sev): int(n) for sev, n in rows}
