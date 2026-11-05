"""Alert persistence (FR-43, FR-44, FR-52, FR-53)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from siem.engine.models import Alert
from siem.storage.mappers import alert_to_orm, alert_to_row, orm_to_alert
from siem.storage.models import Alert as OrmAlert
from siem.storage.repositories.base import BaseRepository


class AlertRepository(BaseRepository):
    """CRUD, search, acknowledgement and incident-linkage for alerts."""

    def add(self, alert: Alert) -> str:
        with self.session_scope() as session:
            session.add(alert_to_orm(alert))
        return alert.alert_id

    def add_many(self, alerts: list[Alert]) -> int:
        if not alerts:
            return 0
        rows = [alert_to_row(a) for a in alerts]
        with self.session_scope() as session:
            stmt = sqlite_insert(OrmAlert).values(rows)
            stmt = stmt.on_conflict_do_nothing(index_elements=["alert_id"])
            session.execute(stmt)
        return len(rows)

    def get(self, alert_id: str) -> Optional[Alert]:
        with self.session_scope() as session:
            row = session.get(OrmAlert, alert_id)
            return orm_to_alert(row) if row else None

    def query(
        self,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        incident_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        order_desc: bool = True,
    ) -> list[Alert]:
        with self.session_scope() as session:
            stmt = select(OrmAlert)
            if severity is not None:
                stmt = stmt.where(OrmAlert.severity == severity)
            if src_ip is not None:
                stmt = stmt.where(OrmAlert.src_ip == src_ip)
            if incident_id is not None:
                stmt = stmt.where(OrmAlert.incident_id == incident_id)
            if rule_id is not None:
                stmt = stmt.where(OrmAlert.rule_id == rule_id)
            if acknowledged is not None:
                stmt = stmt.where(OrmAlert.acknowledged == (1 if acknowledged else 0))
            if start is not None:
                stmt = stmt.where(OrmAlert.timestamp >= start)
            if end is not None:
                stmt = stmt.where(OrmAlert.timestamp <= end)
            order = OrmAlert.timestamp.desc() if order_desc else OrmAlert.timestamp.asc()
            stmt = stmt.order_by(order).limit(limit).offset(offset)
            rows = session.execute(stmt).scalars().all()
            return [orm_to_alert(r) for r in rows]

    def count(
        self,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        incident_id: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        with self.session_scope() as session:
            stmt = select(func.count()).select_from(OrmAlert)
            if severity is not None:
                stmt = stmt.where(OrmAlert.severity == severity)
            if src_ip is not None:
                stmt = stmt.where(OrmAlert.src_ip == src_ip)
            if incident_id is not None:
                stmt = stmt.where(OrmAlert.incident_id == incident_id)
            if acknowledged is not None:
                stmt = stmt.where(OrmAlert.acknowledged == (1 if acknowledged else 0))
            if start is not None:
                stmt = stmt.where(OrmAlert.timestamp >= start)
            if end is not None:
                stmt = stmt.where(OrmAlert.timestamp <= end)
            return int(session.execute(stmt).scalar_one())

    def set_incident(self, alert_id: str, incident_id: Optional[str]) -> int:
        with self.session_scope() as session:
            result = session.execute(
                update(OrmAlert)
                .where(OrmAlert.alert_id == alert_id)
                .values(incident_id=incident_id)
            )
            return int(result.rowcount or 0)

    def link_incident(self, alert_ids: list[str], incident_id: str) -> int:
        if not alert_ids:
            return 0
        with self.session_scope() as session:
            result = session.execute(
                update(OrmAlert)
                .where(OrmAlert.alert_id.in_(alert_ids))
                .values(incident_id=incident_id)
            )
            return int(result.rowcount or 0)

    def acknowledge(self, alert_id: str, acknowledged: bool = True) -> int:
        with self.session_scope() as session:
            result = session.execute(
                update(OrmAlert)
                .where(OrmAlert.alert_id == alert_id)
                .values(acknowledged=1 if acknowledged else 0)
            )
            return int(result.rowcount or 0)

    def delete_older_than(self, cutoff: datetime) -> int:
        with self.session_scope() as session:
            result = session.execute(
                delete(OrmAlert).where(OrmAlert.timestamp < cutoff)
            )
            return int(result.rowcount or 0)

    def severity_counts(self) -> dict[str, int]:
        with self.session_scope() as session:
            rows = session.execute(
                select(OrmAlert.severity, func.count())
                .group_by(OrmAlert.severity)
            ).all()
            return {str(sev): int(n) for sev, n in rows}

    def top_src_ips(
        self, limit: int = 5, start: Optional[datetime] = None
    ) -> list[dict]:
        with self.session_scope() as session:
            stmt = (
                select(OrmAlert.src_ip, func.count().label("n"))
                .where(OrmAlert.src_ip.is_not(None))
                .group_by(OrmAlert.src_ip)
                .order_by(func.count().desc())
                .limit(limit)
            )
            if start is not None:
                stmt = stmt.where(OrmAlert.timestamp >= start)
            rows = session.execute(stmt).all()
            return [{"src_ip": ip, "count": int(n)} for ip, n in rows]
