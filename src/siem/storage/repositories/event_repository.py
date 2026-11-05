"""Event persistence (FR-43, FR-44)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from siem.parsing.models import NormalizedEvent
from siem.storage.mappers import event_to_orm, event_to_row, orm_to_event
from siem.storage.models import Event
from siem.storage.repositories.base import BaseRepository


class EventRepository(BaseRepository):
    """CRUD and search over normalized events."""

    def add(self, event: NormalizedEvent) -> str:
        with self.session_scope() as session:
            session.add(event_to_orm(event))
        return event.event_id

    def add_many(self, events: list[NormalizedEvent]) -> int:
        """Bulk-insert events (ignoring duplicate ids). Returns rows attempted."""
        if not events:
            return 0
        rows = [event_to_row(e) for e in events]
        with self.session_scope() as session:
            stmt = sqlite_insert(Event).values(rows)
            stmt = stmt.on_conflict_do_nothing(index_elements=["event_id"])
            session.execute(stmt)
        return len(rows)

    def get(self, event_id: str) -> Optional[NormalizedEvent]:
        with self.session_scope() as session:
            row = session.get(Event, event_id)
            return orm_to_event(row) if row else None

    def query(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        user_name: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        message_contains: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_desc: bool = True,
    ) -> list[NormalizedEvent]:
        with self.session_scope() as session:
            stmt = select(Event)
            stmt = self._apply_filters(
                stmt, src_ip, dst_ip, event_type, severity, source_id,
                user_name, start, end, message_contains,
            )
            order = Event.timestamp.desc() if order_desc else Event.timestamp.asc()
            stmt = stmt.order_by(order).limit(limit).offset(offset)
            rows = session.execute(stmt).scalars().all()
            return [orm_to_event(r) for r in rows]

    def count(
        self,
        src_ip: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        with self.session_scope() as session:
            stmt = select(func.count()).select_from(Event)
            if src_ip is not None:
                stmt = stmt.where(Event.src_ip == src_ip)
            if event_type is not None:
                stmt = stmt.where(Event.event_type == event_type)
            if severity is not None:
                stmt = stmt.where(Event.severity == severity)
            if source_id is not None:
                stmt = stmt.where(Event.source_id == source_id)
            if start is not None:
                stmt = stmt.where(Event.timestamp >= start)
            if end is not None:
                stmt = stmt.where(Event.timestamp <= end)
            return int(session.execute(stmt).scalar_one())

    def delete_older_than(self, cutoff: datetime) -> int:
        with self.session_scope() as session:
            result = session.execute(
                delete(Event).where(Event.timestamp < cutoff)
            )
            return int(result.rowcount or 0)

    @staticmethod
    def _apply_filters(stmt, src_ip, dst_ip, event_type, severity, source_id,
                       user_name, start, end, message_contains):
        if src_ip is not None:
            stmt = stmt.where(Event.src_ip == src_ip)
        if dst_ip is not None:
            stmt = stmt.where(Event.dst_ip == dst_ip)
        if event_type is not None:
            stmt = stmt.where(Event.event_type == event_type)
        if severity is not None:
            stmt = stmt.where(Event.severity == severity)
        if source_id is not None:
            stmt = stmt.where(Event.source_id == source_id)
        if user_name is not None:
            stmt = stmt.where(Event.user_name == user_name)
        if start is not None:
            stmt = stmt.where(Event.timestamp >= start)
        if end is not None:
            stmt = stmt.where(Event.timestamp <= end)
        if message_contains is not None:
            stmt = stmt.where(Event.message.ilike(f"%{message_contains}%"))
        return stmt
