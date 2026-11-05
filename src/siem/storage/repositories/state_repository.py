"""Correlation state persistence (survives restarts).

Mirrors the in-memory :class:`~siem.engine.state_manager.StateManager` counters
into the ``correlation_state`` table.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import delete, select

from siem.storage.models import CorrelationState
from siem.storage.repositories.base import BaseRepository


class StateRepository(BaseRepository):
    """Persist per-(rule, group) sliding-window counters."""

    def upsert(
        self,
        rule_id: str,
        group_key: str,
        window_start: datetime,
        event_count: int,
    ) -> None:
        with self.session_scope() as session:
            row = session.execute(
                select(CorrelationState).where(
                    CorrelationState.rule_id == rule_id,
                    CorrelationState.group_key == group_key,
                )
            ).scalar_one_or_none()
            if row is None:
                session.add(CorrelationState(
                    rule_id=rule_id,
                    group_key=group_key,
                    window_start=window_start,
                    event_count=event_count,
                ))
            else:
                row.window_start = window_start
                row.event_count = event_count

    def delete(self, rule_id: str, group_key: str) -> int:
        with self.session_scope() as session:
            result = session.execute(
                delete(CorrelationState).where(
                    CorrelationState.rule_id == rule_id,
                    CorrelationState.group_key == group_key,
                )
            )
            return int(result.rowcount or 0)

    def load_all(self) -> list[dict]:
        with self.session_scope() as session:
            rows = session.execute(select(CorrelationState)).scalars().all()
            return [
                {
                    "rule_id": r.rule_id,
                    "group_key": r.group_key,
                    "window_start": r.window_start,
                    "event_count": r.event_count,
                }
                for r in rows
            ]

    def delete_older_than(self, cutoff: datetime) -> int:
        with self.session_scope() as session:
            result = session.execute(
                delete(CorrelationState).where(CorrelationState.window_start < cutoff)
            )
            return int(result.rowcount or 0)

    def count(self) -> int:
        with self.session_scope() as session:
            return len(session.execute(select(CorrelationState)).scalars().all())
