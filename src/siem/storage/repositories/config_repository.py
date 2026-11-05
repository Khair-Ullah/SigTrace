"""Runtime configuration persistence (FR-60)."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select

from siem.storage.models import Config as OrmConfig
from siem.storage.repositories.base import BaseRepository


class ConfigRepository(BaseRepository):
    """Key/value store backed by the ``config`` table."""

    def get(self, key: str, default: Any = None) -> Any:
        with self.session_scope() as session:
            row = session.get(OrmConfig, key)
            return row.value if row else default

    def get_int(self, key: str, default: int = 0) -> int:
        value = self.get(key, None)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: Any, description: Optional[str] = None) -> None:
        with self.session_scope() as session:
            row = session.get(OrmConfig, key)
            if row is None:
                session.add(OrmConfig(key=key, value=str(value), description=description))
            else:
                row.value = str(value)
                if description is not None:
                    row.description = description

    def all(self) -> dict[str, str]:
        with self.session_scope() as session:
            rows = session.execute(select(OrmConfig)).scalars().all()
            return {r.key: r.value for r in rows}
