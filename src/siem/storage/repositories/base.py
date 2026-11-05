"""Shared repository base: session handling."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy.orm import Session, sessionmaker

from siem.storage.database import get_session


class BaseRepository:
    """Base class providing a transaction-scoped session.

    Repositories use the global session factory by default. Tests (and callers
    that need isolation) may pass their own ``session_factory``.
    """

    def __init__(self, session_factory: Optional[sessionmaker] = None):
        self._factory = session_factory

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        if self._factory is not None:
            session = self._factory()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        else:
            with get_session() as session:
                yield session
