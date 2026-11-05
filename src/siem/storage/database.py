"""Database engine and session management (SQLAlchemy 2.0 + SQLite WAL)."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from siem.core.config import get_config
from siem.core.exceptions import StorageError
from siem.core.logger import get_logger

log = get_logger("storage.database")

_engine: Engine | None = None
_session_factory: sessionmaker | None = None

# SQLite performance PRAGMAs
_SQLITE_PRAGMAS = [
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("temp_store", "MEMORY"),
    ("foreign_keys", "ON"),
]


def _apply_sqlite_pragmas(dbapi_conn, connection_record) -> None:
    """Apply performance PRAGMAs on every new SQLite connection."""
    cursor = dbapi_conn.cursor()
    try:
        for pragma, value in _SQLITE_PRAGMAS:
            cursor.execute(f"PRAGMA {pragma}={value}")
        # cache_size in KB (negative = KB): 64 MB
        cursor.execute("PRAGMA cache_size=-64000")
        # mmap 256 MB
        cursor.execute("PRAGMA mmap_size=268435456")
    finally:
        cursor.close()


def _resolve_sqlite_path(url: str) -> str:
    """Convert relative sqlite:/// path to absolute, based on project root."""
    if not url.startswith("sqlite:///"):
        return url
    rel = url[len("sqlite:///"):]
    if rel == ":memory:" or Path(rel).is_absolute():
        return url
    root = get_config().project_root
    abs_path = (root / rel).resolve()
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{abs_path}"


def sqlite_file_path(url: str) -> Path | None:
    """Return the on-disk file Path for a sqlite URL (None for memory/other)."""
    if not url.startswith("sqlite:///"):
        return None
    rel = url[len("sqlite:///"):]
    if rel == ":memory:":
        return None
    path = Path(rel)
    if not path.is_absolute():
        path = (get_config().project_root / rel).resolve()
    return path


def init_engine(url: str | None = None, echo: bool | None = None) -> Engine:
    """Create (or return) the global SQLAlchemy engine."""
    global _engine, _session_factory
    if _engine is not None:
        return _engine

    config = get_config()
    url = url or config.get("database.url", "sqlite:///data/siem.db")
    url = _resolve_sqlite_path(url)
    echo = echo if echo is not None else config.get("database.echo", False)

    # Ensure the schema is up to date before any ORM query runs.
    auto_migrate = config.get("database.auto_migrate", True)
    db_file = sqlite_file_path(url)
    if auto_migrate and db_file is not None:
        from siem.storage.migrations import run_migrations
        run_migrations(db_file)

    try:
        _engine = create_engine(url, echo=echo, future=True)
    except Exception as e:
        raise StorageError(f"Failed to create database engine: {e}") from e

    # Register PRAGMA hook for SQLite
    if url.startswith("sqlite"):
        event.listen(_engine, "connect", _apply_sqlite_pragmas)

    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    log.info("Database engine initialized: %s", url.split("///")[-1])
    return _engine


def get_engine() -> Engine:
    """Return the global engine, initializing if needed."""
    if _engine is None:
        return init_engine()
    return _engine


def get_session_factory() -> sessionmaker:
    """Return the global session factory, initializing if needed."""
    if _session_factory is None:
        init_engine()
    assert _session_factory is not None
    return _session_factory


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Provide a transactional session scope.

    Usage:
        with get_session() as session:
            session.add(event)
            # commits on success, rolls back on exception
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def dispose_engine() -> None:
    """Dispose the global engine (used on shutdown / in tests)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _session_factory = None
        log.info("Database engine disposed")
