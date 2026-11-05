"""Lightweight SQL migration runner for the SQLite database.

Migrations live in ``src/siem/storage/migrations`` as ``NNN_name.sql`` files and
are applied in numeric order. Applied versions are recorded in a
``schema_migrations`` table so re-running is safe.

The runner talks to SQLite directly (not through SQLAlchemy) so that it can run
before the ORM engine is used and inside ``scripts/setup_db.py``.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from siem.core.logger import get_logger

log = get_logger("storage.migrations")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# Persistent / connection PRAGMAs (applied before schema work)
PRAGMAS = [
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA cache_size = -64000",
    "PRAGMA temp_store = MEMORY",
    "PRAGMA mmap_size = 268435456",
    "PRAGMA foreign_keys = ON",
]

_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""


def _iter_statements(sql: str):
    """Yield individual SQL statements, stripping comment-only lines."""
    for chunk in sql.split(";"):
        stmt = "\n".join(
            line for line in chunk.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ).strip()
        if stmt:
            yield stmt


def _table_exists(cursor: sqlite3.Cursor, name: str) -> bool:
    row = cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    rows = cursor.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _discover(migrations_dir: Path) -> list[Path]:
    if not migrations_dir.exists():
        return []
    files = [
        p for p in migrations_dir.iterdir()
        if p.is_file() and p.suffix.lower() == ".sql"
    ]
    return sorted(files, key=lambda p: int(p.name.split("_", 1)[0]))


def run_migrations(
    db_path: str | Path,
    migrations_dir: Path | None = None,
) -> list[str]:
    """Apply all pending migrations. Returns the names of applied migrations."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    migrations_dir = migrations_dir or MIGRATIONS_DIR

    conn = sqlite3.connect(str(db_path))
    applied_now: list[str] = []
    try:
        cursor = conn.cursor()
        for pragma in PRAGMAS:
            cursor.execute(pragma)
        cursor.execute(_TRACKING_TABLE)

        applied = {row[0] for row in cursor.execute(
            "SELECT version FROM schema_migrations"
        )}

        for path in _discover(migrations_dir):
            version = int(path.name.split("_", 1)[0])
            if version in applied:
                continue

            # Legacy database created before migration tracking existed:
            # if 001's core table is already present, just record it.
            if version == 1 and _table_exists(cursor, "events"):
                cursor.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (?, ?)",
                    (version, path.name),
                )
                applied_now.append(path.name)
                log.info("Migration %s already present (adopted)", path.name)
                continue

            sql = path.read_text(encoding="utf-8")
            for stmt in _iter_statements(sql):
                try:
                    cursor.execute(stmt)
                except sqlite3.OperationalError as e:
                    msg = str(e).lower()
                    if "duplicate column name" in msg:
                        continue  # ALTER already applied
                    raise
            cursor.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (?, ?)",
                (version, path.name),
            )
            applied_now.append(path.name)
            log.info("Applied migration %s", path.name)

        conn.commit()
    finally:
        conn.close()

    return applied_now


def current_version(db_path: str | Path) -> int:
    """Return the highest applied migration version (0 if none)."""
    db_path = Path(db_path)
    if not db_path.exists():
        return 0
    conn = sqlite3.connect(str(db_path))
    try:
        try:
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        conn.close()
