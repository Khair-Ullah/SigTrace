"""Database bootstrap helpers shared by the CLI, installer and desktop app.

Keeping this logic inside the package (rather than ``scripts/setup_db.py``)
means it is also available from a frozen PyInstaller build, where the
``scripts`` directory is not shipped.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from siem.core.config import Config, get_config


def default_db_file() -> Path:
    """Default on-disk SQLite database path for the current data root."""
    from siem.core import paths

    return paths.database_dir() / "siem.db"


def resolve_db_file(config: Optional[Config] = None) -> Path:
    """Resolve ``database.url`` to an on-disk file path.

    Falls back to ``data/siem.db`` under the data root for non-SQLite URLs
    (which are not supported by the bundled desktop app).
    """
    config = config or get_config()
    url = str(config.get("database.url", "sqlite:///data/siem.db"))
    if url.startswith("sqlite:///"):
        rel = url[len("sqlite:///"):]
        if rel == ":memory:":
            return default_db_file()
        path = Path(rel)
        if path.is_absolute():
            return path
        return (config.project_root / rel).resolve()
    return default_db_file()


def setup_database(db_file: Path, force: bool = False) -> int:
    """Create or upgrade the SQLite database at ``db_file``."""
    db_file = Path(db_file)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    if force and db_file.exists():
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(db_file) + suffix)
            if p.exists():
                p.unlink()
        print(f"Removed existing database: {db_file}")

    from siem.storage.migrations import current_version, run_migrations

    applied = run_migrations(db_file)

    conn = sqlite3.connect(db_file)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()

    print(f"Database initialized: {db_file}")
    print(f"Schema version: {current_version(db_file)}")
    if applied:
        print(f"Migrations applied: {', '.join(applied)}")
    else:
        print("Migrations applied: none (already up to date)")
    print(f"Tables ({len(tables)}): {', '.join(tables)}")
    return 0


def init_database(force: bool = False) -> int:
    """Initialise the database referenced by the active configuration."""
    try:
        config = get_config()
    except Exception:
        config = None
    db_file = resolve_db_file(config)
    return setup_database(db_file, force=force)
