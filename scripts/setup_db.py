"""Initialize the SQLite database with schema and PRAGMA tuning.

Thin wrapper around :func:`siem.storage.bootstrap.setup_database` for
backwards compatibility (Docker entrypoint, docs, existing tooling).

Usage:
    python scripts/setup_db.py [--db PATH] [--force]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from siem.storage.bootstrap import default_db_file, setup_database  # noqa: E402

DEFAULT_DB_FILE = default_db_file()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize the SIEM SQLite database.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_FILE, help="Database file path")
    parser.add_argument("--force", action="store_true", help="Drop and recreate existing database")
    args = parser.parse_args(argv)

    return setup_database(args.db, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
