"""Packaged database reset (formerly ``scripts/reset_fresh_db.py``).

Lives inside the package so it also works from a frozen PyInstaller build.
The script remains as a thin wrapper for backwards compatibility.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from siem.core import paths
from siem.core.config import Config, get_config
from siem.storage.bootstrap import default_db_file, resolve_db_file, setup_database


def reset_database(
    db_path: Optional[Path] = None,
    config: Optional[Config] = None,
) -> int:
    """Delete the SQLite database and recreate a fresh migrated schema."""
    if db_path is not None:
        target = Path(db_path).expanduser().resolve()
    elif config is not None:
        target = resolve_db_file(config)
    else:
        target = default_db_file()

    print(f"[RESET] Target DB: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    removed = []
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(target) + suffix)
        if not candidate.exists():
            continue
        try:
            candidate.unlink()
        except PermissionError as exc:
            print(f"[ERROR] Could not delete {candidate}: {exc}")
            print("[HINT] Close any running siem/web/desktop/agent process using this DB.")
            return 1
        except OSError as exc:
            print(f"[ERROR] Failed to delete {candidate}: {exc}")
            return 1
        removed.append(str(candidate))
        print(f"[RESET] Deleted: {candidate}")

    if not removed:
        print("[RESET] No existing DB files found (already clean).")

    print("[RESET] Running database setup with --force...")
    try:
        code = setup_database(target, force=False)
    except Exception as exc:  # pragma: no cover - filesystem/db boundary
        print(f"[ERROR] setup_database failed: {exc}")
        return 1

    if code != 0:
        print(f"[ERROR] setup_database failed with exit code {code}")
        return code

    print("[RESET] Database reset complete. Fresh schema created.")
    print(
        "[RESET] If you need demo data, run: python -m siem demo "
        "(or the packaged equivalent)."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reset the SIEM database to a clean state")
    parser.add_argument(
        "--db",
        type=Path,
        help="Database file to reset (default: the active configured database)",
    )
    return parser


def cmd_reset(args, config: Optional[Config] = None) -> int:
    paths.bootstrap_env()
    if config is None:
        try:
            config = get_config()
        except Exception:
            config = None
    return reset_database(db_path=args.db, config=config)


def main(argv: Optional[list[str]] = None) -> int:
    return cmd_reset(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
