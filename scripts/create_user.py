"""Create and manage dashboard user accounts (FR-56, FR-57).

Thin wrapper around :mod:`siem.cli.commands.users` so the same logic is
available from ``siem user ...`` and from a frozen desktop build.

Usage:
    python scripts/create_user.py create --username admin --password secret --role admin
    python scripts/create_user.py list
    python scripts/create_user.py passwd --username analyst --password newsecret
    python scripts/create_user.py role   --username analyst --role viewer
    python scripts/create_user.py delete --username olduser
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from siem.cli.commands.users import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
