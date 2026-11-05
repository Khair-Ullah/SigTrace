"""Reset the SIEM database to a clean state for a presentation.

Thin compatibility wrapper around :mod:`siem.cli.commands.reset`, which lives
inside the package so the reset also works from a frozen desktop/CLI build.

Usage (from repo root):
  python scripts/reset_fresh_db.py [--db PATH]
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from siem.cli.commands.reset import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
