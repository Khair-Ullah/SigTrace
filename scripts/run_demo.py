#!/usr/bin/env python3
"""Run the multi-stage attack demo.

Thin compatibility wrapper around :mod:`siem.cli.commands.demo`, which lives
inside the package so the demo also works from a frozen desktop/CLI build.

Usage (from repo root):
  python scripts/run_demo.py [--dry-run] [--db PATH]
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure 'src' is on sys.path when running from a source checkout.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from siem.cli.commands.demo import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
