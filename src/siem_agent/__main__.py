"""Allow ``python -m siem_agent``."""
from __future__ import annotations

from siem_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
