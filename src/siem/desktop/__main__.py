"""Allow ``python -m siem.desktop``."""
from siem.desktop.entry import main

if __name__ == "__main__":
    raise SystemExit(main())
