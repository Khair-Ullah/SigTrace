"""PyInstaller entry script for the remote log-shipping agent."""
from siem_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
