"""PyInstaller entry script for the console CLI."""
from siem.cli.main import cli

if __name__ == "__main__":
    raise SystemExit(cli())
