"""Native desktop shell for the SIEM dashboard (pywebview + system tray).

This package is optional: the web/CLI experience does not import it. Install
the ``desktop`` extra (``pip install -e ".[desktop]"``) to use it.
"""
from __future__ import annotations

__all__ = ["run_desktop"]


def run_desktop() -> int:  # pragma: no cover - thin lazy wrapper
    from siem.desktop.app import run_desktop as _run

    return _run()
