"""Console entry point for the desktop application (``siem-desktop``)."""
from __future__ import annotations

import logging
import sys
import traceback


def main() -> int:
    if sys.platform == "win32":
        import multiprocessing

        multiprocessing.freeze_support()

    try:
        from siem.desktop.app import run_desktop

        return run_desktop()
    except SystemExit as exc:  # pragma: no cover - explicit exits
        return int(exc.code or 0)
    except Exception as exc:  # pragma: no cover - last-resort crash handler
        logging.getLogger("siem.desktop.entry").exception("Unhandled desktop error")
        try:
            from siem.desktop.app import _show_message

            _show_message(
                "SIEM - Unexpected error",
                f"{exc}\n\n{traceback.format_exc()}",
                error=True,
            )
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
