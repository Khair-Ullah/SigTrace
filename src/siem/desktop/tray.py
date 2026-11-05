"""Optional system-tray icon for the desktop shell."""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("siem.desktop.tray")


def _make_image():
    from PIL import Image, ImageDraw

    size = 64
    image = Image.new("RGBA", (size, size), (15, 23, 42, 255))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((6, 6, size - 6, size - 6), radius=14,
                           fill=(15, 23, 42, 255), outline=(34, 211, 238, 255),
                           width=4)
    # Simple shield glyph
    draw.polygon(
        [(32, 14), (48, 21), (48, 36), (32, 52), (16, 36), (16, 21)],
        outline=(34, 211, 238, 255),
    )
    draw.line((24, 32, 30, 39), fill=(34, 211, 238, 255), width=4)
    draw.line((30, 39, 41, 25), fill=(34, 211, 238, 255), width=4)
    return image


def _open_path(path: Path) -> None:
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys_platform() == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:  # pragma: no cover - desktop integration is best-effort
        log.exception("Could not open %s", path)


def sys_platform() -> str:
    import sys

    return sys.platform


class DesktopTray:
    """Thin wrapper around pystray with a graceful no-tray fallback."""

    def __init__(
        self,
        on_open: Callable[[], None],
        on_quit: Callable[[], None],
        data_dir: Optional[Path] = None,
        title: str = "SIEM Dashboard",
    ) -> None:
        self.on_open = on_open
        self.on_quit = on_quit
        self.data_dir = data_dir
        self.title = title
        self._icon = None

    @property
    def running(self) -> bool:
        return self._icon is not None

    def start(self) -> bool:
        try:
            import pystray
        except Exception:
            log.info("pystray is not available; running without a tray icon")
            return False

        items = [pystray.MenuItem("Open Dashboard", self._handle_open, default=True)]
        if self.data_dir is not None:
            items.append(
                pystray.MenuItem(
                    "Open Data Folder",
                    lambda _icon, _item: _open_path(Path(self.data_dir)),
                )
            )
        items.append(pystray.MenuItem("Quit", self._handle_quit))

        try:
            self._icon = pystray.Icon(
                "siem", _make_image(), self.title, menu=pystray.Menu(*items)
            )
            self._icon.run_detached()
            return True
        except Exception:
            log.exception("Failed to start the system tray icon")
            self._icon = None
            return False

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:  # pragma: no cover
                log.exception("Error stopping tray icon")
            self._icon = None

    def _handle_open(self, _icon=None, _item=None) -> None:
        try:
            self.on_open()
        except Exception:
            log.exception("Tray 'Open Dashboard' failed")

    def _handle_quit(self, _icon=None, _item=None) -> None:
        try:
            self.on_quit()
        finally:
            self.stop()
