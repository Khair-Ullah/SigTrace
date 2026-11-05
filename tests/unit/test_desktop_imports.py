"""The desktop modules must import without optional GUI dependencies installed."""
from __future__ import annotations


def test_desktop_modules_import_lazily():
    import siem.desktop
    import siem.desktop.app
    import siem.desktop.bootstrap
    import siem.desktop.entry
    import siem.desktop.server
    import siem.desktop.tray

    assert callable(siem.desktop.run_desktop)
    assert callable(siem.desktop.app.run_desktop)
    assert callable(siem.desktop.entry.main)
    assert callable(siem.desktop.server.start)
    assert callable(siem.desktop.tray.DesktopTray)
