# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the native desktop application (onedir build)."""
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).resolve().parent
SRC = ROOT / "src"

datas = [
    (str(ROOT / "config"), "config"),
    (str(ROOT / "rules"), "rules"),
]
binaries = []
hiddenimports = [
    "engineio.async_drivers.threading",
    "simple_websocket",
    "watchdog.observers.winapi",
    "sqlalchemy.dialects.sqlite",
    "jinja2.ext",
    "webview.platforms.edgechromium",
    "pystray._win32",
]


def _collect(package):
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    except Exception:
        return
    datas.extend(pkg_datas)
    binaries.extend(pkg_binaries)
    hiddenimports.extend(pkg_hidden)


for _package in ("siem", "webview", "pystray", "PIL", "clr", "clr_loader", "pythonnet"):
    _collect(_package)

_icon = ROOT / "src" / "siem" / "web" / "static" / "img" / "siem.ico"
icon = str(_icon) if _icon.exists() else None

a = Analysis(
    [str(ROOT / "packaging" / "entry_desktop.py")],
    pathex=[str(SRC)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SIEM",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SIEM",
)
