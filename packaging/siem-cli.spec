# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the console CLI (optional, onedir build)."""
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
    "watchdog.observers.winapi",
    "sqlalchemy.dialects.sqlite",
    "jinja2.ext",
]

try:
    _d, _b, _h = collect_all("siem")
    datas.extend(_d)
    binaries.extend(_b)
    hiddenimports.extend(_h)
except Exception:
    pass

a = Analysis(
    [str(ROOT / "packaging" / "entry_cli.py")],
    pathex=[str(SRC)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "webview", "pystray", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SIEM-CLI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SIEM-CLI",
)
