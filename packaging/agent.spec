# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the remote log-shipping agent (optional, onedir)."""
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).resolve().parent
SRC = ROOT / "src"

datas = []
binaries = []
hiddenimports = ["watchdog.observers.winapi"]

try:
    _d, _b, _h = collect_all("siem_agent")
    datas.extend(_d)
    binaries.extend(_b)
    hiddenimports.extend(_h)
except Exception:
    pass

a = Analysis(
    [str(ROOT / "packaging" / "entry_agent.py")],
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
    name="siem-agent",
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
    name="siem-agent",
)
