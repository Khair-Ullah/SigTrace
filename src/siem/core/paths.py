"""Filesystem layout helpers for source, frozen (PyInstaller) and desktop runs.

The application has two roots:

* **bundle root** - read-only resources shipped with the app (default config,
  built-in rules, docs). When frozen this is PyInstaller's extraction directory
  (``sys._MEIPASS``); in a source checkout it is the repository root.
* **data root** - writable runtime state (SQLite database, logs, custom rules,
  generated config/.env). When frozen this defaults to per-user application data
  (``%LOCALAPPDATA%\\SIEM`` on Windows); in a source checkout it stays the
  repository root so development and tests behave exactly as before.

``SIEM_HOME`` overrides the data root in every mode.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_DEV_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_APP_DIR_NAME = "SIEM"


def is_frozen() -> bool:
    """True when running from a PyInstaller (or similar) bundle."""
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path:
    """Read-only resource root (bundled defaults, built-in rules, package data)."""
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return _DEV_PROJECT_ROOT


def _platform_app_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / _APP_DIR_NAME
        return Path.home() / "AppData" / "Local" / _APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / _APP_DIR_NAME
    return Path.home() / ".local" / "share" / _APP_DIR_NAME


def data_dir() -> Path:
    """Writable runtime root.

    Resolution order: ``SIEM_HOME`` -> per-user app data (frozen) -> repo root
    (source checkout). The directory is not created here; call
    :func:`ensure_layout`.
    """
    override = os.environ.get("SIEM_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if is_frozen():
        return _platform_app_dir()
    return _DEV_PROJECT_ROOT


def project_root() -> Path:
    """Backwards-compatible alias for :func:`data_dir`."""
    return data_dir()


def config_dir() -> Path:
    return data_dir() / "config"


def logs_dir() -> Path:
    return data_dir() / "logs"


def rules_dir() -> Path:
    return data_dir() / "rules"


def database_dir() -> Path:
    return data_dir() / "data"


def default_config_path() -> Path:
    return config_dir() / "config.yaml"


def bundled_config_dir() -> Path:
    return bundle_dir() / "config"


def bundled_rules_dir() -> Path:
    return bundle_dir() / "rules"


def ensure_layout() -> Path:
    """Create the writable runtime layout and return the data root."""
    root = data_dir()
    for path in (
        root,
        config_dir(),
        logs_dir(),
        database_dir(),
        rules_dir(),
        rules_dir() / "builtin",
        rules_dir() / "custom",
    ):
        path.mkdir(parents=True, exist_ok=True)
    return root


def bootstrap_env() -> Path:
    """Set environment defaults used by :mod:`siem.core.config`.

    Must be called before the first :func:`siem.core.config.get_config` call so
    the cached singleton picks up the right data root and config file.
    """
    root = ensure_layout()
    os.environ.setdefault("SIEM_HOME", str(root))

    config_file = default_config_path()
    if config_file.exists():
        os.environ.setdefault("SIEM_CONFIG", str(config_file))
    return root
