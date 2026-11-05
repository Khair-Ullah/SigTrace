"""Logging setup for the SIEM engine.

Reads ``config/logging.yaml`` from the writable data root and initializes the
``siem`` logger hierarchy.

In windowed (console-less) builds ``sys.stdout``/``sys.stderr`` are ``None``;
the console handler is dropped in that case so logging never crashes the app.
Relative handler filenames are resolved against the data root, which makes the
same configuration work for a source checkout, a frozen bundle and a desktop
install.
"""
from __future__ import annotations

import logging
import logging.config
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any

from siem.core import paths

_configured = False


def _has_console() -> bool:
    """True when the process has usable standard streams."""
    return sys.stdout is not None and sys.stderr is not None


def _absolutize_handlers(log_config: dict[str, Any], root: Path) -> None:
    """Resolve relative ``filename`` values against the writable data root."""
    handlers = log_config.get("handlers") or {}
    if not isinstance(handlers, dict):
        return
    for handler in handlers.values():
        if not isinstance(handler, dict):
            continue
        filename = handler.get("filename")
        if not filename:
            continue
        path = Path(str(filename))
        if not path.is_absolute():
            handler["filename"] = str(root / path)


def _drop_console_handlers(log_config: dict[str, Any]) -> None:
    """Remove console/StreamHandler entries in a console-less build."""
    handlers = log_config.get("handlers") or {}
    if not isinstance(handlers, dict):
        return

    console_names = {
        name
        for name, handler in handlers.items()
        if isinstance(handler, dict)
        and str(handler.get("class", "")).endswith("StreamHandler")
    }
    for name in console_names:
        handlers.pop(name, None)

    root_cfg = log_config.get("root")
    if isinstance(root_cfg, dict):
        root_cfg["handlers"] = [
            h for h in root_cfg.get("handlers", []) if h not in console_names
        ]

    loggers = log_config.get("loggers") or {}
    if isinstance(loggers, dict):
        for logger_cfg in loggers.values():
            if isinstance(logger_cfg, dict) and "handlers" in logger_cfg:
                logger_cfg["handlers"] = [
                    h for h in logger_cfg["handlers"] if h not in console_names
                ]


def setup_logging(config_file: str | Path | None = None, level: str | None = None) -> None:
    """Configure logging from YAML. Safe to call multiple times."""
    global _configured
    if _configured:
        if level:
            logging.getLogger("siem").setLevel(level.upper())
        return

    root = paths.data_dir()
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    if config_file is None:
        config_file = os.environ.get("SIEM_LOGGING_CONFIG") or str(
            paths.config_dir() / "logging.yaml"
        )
    path = Path(config_file)
    if not path.is_absolute():
        path = root / path

    if path.exists():
        import yaml

        with open(path, "r", encoding="utf-8") as f:
            log_config = yaml.safe_load(f) or {}
        _absolutize_handlers(log_config, root)
        has_console = _has_console()
        if not has_console:
            _drop_console_handlers(log_config)
        logging.config.dictConfig(log_config)
        if not has_console:
            # dictConfig may still configure a handler with stream=None for
            # loggers we did not anticipate; guarantee at least one file sink.
            _ensure_file_handler(log_dir, level)
    elif _has_console():
        logging.basicConfig(
            level=level or "INFO",
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:
        _install_file_handler(log_dir, level)

    if level:
        logging.getLogger("siem").setLevel(level.upper())

    _configured = True


def _file_handler(log_dir: Path) -> logging.Handler:
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "siem.log",
        maxBytes=100 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )
    )
    return handler


def _install_file_handler(log_dir: Path, level: str | None) -> None:
    logging.basicConfig(
        level=level or "INFO",
        handlers=[_file_handler(log_dir)],
    )


def _ensure_file_handler(log_dir: Path, level: str | None) -> None:
    """Make sure the root logger writes somewhere when no console exists."""
    root_logger = logging.getLogger()
    if any(
        isinstance(h, logging.FileHandler) for h in root_logger.handlers
    ):
        return
    root_logger.addHandler(_file_handler(log_dir))
    if root_logger.level == logging.NOTSET:
        root_logger.setLevel((level or "INFO").upper())


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the 'siem' namespace."""
    if not name.startswith("siem"):
        name = f"siem.{name}"
    return logging.getLogger(name)
