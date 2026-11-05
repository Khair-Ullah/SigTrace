"""Request-scoped accessors for the web layer."""
from __future__ import annotations

from flask import current_app

from siem.core.config import Config
from siem.storage.service import StorageService


def get_storage() -> StorageService:
    """Return the StorageService bound to the current application."""
    return current_app.extensions["siem_storage"]


def get_siem_config() -> Config:
    """Return the SIEM Config bound to the current application."""
    return current_app.extensions["siem_config"]


def get_monitor():
    """Return the local-log SystemMonitor bound to the current application."""
    return current_app.extensions["siem_monitor"]
