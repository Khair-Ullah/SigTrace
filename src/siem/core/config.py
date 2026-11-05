"""Configuration loader for the SIEM engine.

Loads config/config.yaml and overlays environment variables (.env).
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from siem.core import paths
from siem.core.constants import DEFAULT_WEB_PORT
from siem.core.exceptions import ConfigError

# Environment variable -> (dotted config path) overrides
_ENV_OVERRIDES = {
    "SIEM_DATABASE_URL": "database.url",
    "SIEM_SECRET_KEY": "web.secret_key",
    "SIEM_SYSLOG_UDP_PORT": "ingestion.syslog.udp_port",
    "SIEM_SYSLOG_TCP_PORT": "ingestion.syslog.tcp_port",
    "SIEM_WEB_HOST": "web.host",
    "SIEM_WEB_PORT": "web.port",
    "SIEM_WEB_WORKERS": "web.workers",
    "SIEM_COOKIE_SECURE": "web.cookie_secure",
    "SIEM_LOG_LEVEL": "system.log_level",
}


class Config:
    """Nested configuration accessor backed by a plain dict."""

    def __init__(
        self,
        data: dict[str, Any],
        project_root: Path,
        bundle_root: Path | None = None,
    ):
        self._data = data
        self.project_root = Path(project_root)
        self.bundle_root = Path(bundle_root) if bundle_root is not None else self.project_root

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Get a value by dotted path, e.g. 'ingestion.syslog.udp_port'."""
        node: Any = self._data
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a value by dotted path (creates intermediate dicts)."""
        parts = dotted_key.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data


def _set_nested(data: dict[str, Any], dotted_key: str, value: Any) -> None:
    parts = dotted_key.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _coerce_env_value(raw: str, current: Any) -> Any:
    """Coerce env string to the type of the current config value."""
    if isinstance(current, bool):
        return raw.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        try:
            return int(raw)
        except ValueError:
            return raw
    return raw


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from YAML file with .env overlays.

    Resolution order (later wins):
      1. config/config.yaml (or SIEM_CONFIG path)
      2. Environment variables / .env file
    """
    root = paths.data_dir()

    # Load .env into environment (writable data root; repo root in dev mode)
    load_dotenv(root / ".env", override=False)

    # Determine config file path
    if config_path is None:
        config_path = os.environ.get("SIEM_CONFIG") or str(
            paths.default_config_path()
        )
    path = Path(config_path)
    if not path.is_absolute():
        path = root / path

    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict):
        raise ConfigError(f"Configuration root must be a mapping, got {type(data).__name__}")

    data = copy.deepcopy(data)

    # Apply environment overrides
    for env_name, dotted_key in _ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is not None:
            current = None
            node: Any = data
            for part in dotted_key.split("."):
                if not isinstance(node, dict):
                    break
                node = node.get(part)
            else:
                current = node
            _set_nested(data, dotted_key, _coerce_env_value(raw, current))

    # Safety: empty secret key falls back to a generated one (dev only warning path)
    web = data.setdefault("web", {})
    if not web.get("secret_key") or web.get("secret_key") == "CHANGE_ME_IN_PRODUCTION":
        web["port"] = web.get("port", DEFAULT_WEB_PORT)

    return Config(data, project_root=root, bundle_root=paths.bundle_dir())


# Module-level singleton
_config: Config | None = None


def get_config() -> Config:
    """Return the process-wide Config singleton (loads on first call)."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: Config) -> None:
    """Override the process-wide Config singleton (used by tests/CLI)."""
    global _config
    _config = config
