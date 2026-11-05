"""First-run setup for the desktop application.

Creates the writable runtime layout under ``%LOCALAPPDATA%\\SIEM`` (or
``SIEM_HOME``), seeds default configuration/rules, initialises the database and
creates an administrator account when none exists.

Everything here is safe to run on every start: files are only created when
missing and migrations are idempotent.
"""
from __future__ import annotations

import logging
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from siem.core import paths

log = logging.getLogger("siem.desktop.bootstrap")

_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%*"

_FALLBACK_CONFIG = {
    "system": {"name": "SIEM Log Correlator", "version": "1.0.0", "log_level": "INFO"},
    "database": {"url": "sqlite:///data/siem.db", "echo": False, "auto_migrate": True},
    "ingestion": {
        "syslog": {
            "enabled": True,
            "udp_port": 514,
            "tcp_port": 514,
            "host": "0.0.0.0",
            "source_id": "syslog",
            "source_type": "syslog",
        },
        "http": {"enabled": True},
        "files": {"read_from_beginning": False, "sources": []},
    },
    "rules": {
        "builtin_path": "rules/builtin",
        "custom_path": "rules/custom",
        "auto_reload": True,
    },
    "correlation": {
        "window_seconds": 300,
        "min_alerts_for_incident": 2,
        "match_fields": ["src_ip", "user_name", "dst_ip"],
        "correlation_rules_path": "rules/builtin/correlation",
    },
    "retention": {
        "events_days": 30,
        "alerts_days": 90,
        "incidents_days": 365,
        "interval_hours": 24,
    },
    "monitoring": {
        "enabled": True,
        "interval_seconds": 5,
        "max_events_per_poll": 50,
        "windows_event_logs": ["System", "Application", "Security"],
        "files": [],
        "read_from_beginning": False,
    },
    "alerting": {
        "email": {"enabled": False, "min_severity": "high"},
        "logfile": {"enabled": True, "path": "logs/alerts.log", "min_severity": "medium"},
        "rate_limit": {"max_per_minute": 60},
        "dedup_window_seconds": 300,
    },
    "soar": {"enabled": True},
    "web": {
        "host": "127.0.0.1",
        "port": 5000,
        "secret_key": "CHANGE_ME_IN_PRODUCTION",
        "session_timeout_minutes": 30,
        "debug": False,
        "csrf_enabled": True,
        "socketio_cors": "http://127.0.0.1",
        "cookie_secure": False,
        "workers": 1,
        "threads": 8,
    },
}


@dataclass
class FirstRunResult:
    """Details of a completed first-run bootstrap."""

    data_root: Path
    admin_username: Optional[str] = None
    admin_password: Optional[str] = None

    @property
    def admin_created(self) -> bool:
        return bool(self.admin_username and self.admin_password)


def _yaml():
    import yaml

    return yaml


def _database_file(root: Path) -> Path:
    return root / "data" / "siem.db"


def _seed_config(root: Path) -> None:
    target = paths.config_dir() / "config.yaml"
    if target.exists():
        return

    bundled = paths.bundled_config_dir() / "config.yaml"
    if bundled.exists():
        text = bundled.read_text(encoding="utf-8")
        data = _yaml().safe_load(text) or {}
    else:
        data = dict(_FALLBACK_CONFIG)

    db_path = _database_file(root)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("database", {})
    data["database"]["url"] = f"sqlite:///{db_path.as_posix()}"

    web = data.setdefault("web", {})
    web["host"] = "127.0.0.1"

    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        _yaml().safe_dump(data, f, sort_keys=False, allow_unicode=True)
    log.info("Seeded configuration at %s", target)


def _seed_logging(root: Path) -> None:
    target = paths.config_dir() / "logging.yaml"
    if target.exists():
        return
    bundled = paths.bundled_config_dir() / "logging.yaml"
    if bundled.exists():
        shutil.copyfile(bundled, target)
        return
    # Minimal fallback; absolute paths are resolved by siem.core.logger.
    target.write_text(
        "version: 1\n"
        "disable_existing_loggers: false\n"
        "formatters:\n"
        "  standard:\n"
        '    format: "%(asctime)s [%(levelname)s] %(name)s: %(message)s"\n'
        "handlers:\n"
        "  file:\n"
        "    class: logging.handlers.RotatingFileHandler\n"
        "    level: DEBUG\n"
        "    formatter: standard\n"
        '    filename: "logs/siem.log"\n'
        "    maxBytes: 104857600\n"
        "    backupCount: 5\n"
        "    encoding: utf-8\n"
        "root:\n"
        "  level: INFO\n"
        "  handlers: [file]\n"
        "loggers:\n"
        "  siem:\n"
        "    level: INFO\n"
        "    handlers: [file]\n"
        "    propagate: false\n",
        encoding="utf-8",
    )


def _seed_rules(root: Path) -> None:
    """Copy bundled built-in rules; replace them when the app version changes."""
    from siem import version as version_mod

    bundled = paths.bundled_rules_dir()
    if not bundled.exists():
        return

    target = paths.rules_dir() / "builtin"
    marker = paths.rules_dir() / ".bundled-version"
    current = version_mod.__version__
    source = bundled / "builtin"

    # In a source checkout the bundled rules are the data-root rules; there is
    # nothing to copy.
    if source.resolve() == target.resolve():
        return

    installed = marker.read_text(encoding="utf-8").strip() if marker.exists() else ""
    populated = target.exists() and any(target.iterdir())
    if populated and (not paths.is_frozen() or installed == current):
        # Never overwrite a developer's checkout; in a frozen bundle refresh
        # built-ins only when the app version changes.
        return

    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    if source.exists():
        shutil.copytree(source, target)
    marker.write_text(current, encoding="utf-8")
    log.info("Seeded built-in rules (version %s) at %s", current, target)


def _seed_playbooks(_root: Path) -> None:
    """Copy the bundled SOAR playbooks into the writable data root."""
    target = paths.config_dir() / "playbooks.yaml"
    if target.exists():
        return

    bundled = paths.bundled_config_dir() / "playbooks.yaml"
    if not bundled.exists() or bundled.resolve() == target.resolve():
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundled, target)
    log.info("Seeded SOAR playbooks at %s", target)


def _write_env(root: Path, secret_key: str) -> None:
    env_file = root / ".env"
    wanted = {
        "SIEM_HOME": str(root),
        "SIEM_CONFIG": str(paths.default_config_path()),
        "SIEM_SECRET_KEY": secret_key,
        "SIEM_COOKIE_SECURE": "false",
    }

    existing = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    lines = [line for line in existing.splitlines() if line.strip()]
    present = {
        line.split("=", 1)[0].strip()
        for line in lines
        if "=" in line and not line.lstrip().startswith("#")
    }
    for key, value in wanted.items():
        if key not in present:
            lines.append(f"{key}={value}")
    env_file.write_text("\r\n".join(lines) + "\r\n", encoding="ascii", errors="ignore")


def _existing_secret(root: Path) -> str:
    """Read a previously generated SIEM_SECRET_KEY from the data root's .env."""
    env_file = root / ".env"
    if not env_file.exists():
        return ""
    try:
        from dotenv import dotenv_values

        values = dotenv_values(env_file)
    except Exception:
        return ""
    return str(values.get("SIEM_SECRET_KEY") or "")


def _generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def _ensure_admin() -> tuple[Optional[str], Optional[str]]:
    """Create an admin account on first run. Returns (username, password)."""
    from siem.storage import database
    from siem.storage.repositories import UserRepository

    database.init_engine()
    repo = UserRepository()
    if repo.list():
        return None, None

    username = os.environ.get("SIEM_ADMIN_USER", "admin")
    password = os.environ.get("SIEM_ADMIN_PASSWORD") or _generate_password()
    repo.create(username, password, role="admin")

    note = paths.data_dir() / "FIRST_RUN_ADMIN.txt"
    note.write_text(
        "SIEM administrator account (first run)\n"
        "=====================================\n"
        f"Username: {username}\n"
        f"Password: {password}\n\n"
        "Sign in to the dashboard, then change this password and delete this file.\n",
        encoding="utf-8",
    )
    try:
        os.chmod(note, 0o600)
    except OSError:
        pass
    log.info("Created first-run administrator '%s'", username)
    return username, password


def prepare_runtime() -> FirstRunResult:
    """Prepare directories, defaults, database and admin account."""
    root = paths.bootstrap_env()
    _seed_config(root)
    _seed_logging(root)
    _seed_rules(root)
    _seed_playbooks(root)

    secret_key = os.environ.get("SIEM_SECRET_KEY") or _existing_secret(root)
    if not secret_key:
        secret_key = secrets.token_hex(32)
    os.environ.setdefault("SIEM_SECRET_KEY", secret_key)
    _write_env(root, secret_key)

    # Reload the config singleton now that seeds/.env exist.
    from siem.core.config import load_config, set_config

    try:
        config = load_config()
    except Exception:
        config = load_config(paths.default_config_path())
    set_config(config)

    from siem.storage import database
    from siem.storage.bootstrap import resolve_db_file
    from siem.storage.migrations import run_migrations

    database.dispose_engine()
    db_file = resolve_db_file(config)
    run_migrations(db_file)

    username, password = _ensure_admin()
    database.dispose_engine()

    return FirstRunResult(
        data_root=root,
        admin_username=username,
        admin_password=password,
    )
