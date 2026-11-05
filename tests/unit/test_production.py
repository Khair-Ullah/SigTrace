"""Tests for production-hardening features (Phase 10)."""
from __future__ import annotations

from pathlib import Path

import pytest

from siem.core.config import Config


def _config(project_root: Path, **web_overrides):
    web = {
        "host": "127.0.0.1",
        "port": 5000,
        "secret_key": "a-strong-static-key",
        "session_timeout_minutes": 30,
        "debug": False,
        "csrf_enabled": False,
        "socketio_cors": "*",
        "cookie_secure": False,
        "workers": 1,
        "threads": 8,
    }
    web.update(web_overrides)
    return Config(
        {
            "system": {"name": "SIEM Log Correlator", "version": "1.0.0"},
            "retention": {"interval_hours": 0},
            "web": web,
        },
        project_root=project_root,
    )


def test_session_cookie_flags(tmp_path, session_factory):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    config = _config(tmp_path, cookie_secure=True)
    storage = StorageService(session_factory=session_factory, config=config)
    app = create_app(config, storage=storage)

    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_default_secret_key_is_replaced(tmp_path, session_factory):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    config = _config(tmp_path, secret_key="CHANGE_ME_IN_PRODUCTION")
    storage = StorageService(session_factory=session_factory, config=config)
    app = create_app(config, storage=storage)

    assert app.secret_key not in (None, "", "CHANGE_ME_IN_PRODUCTION")
    assert len(app.secret_key) >= 32


def test_retention_scheduler_disabled_when_zero(session_factory):
    from siem.pipeline import Pipeline

    config = _config(Path("."), )
    pipeline = Pipeline(config, storage=None, persist=False)
    pipeline._maybe_start_retention()
    assert pipeline._retention_thread is None


def test_retention_scheduler_starts_when_enabled(session_factory):
    from siem.storage.service import StorageService
    from siem.pipeline import Pipeline

    config = Config(
        {
            "system": {"name": "x", "version": "1"},
            "retention": {"interval_hours": 99, "events_days": 1,
                          "alerts_days": 1, "incidents_days": 1},
        },
        project_root=Path("."),
    )
    storage = StorageService(session_factory=session_factory, config=config)
    pipeline = Pipeline(config, storage=storage)
    pipeline._maybe_start_retention()
    assert pipeline._retention_thread is not None
    pipeline._stop.set()
    pipeline._retention_thread.join(timeout=2)


def test_notify_test_command_returns_status(tmp_path, session_factory):
    from argparse import Namespace

    from siem.cli.commands.notify import cmd_notify_test

    config = _config(
        tmp_path,
        secret_key="s",
    )
    # Enable the logfile notifier so at least one channel delivers.
    config._data["alerting"] = {
        "logfile": {"enabled": True, "path": str(tmp_path / "alerts.log"),
                    "min_severity": "low"},
        "email": {"enabled": False},
        "rate_limit": {"max_per_minute": 100},
        "dedup_window_seconds": 0,
    }
    rc = cmd_notify_test(Namespace(severity="high"), config)
    assert rc == 0
    assert (tmp_path / "alerts.log").exists()


def test_serve_requires_gunicorn(monkeypatch, tmp_path):
    from argparse import Namespace

    from siem.cli.commands import engine as engine_cmd

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("gunicorn"):
            raise ImportError("no gunicorn")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = engine_cmd.cmd_serve(
        Namespace(host=None, port=None, workers=None, server="gunicorn"),
        _config(tmp_path),
    )
    assert rc == 1
