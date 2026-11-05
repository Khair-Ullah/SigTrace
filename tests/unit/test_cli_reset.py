"""Tests for the packaged database reset (formerly scripts/reset_fresh_db.py)."""
from __future__ import annotations

import sqlite3

import pytest

from siem.cli.commands import reset
from siem.core import config as config_mod
from siem.storage import database


@pytest.fixture
def reset_config(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEM_CONFIG", raising=False)
    monkeypatch.delenv("SIEM_HOME", raising=False)

    previous = config_mod.get_config()
    cfg = config_mod.load_config()
    cfg.set("database.url", f"sqlite:///{(tmp_path / 'reset.db').as_posix()}")
    database.dispose_engine()
    config_mod.set_config(cfg)
    yield cfg, tmp_path / "reset.db"
    database.dispose_engine()
    config_mod.set_config(previous)


def test_reset_creates_fresh_schema(reset_config):
    config, db_file = reset_config

    assert reset.reset_database(config=config) == 0
    assert db_file.is_file()

    conn = sqlite3.connect(db_file)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        conn.close()
    assert "schema_migrations" in tables
    assert "events" in tables
    assert "incidents" in tables


def test_reset_removes_existing_data(reset_config):
    config, db_file = reset_config

    assert reset.reset_database(config=config) == 0
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("CREATE TABLE reset_marker (id INTEGER)")
        conn.execute("INSERT INTO reset_marker (id) VALUES (1)")
        conn.commit()
    finally:
        conn.close()

    assert reset.reset_database(config=config) == 0

    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='reset_marker'"
        ).fetchone()
    finally:
        conn.close()
    assert row is None


def test_reset_accepts_explicit_path(reset_config, tmp_path):
    _, _ = reset_config
    target = tmp_path / "explicit.db"

    assert reset.reset_database(db_path=target) == 0
    assert target.is_file()
