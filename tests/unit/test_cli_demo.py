"""Tests for the packaged multi-stage demo (formerly scripts/run_demo.py)."""
from __future__ import annotations

import sqlite3

import pytest

from siem.cli.commands import demo
from siem.cli.main import build_parser, cli
from siem.core import config as config_mod
from siem.storage import database


@pytest.fixture
def demo_config(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEM_CONFIG", raising=False)
    monkeypatch.delenv("SIEM_HOME", raising=False)

    previous = config_mod.get_config()
    cfg = config_mod.load_config()
    cfg.set("database.url", f"sqlite:///{(tmp_path / 'demo.db').as_posix()}")
    cfg.set("alerting.email.enabled", False)
    cfg.set("alerting.logfile.enabled", False)
    database.dispose_engine()
    config_mod.set_config(cfg)
    yield cfg
    database.dispose_engine()
    config_mod.set_config(previous)


def test_demo_dry_run_generates_critical_incident(demo_config):
    result = demo.simulate(dry_run=True, config=demo_config)

    assert len(result.events) == 27
    assert result.alerts
    assert result.incidents
    assert any(incident.severity == "critical" for incident in result.incidents)
    assert result.rules
    assert result.persisted is False
    assert result.db_path is None


def test_demo_persists_to_active_database(demo_config):
    result = demo.simulate(dry_run=False, config=demo_config)

    assert result.persisted is True
    assert result.db_path is not None
    assert result.db_path.is_file()

    conn = sqlite3.connect(result.db_path)
    try:
        for table in ("events", "alerts", "incidents", "rules"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            assert count > 0, table
    finally:
        conn.close()


def test_demo_cli_dry_run(demo_config, capsys):
    assert demo.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Dry-run complete" in out
    assert "INCIDENT" in out


def test_parser_exposes_demo_and_db_reset():
    parser = build_parser()
    choices = parser._subparsers._group_actions[0].choices
    assert "demo" in choices

    db_parser = choices["db"]
    db_choices = db_parser._subparsers._group_actions[0].choices
    assert "reset" in db_choices


def test_cli_demo_dispatch(demo_config, capsys):
    assert cli(["demo", "--dry-run"]) == 0
    assert "Dry-run complete" in capsys.readouterr().out
