"""Unit tests for the CLI commands (Phase 9)."""
from types import SimpleNamespace

import pytest

from siem.cli.commands import cmd_ingest, cmd_rules_validate, cmd_simulate
from siem.cli.main import build_parser, cli
from siem.simulators import LogSimulator


@pytest.fixture
def cli_env(tmp_path):
    """Point the global config/engine at a throwaway database, then restore."""
    from siem.core import config as config_mod
    from siem.storage import database

    previous = config_mod.get_config()
    cfg = config_mod.load_config()
    cfg.set("database.url", f"sqlite:///{(tmp_path / 'cli.db').as_posix()}")
    cfg.set("alerting.email.enabled", False)
    cfg.set("alerting.logfile.enabled", False)
    database.dispose_engine()
    config_mod.set_config(cfg)
    yield cfg
    database.dispose_engine()
    config_mod.set_config(previous)


def test_parser_has_all_commands():
    parser = build_parser()
    choices = parser._subparsers._group_actions[0].choices
    for name in ("db", "status", "run", "simulate", "ingest", "rules", "alerts",
                 "web", "user"):
        assert name in choices


def test_rules_validate_command(cli_env):
    assert cli(["rules", "validate"]) == 0


def test_rules_list_command(cli_env, capsys):
    assert cli(["rules", "list"]) == 0
    out = capsys.readouterr().out
    assert "rule" in out.lower()


def test_simulate_command(cli_env, capsys):
    args = SimpleNamespace(scenario=["multi_stage"], count=None, seed=1, write=None)
    assert cmd_simulate(args) == 0
    out = capsys.readouterr().out
    assert "Incidents: 1" in out


def test_simulate_all_scenarios(cli_env, capsys):
    args = SimpleNamespace(scenario=["all"], count=None, seed=2, write=None)
    assert cmd_simulate(args) == 0
    assert "simulated line(s)" in capsys.readouterr().out


def test_simulate_unknown_scenario(cli_env, capsys):
    args = SimpleNamespace(scenario=["nope"], count=None, seed=1, write=None)
    assert cmd_simulate(args) == 2
    assert "Unknown scenario" in capsys.readouterr().out


def test_simulate_write_file(cli_env, tmp_path, capsys):
    target = tmp_path / "generated.log"
    args = SimpleNamespace(scenario=["port_scan"], count=5, seed=1,
                           write=str(target))
    assert cmd_simulate(args) == 0
    assert target.exists()
    assert len(target.read_text(encoding="utf-8").strip().splitlines()) == 5


def test_ingest_missing_file_returns_2(tmp_path, capsys):
    args = SimpleNamespace(path=str(tmp_path / "missing.log"),
                           source_id=None, source_type="custom")
    assert cmd_ingest(args) == 2
    assert "not found" in capsys.readouterr().out


def test_ingest_file_end_to_end(cli_env, tmp_path, capsys):
    logs = LogSimulator(seed=4).generate("port_scan")
    path = tmp_path / "scan.log"
    path.write_text("\n".join(entry.raw for entry in logs), encoding="utf-8")

    args = SimpleNamespace(path=str(path), source_id="fw-01", source_type="firewall")
    assert cmd_ingest(args) == 0
    out = capsys.readouterr().out
    assert "Alerts: 1" in out


def test_no_command_prints_help(capsys):
    assert cli([]) == 0
    assert "usage" in capsys.readouterr().out.lower()
