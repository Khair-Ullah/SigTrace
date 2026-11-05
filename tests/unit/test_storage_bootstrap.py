"""Tests for the frozen-safe database bootstrap helpers."""
from __future__ import annotations

from pathlib import Path

from siem.core import paths
from siem.core.config import Config
from siem.storage import bootstrap
from siem.storage.migrations import current_version


def test_resolve_relative_sqlite_url(tmp_path):
    config = Config({"database": {"url": "sqlite:///data/siem.db"}}, project_root=tmp_path)
    assert bootstrap.resolve_db_file(config) == (tmp_path / "data" / "siem.db").resolve()


def test_resolve_absolute_sqlite_url(tmp_path):
    db_file = tmp_path / "custom.db"
    config = Config(
        {"database": {"url": f"sqlite:///{db_file.as_posix()}"}},
        project_root=tmp_path,
    )
    assert bootstrap.resolve_db_file(config) == Path(db_file.as_posix())


def test_resolve_non_sqlite_falls_back_to_data_root(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_HOME", str(tmp_path / "home"))
    config = Config({"database": {"url": "postgresql://localhost/siem"}}, project_root=tmp_path)
    assert bootstrap.resolve_db_file(config) == paths.database_dir() / "siem.db"


def test_setup_database_is_idempotent(tmp_path, capsys):
    db_file = tmp_path / "nested" / "siem.db"

    assert bootstrap.setup_database(db_file) == 0
    assert db_file.is_file()
    first = current_version(db_file)
    assert first

    assert bootstrap.setup_database(db_file) == 0
    assert current_version(db_file) == first
    assert "already up to date" in capsys.readouterr().out


def test_setup_database_force_recreates(tmp_path):
    db_file = tmp_path / "siem.db"
    bootstrap.setup_database(db_file)
    db_file.write_bytes(b"not a database")

    assert bootstrap.setup_database(db_file, force=True) == 0
    assert current_version(db_file)
