"""Tests for source/frozen path resolution."""
from __future__ import annotations

import sys
from pathlib import Path

from siem.core import paths


def test_data_dir_uses_siem_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_HOME", str(tmp_path / "custom"))
    assert paths.data_dir() == (tmp_path / "custom").resolve()


def test_data_dir_source_checkout_is_repo_root(tmp_path, monkeypatch):
    monkeypatch.delenv("SIEM_HOME", raising=False)
    monkeypatch.setattr(paths, "is_frozen", lambda: False)
    assert paths.data_dir() == paths._DEV_PROJECT_ROOT


def test_frozen_bundle_and_data_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.delenv("SIEM_HOME", raising=False)
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)

    assert paths.bundle_dir() == tmp_path / "bundle"
    assert paths.data_dir() == tmp_path / "local" / "SIEM"


def test_frozen_without_meipass_uses_executable_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(sys, "_MEIPASS", None, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "SIEM.exe"), raising=False)
    assert paths.bundle_dir() == tmp_path


def test_ensure_layout_creates_directories(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_HOME", str(tmp_path / "home"))
    root = paths.ensure_layout()

    assert root == (tmp_path / "home").resolve()
    for relative in ("config", "logs", "data", "rules", "rules/builtin", "rules/custom"):
        assert (root / relative).is_dir()


def test_bootstrap_env_sets_home_and_config(tmp_path, monkeypatch):
    import os

    monkeypatch.setenv("SIEM_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIEM_CONFIG", raising=False)

    try:
        root = paths.bootstrap_env()
        config_file = root / "config" / "config.yaml"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("system: {}\n", encoding="utf-8")

        paths.bootstrap_env()

        assert os.environ["SIEM_HOME"] == str(root)
        assert Path(os.environ["SIEM_CONFIG"]) == config_file
    finally:
        os.environ.pop("SIEM_CONFIG", None)


def test_path_helpers_follow_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_HOME", str(tmp_path / "home"))
    root = paths.data_dir()

    assert paths.config_dir() == root / "config"
    assert paths.logs_dir() == root / "logs"
    assert paths.rules_dir() == root / "rules"
    assert paths.database_dir() == root / "data"
    assert paths.default_config_path() == root / "config" / "config.yaml"
    assert paths.project_root() == root
