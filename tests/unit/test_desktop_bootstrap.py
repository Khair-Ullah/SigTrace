"""Tests for first-run desktop bootstrap (config, rules, DB, admin)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from siem.core import paths
from siem.desktop import bootstrap


@pytest.fixture
def data_root(tmp_path, monkeypatch):
    root = tmp_path / "home"
    monkeypatch.setenv("SIEM_HOME", str(root))
    for name in (
        "SIEM_CONFIG",
        "SIEM_SECRET_KEY",
        "SIEM_ADMIN_USER",
        "SIEM_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)

    from siem.core.config import set_config
    from siem.storage import database

    database.dispose_engine()
    set_config(None)  # type: ignore[arg-type]

    yield root

    database.dispose_engine()
    set_config(None)  # type: ignore[arg-type]
    os.environ.pop("SIEM_SECRET_KEY", None)
    os.environ.pop("SIEM_CONFIG", None)


def test_prepare_runtime_seeds_everything(data_root, monkeypatch):
    monkeypatch.setenv("SIEM_ADMIN_USER", "admin")
    monkeypatch.setenv("SIEM_ADMIN_PASSWORD", "first-run-secret")

    result = bootstrap.prepare_runtime()

    assert result.data_root == data_root.resolve()
    assert result.admin_created
    assert result.admin_username == "admin"
    assert result.admin_password == "first-run-secret"

    assert (data_root / "config" / "config.yaml").is_file()
    assert (data_root / "config" / "logging.yaml").is_file()
    assert (data_root / "config" / "playbooks.yaml").is_file()
    assert (data_root / ".env").is_file()
    assert (data_root / "logs").is_dir()
    assert (data_root / "rules" / "builtin").is_dir()
    assert (data_root / "data" / "siem.db").is_file()

    note = (data_root / "FIRST_RUN_ADMIN.txt").read_text(encoding="utf-8")
    assert "Username: admin" in note
    assert "first-run-secret" in note

    from siem.core.config import get_config
    from siem.storage.repositories import UserRepository

    config = get_config()
    assert Path(config.project_root) == data_root.resolve()
    assert config.get("web.host") == "127.0.0.1"

    users = UserRepository().list()
    assert [u["username"] for u in users] == ["admin"]
    assert users[0]["role"] == "admin"


def test_prepare_runtime_is_idempotent_and_keeps_secret(data_root):
    first = bootstrap.prepare_runtime()
    first_env = (data_root / ".env").read_text(encoding="utf-8")
    first_secret = os.environ["SIEM_SECRET_KEY"]

    second = bootstrap.prepare_runtime()

    assert first.admin_created
    assert not second.admin_created
    assert (data_root / ".env").read_text(encoding="utf-8") == first_env
    assert os.environ["SIEM_SECRET_KEY"] == first_secret
    assert first_env.count("SIEM_SECRET_KEY=") == 1


def test_existing_env_secret_is_reused(data_root, monkeypatch):
    root = paths.ensure_layout()
    (root / ".env").write_text("SIEM_SECRET_KEY=keep-me\n", encoding="utf-8")
    monkeypatch.delenv("SIEM_SECRET_KEY", raising=False)

    bootstrap.prepare_runtime()

    assert os.environ["SIEM_SECRET_KEY"] == "keep-me"
    text = (root / ".env").read_text(encoding="utf-8")
    assert text.count("SIEM_SECRET_KEY=") == 1
    assert "keep-me" in text


def test_seed_config_writes_absolute_sqlite_url(data_root):
    root = paths.ensure_layout()
    bootstrap._seed_config(root)

    import yaml

    data = yaml.safe_load((root / "config" / "config.yaml").read_text(encoding="utf-8"))
    url = data["database"]["url"]
    assert url.startswith("sqlite:///")
    assert Path(url[len("sqlite:///") :]).is_absolute()
    assert url.endswith("siem.db")
    assert data["web"]["host"] == "127.0.0.1"


def test_seed_rules_refreshes_on_version_change(tmp_path, monkeypatch):
    bundled = tmp_path / "bundle" / "rules"
    (bundled / "builtin").mkdir(parents=True)
    (bundled / "builtin" / "new.yml").write_text("id: new\n", encoding="utf-8")

    rules = tmp_path / "home" / "rules"
    (rules / "builtin").mkdir(parents=True)
    (rules / "builtin" / "old.yml").write_text("id: old\n", encoding="utf-8")
    (rules / ".bundled-version").write_text("0.0.1", encoding="utf-8")

    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "bundled_rules_dir", lambda: bundled)
    monkeypatch.setattr(paths, "rules_dir", lambda: rules)

    from siem import version

    bootstrap._seed_rules(tmp_path / "home")

    assert (rules / "builtin" / "new.yml").is_file()
    assert not (rules / "builtin" / "old.yml").exists()
    marker = rules / ".bundled-version"
    assert marker.read_text(encoding="utf-8").strip() == version.__version__


def test_seed_rules_fills_empty_data_root_in_source_mode(tmp_path, monkeypatch):
    bundled = tmp_path / "bundle" / "rules"
    (bundled / "builtin").mkdir(parents=True)
    (bundled / "builtin" / "new.yml").write_text("id: new\n", encoding="utf-8")

    rules = tmp_path / "home" / "rules"
    (rules / "builtin").mkdir(parents=True)

    monkeypatch.setattr(paths, "is_frozen", lambda: False)
    monkeypatch.setattr(paths, "bundled_rules_dir", lambda: bundled)
    monkeypatch.setattr(paths, "rules_dir", lambda: rules)

    bootstrap._seed_rules(tmp_path / "home")

    assert (rules / "builtin" / "new.yml").is_file()
    marker = rules / ".bundled-version"
    assert marker.read_text(encoding="utf-8").strip()


def test_seed_rules_keeps_dev_checkout(tmp_path, monkeypatch):
    bundled = tmp_path / "bundle" / "rules"
    (bundled / "builtin").mkdir(parents=True)
    (bundled / "builtin" / "new.yml").write_text("id: new\n", encoding="utf-8")

    rules = tmp_path / "home" / "rules"
    (rules / "builtin").mkdir(parents=True)
    (rules / "builtin" / "custom.yml").write_text("id: custom\n", encoding="utf-8")
    (rules / ".bundled-version").write_text("0.0.1", encoding="utf-8")

    monkeypatch.setattr(paths, "is_frozen", lambda: False)
    monkeypatch.setattr(paths, "bundled_rules_dir", lambda: bundled)
    monkeypatch.setattr(paths, "rules_dir", lambda: rules)

    bootstrap._seed_rules(tmp_path / "home")

    assert (rules / "builtin" / "custom.yml").is_file()
    assert not (rules / "builtin" / "new.yml").exists()


def test_generated_password_shape():
    password = bootstrap._generate_password()
    assert len(password) == 20
    assert set(password) <= set(bootstrap._PASSWORD_ALPHABET)
