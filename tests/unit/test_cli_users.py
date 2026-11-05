"""Tests for packaged user management commands (formerly scripts/create_user.py)."""
from __future__ import annotations

import pytest

from siem.cli.commands import users
from siem.core.config import Config, set_config
from siem.storage import database


@pytest.fixture
def user_db(tmp_path):
    db_file = tmp_path / "users.db"
    config = Config(
        {
            "database": {
                "url": f"sqlite:///{db_file.as_posix()}",
                "auto_migrate": True,
            },
            "web": {"secret_key": "test"},
        },
        project_root=tmp_path,
    )
    database.dispose_engine()
    set_config(config)
    yield db_file
    database.dispose_engine()
    set_config(None)  # type: ignore[arg-type]


def test_create_and_duplicate(user_db):
    assert not users.has_users()
    assert users.create_user("admin", "secret", role="admin") == 0
    assert users.has_users()
    assert users.create_user("admin", "other", role="admin") == 1


def test_cli_create_list_and_password(user_db, capsys):
    assert users.main(["create", "--username", "alice", "--password", "pw", "--role", "analyst"]) == 0
    assert users.main(["create", "--username", "alice", "--password", "pw"]) == 1
    assert users.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "alice" in out
    assert "analyst" in out

    assert users.main(["passwd", "--username", "alice", "--password", "newpw"]) == 0
    assert users.main(["role", "--username", "alice", "--role", "admin"]) == 0
    assert users.main(["delete", "--username", "alice"]) == 0
    assert users.main(["delete", "--username", "alice"]) == 1


def test_parser_requires_password_only_when_no_console(monkeypatch):
    parser = users.build_parser()
    args = parser.parse_args(["create", "--username", "bob"])
    monkeypatch.setattr("sys.stdin", None)
    with pytest.raises(SystemExit):
        users._get_password(args)
