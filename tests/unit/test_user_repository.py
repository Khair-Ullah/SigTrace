"""Tests for UserRepository and authentication."""
import pytest

from siem.storage.repositories import UserRepository


def test_create_and_get(session_factory):
    repo = UserRepository(session_factory)
    uid = repo.create("alice", "pw123", role="analyst")
    assert uid > 0
    user = repo.get(uid)
    assert user["username"] == "alice"
    assert user["role"] == "analyst"
    assert "password_hash" not in user


def test_get_by_username_and_duplicate(session_factory):
    import sqlalchemy.exc

    repo = UserRepository(session_factory)
    repo.create("bob", "pw")
    assert repo.get_by_username("bob")["username"] == "bob"
    assert repo.get_by_username("nope") is None
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        repo.create("bob", "other")


def test_invalid_role_rejected(session_factory):
    repo = UserRepository(session_factory)
    with pytest.raises(ValueError):
        repo.create("eve", "pw", role="superuser")


def test_authenticate_success_and_failure(session_factory):
    repo = UserRepository(session_factory)
    repo.create("carol", "hunter2", role="viewer")
    assert repo.authenticate("carol", "hunter2")["username"] == "carol"
    assert repo.authenticate("carol", "wrong") is None
    assert repo.authenticate("ghost", "hunter2") is None


def test_authenticate_updates_last_login(session_factory):
    repo = UserRepository(session_factory)
    repo.create("dan", "pw")
    assert repo.get_by_username("dan")["last_login"] is None
    repo.authenticate("dan", "pw")
    assert repo.get_by_username("dan")["last_login"] is not None


def test_set_role_and_password(session_factory):
    repo = UserRepository(session_factory)
    uid = repo.create("erin", "pw", role="viewer")
    assert repo.set_role(uid, "admin") == 1
    assert repo.get(uid)["role"] == "admin"
    with pytest.raises(ValueError):
        repo.set_role(uid, "root")

    assert repo.set_password(uid, "newpw") == 1
    assert repo.authenticate("erin", "newpw") is not None
    assert repo.authenticate("erin", "pw") is None


def test_delete_and_count(session_factory):
    repo = UserRepository(session_factory)
    uid = repo.create("frank", "pw")
    assert repo.count() == 1
    assert repo.delete(uid) == 1
    assert repo.count() == 0
