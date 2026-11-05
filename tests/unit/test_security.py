"""Tests for password hashing helpers."""
import pytest

from siem.core.security import hash_password, verify_password


def test_hash_and_verify():
    h = hash_password("s3cret")
    assert h != "s3cret"
    assert verify_password("s3cret", h) is True
    assert verify_password("wrong", h) is False


def test_hash_is_salted():
    assert hash_password("same") != hash_password("same")


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        hash_password("")


def test_verify_handles_empty():
    assert verify_password("", "x") is False
    assert verify_password("x", "") is False
