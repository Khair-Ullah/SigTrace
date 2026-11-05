"""Security helpers: password hashing (FR-56).

Kept dependency-light (werkzeug, already required by Flask) so both the web
layer, the CLI and setup scripts can use it without importing Flask itself.
"""
from __future__ import annotations

from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password: str) -> str:
    """Return a salted hash suitable for storage in ``users.password_hash``."""
    if not password:
        raise ValueError("password must not be empty")
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification of a plaintext password against a hash."""
    if not password or not password_hash:
        return False
    return check_password_hash(password_hash, password)
