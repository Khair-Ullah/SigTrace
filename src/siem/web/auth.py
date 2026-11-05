"""Authentication and authorization helpers (FR-56, FR-58)."""
from __future__ import annotations

from functools import wraps

from flask import Flask, abort, jsonify, redirect, request, url_for
from flask_login import UserMixin, current_user, login_required

from siem.core.constants import ROLE_ADMIN, ROLE_ANALYST
from siem.web.deps import get_storage
from siem.web.extensions import login_manager


class AuthUser(UserMixin):
    """Flask-Login compatible view of a ``users`` row."""

    def __init__(self, user_id: int, username: str, role: str):
        self.id = str(user_id)
        self.user_id = user_id
        self.username = username
        self.role = role

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def can_edit(self) -> bool:
        return self.role in (ROLE_ADMIN, ROLE_ANALYST)


def register_auth(app: Flask) -> None:
    """Register the user loader and unauthorized handler."""

    @login_manager.user_loader
    def _load_user(user_id: str):  # noqa: ANN202
        try:
            uid = int(user_id)
        except (TypeError, ValueError):
            return None
        data = get_storage().users.get(uid)
        if not data:
            return None
        return AuthUser(data["user_id"], data["username"], data["role"])

    @login_manager.unauthorized_handler
    def _unauthorized():  # noqa: ANN202
        if request.path.startswith("/api/") or "/api/" in request.path:
            return jsonify(error="unauthorized",
                           message="Authentication required"), 401
        return redirect(url_for("auth.login", next=request.full_path))


def role_required(*roles: str):
    """Require the current user to hold one of ``roles``."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if getattr(current_user, "role", None) not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def analyst_required(view):
    """Shortcut: admin or analyst."""
    return role_required(ROLE_ADMIN, ROLE_ANALYST)(view)


def admin_required(view):
    """Shortcut: admin only."""
    return role_required(ROLE_ADMIN)(view)
