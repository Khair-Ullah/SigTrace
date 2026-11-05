"""CSRF protection (FR-59).

A lightweight, session-backed token scheme (no Flask-WTF dependency). Tokens
are exposed to templates via the ``csrf_token()`` global and validated on every
unsafe request. API clients send the token via the ``X-CSRFToken`` header.
"""
from __future__ import annotations

import secrets

from flask import Flask, jsonify, request, session

CSRF_SESSION_KEY = "_csrf_token"
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def generate_csrf_token() -> str:
    """Return the current session's CSRF token, creating one if needed."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _submitted_token() -> str | None:
    token = request.form.get("_csrf_token")
    if token:
        return token
    token = request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")
    if token:
        return token
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if isinstance(data, dict):
            return data.get("_csrf_token")
    return None


def init_csrf(app: Flask) -> None:
    """Register the CSRF before-request hook and template global."""

    @app.before_request
    def _csrf_protect():  # pragma: no cover - exercised via integration tests
        if not app.config.get("CSRF_ENABLED", True):
            return None
        if request.method not in _UNSAFE_METHODS:
            return None
        if request.path == "/api/ingest":
            # Agent ingestion uses Bearer-token auth, not session cookies.
            return None
        expected = session.get(CSRF_SESSION_KEY)
        submitted = _submitted_token()
        if not expected or not submitted or not secrets.compare_digest(submitted, expected):
            if request.path.startswith("/api/"):
                return jsonify(error="csrf_failed",
                               message="Missing or invalid CSRF token"), 400
            return "CSRF validation failed", 400
        return None

    app.jinja_env.globals["csrf_token"] = generate_csrf_token
