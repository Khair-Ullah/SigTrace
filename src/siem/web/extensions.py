"""Shared Flask extension singletons (FR-58).

Kept in a dedicated module so the SocketIO server can be imported by the
ingestion/alerting pipeline (to push realtime alerts) without importing the
whole application factory.
"""
from __future__ import annotations

from flask_login import LoginManager
from flask_socketio import SocketIO

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

# ``threading`` async mode works under the stdlib WSGI server used by the CLI
# without requiring eventlet/gevent.
socketio = SocketIO(async_mode="threading", cors_allowed_origins=None)
