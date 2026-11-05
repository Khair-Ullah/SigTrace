"""Flask web dashboard (FR-55..FR-60)."""
from siem.web.app import create_app, run_server
from siem.web.extensions import socketio

__all__ = ["create_app", "run_server", "socketio"]
