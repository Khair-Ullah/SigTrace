"""Flask application factory (FR-55, FR-58)."""
from __future__ import annotations

import secrets
import socket
import threading
from datetime import datetime, timedelta

from flask import Flask, render_template

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.storage.service import StorageService
from siem.version import __version__
from siem.web.auth import register_auth
from siem.web.extensions import login_manager, socketio
from siem.web.realtime import init_realtime
from siem.web.routes import register_blueprints
from siem.web.security import init_csrf

log = get_logger("web.app")

_DEFAULT_SECRET = "CHANGE_ME_IN_PRODUCTION"


def create_app(
    config: Config | None = None,
    storage: StorageService | None = None,
) -> Flask:
    """Build and configure the Flask dashboard application."""
    config = config or get_config()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static",
    )

    secret = config.get("web.secret_key")
    if not secret or secret == _DEFAULT_SECRET:
        # Never ship a publicly-known static secret. Generate an ephemeral key
        # so sessions are at least signed with a random value (sessions reset
        # on restart; set SIEM_SECRET_KEY for a stable, production key).
        secret = secrets.token_hex(32)
        log.warning(
            "web.secret_key not set (or still the default) - generated an "
            "ephemeral key for this process. Set SIEM_SECRET_KEY before "
            "production use; existing sessions reset on restart."
        )
    app.secret_key = secret
    cookie_secure = bool(config.get("web.cookie_secure", False))
    app.config.update(
        CSRF_ENABLED=config.get("web.csrf_enabled", True),
        SESSION_TIMEOUT_MINUTES=int(config.get("web.session_timeout_minutes", 30)),
        SOCKETIO_CORS=config.get("web.socketio_cors", "*"),
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=int(config.get("web.session_timeout_minutes", 30))
        ),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure,
        SIEM_VERSION=__version__,
        SIEM_APP_NAME=config.get("system.name", "SIEM Log Correlator"),
    )

    # Storage: use the supplied service, or build one on the global engine.
    if storage is None:
        from siem.storage import database

        database.init_engine()
        storage = StorageService()
    app.extensions["siem_storage"] = storage
    app.extensions["siem_config"] = config

    login_manager.init_app(app)
    register_auth(app)
    init_csrf(app)
    init_realtime(app)
    _init_monitor(app, config, storage)
    register_blueprints(app)
    _register_template_globals(app)
    _register_error_handlers(app)

    log.info("Web application created (version %s)", __version__)
    return app


def _init_monitor(app: Flask, config: Config, storage: StorageService) -> None:
    """Create the interactive local-log Monitor bound to this app."""
    from siem.monitoring import SystemMonitor
    from siem.web.realtime import make_socketio_callback

    monitor = SystemMonitor(config, storage, on_alert=make_socketio_callback())
    app.extensions["siem_monitor"] = monitor
    log.info("Local-log Monitor initialised (%d source(s))",
             len(monitor.collectors))


def _register_template_globals(app: Flask) -> None:
    @app.context_processor
    def _inject_globals():  # noqa: ANN202
        return {
            "app_name": app.config.get("SIEM_APP_NAME"),
            "app_version": app.config.get("SIEM_VERSION"),
        }

    @app.template_filter("dt")
    def _fmt_dt(value):  # noqa: ANN001
        if not value:
            return "-"
        if isinstance(value, datetime):
            return value.replace(microsecond=0).isoformat(sep=" ")[:19]
        try:
            return str(value).replace("T", " ")[:19]
        except Exception:  # pragma: no cover - defensive
            return value

    @app.template_global()
    def severity_class(severity: str) -> str:
        return _SEVERITY_CLASSES.get(
            severity, "bg-slate-700 text-slate-200"
        )

    @app.template_global()
    def status_class(status: str) -> str:
        return _STATUS_CLASSES.get(status, "bg-slate-700 text-slate-200")


_SEVERITY_CLASSES = {
    "low": "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
    "medium": "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
    "high": "bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30",
    "critical": "bg-red-500/20 text-red-300 ring-1 ring-red-500/40",
}

_STATUS_CLASSES = {
    "open": "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
    "investigating": "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
    "closed": "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
}


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def _forbidden(_e):  # noqa: ANN202
        return render_template("error.html", code=403,
                               message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def _not_found(_e):  # noqa: ANN202
        return render_template("error.html", code=404,
                               message="The page or record was not found."), 404

    @app.errorhandler(500)
    def _server_error(_e):  # noqa: ANN202
        return render_template("error.html", code=500,
                               message="An internal server error occurred."), 500


def run_server(config: Config | None = None, host: str | None = None,
               port: int | None = None, debug: bool | None = None,
               app: Flask | None = None) -> None:
    """Create the app and start the SocketIO/Flask development server."""
    config = config or get_config()
    app = app or create_app(config)
    host = host or config.get("web.host", "0.0.0.0")
    port = port or int(config.get("web.port", 5000))
    debug = config.get("web.debug", False) if debug is None else debug
    log.info("Starting web dashboard on http://%s:%s", host, port)
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


def find_free_port(host: str = "127.0.0.1") -> int:
    """Return an ephemeral TCP port that is currently free on ``host``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def start_server_thread(
    app: Flask,
    host: str = "127.0.0.1",
    port: int | None = None,
    threads: int = 8,
):
    """Serve ``app`` with waitress on a background thread.

    Returns ``(server, thread, port)``. Unlike the Werkzeug development server,
    waitress can be started and stopped reliably from a thread, which is what
    the desktop shell needs. Flask-SocketIO's threaded middleware keeps working
    over HTTP long-polling (waitress does not provide WebSocket upgrades).
    """
    from waitress.server import create_server

    port = int(port or find_free_port(host))
    server = create_server(app, host=host, port=port, threads=threads)
    thread = threading.Thread(target=server.run, name="siem-waitress", daemon=True)
    thread.start()
    log.info("Dashboard server thread started on http://%s:%s", host, port)
    return server, thread, port
