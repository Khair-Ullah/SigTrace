"""Web blueprints."""
from __future__ import annotations

from flask import Flask


def register_blueprints(app: Flask) -> None:
    from siem.web.routes.alerts import bp as alerts_bp
    from siem.web.routes.api import bp as api_bp
    from siem.web.routes.auth import bp as auth_bp
    from siem.web.routes.dashboard import bp as dashboard_bp
    from siem.web.routes.events import bp as events_bp
    from siem.web.routes.incidents import bp as incidents_bp
    from siem.web.routes.ingest import bp as ingest_bp
    from siem.web.routes.monitor import bp as monitor_bp
    from siem.web.routes.rules import bp as rules_bp
    from siem.web.routes.settings import bp as settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ingest_bp)
