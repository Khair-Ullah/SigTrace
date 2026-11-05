"""Interactive local-log Monitor views and API (Phase 10)."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from siem.web.auth import admin_required
from siem.web.deps import get_monitor

bp = Blueprint("monitor", __name__, url_prefix="/monitor")


@bp.route("/")
@login_required
def index():
    monitor = get_monitor()
    return render_template(
        "monitor.html",
        status=monitor.status(),
        recent=monitor.recent_events(limit=50),
        can_control=bool(getattr(current_user, "is_admin", False)),
    )


@bp.route("/api/status")
@login_required
def api_status():
    return jsonify(get_monitor().status())


@bp.route("/api/events")
@login_required
def api_events():
    try:
        limit = max(1, min(200, int(request.args.get("limit", "50"))))
    except ValueError:
        limit = 50
    return jsonify(items=get_monitor().recent_events(limit=limit))


@bp.route("/api/start", methods=["POST"])
@admin_required
def api_start():
    monitor = get_monitor()
    return jsonify(monitor.start())


@bp.route("/api/stop", methods=["POST"])
@admin_required
def api_stop():
    monitor = get_monitor()
    return jsonify(monitor.stop())


@bp.route("/api/clear", methods=["POST"])
@admin_required
def api_clear():
    monitor = get_monitor()
    monitor.clear_recent()
    return jsonify(ok=True)
