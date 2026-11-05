"""Settings & user-management views (FR-56, FR-60). Admin only."""
from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from siem.core.constants import VALID_ROLES
from siem.web.auth import admin_required
from siem.web.deps import get_siem_config, get_storage

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/")
@admin_required
def index():
    storage = get_storage()
    config = get_siem_config()
    return render_template(
        "settings.html",
        users=storage.users.list(),
        roles=sorted(VALID_ROLES),
        config_snapshot=_config_snapshot(config),
        db_config=storage.settings.all(),
    )


def _config_snapshot(config) -> dict:
    keys = [
        "system.name", "system.version", "system.log_level",
        "database.url",
        "ingestion.syslog.enabled", "ingestion.syslog.udp_port",
        "ingestion.syslog.tcp_port",
        "rules.builtin_path", "rules.custom_path", "rules.auto_reload",
        "correlation.window_seconds", "correlation.min_alerts_for_incident",
        "retention.events_days", "retention.alerts_days", "retention.incidents_days",
        "alerting.email.enabled", "alerting.email.min_severity",
        "alerting.logfile.enabled", "alerting.logfile.path",
        "web.host", "web.port",
    ]
    return {k: config.get(k) for k in keys}


@bp.route("/users", methods=["POST"])
@admin_required
def create_user():
    storage = get_storage()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = request.form.get("role") or "analyst"
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("settings.index"))
    if role not in VALID_ROLES:
        flash("Invalid role.", "error")
        return redirect(url_for("settings.index"))
    if storage.users.get_by_username(username) is not None:
        flash(f"User '{username}' already exists.", "error")
        return redirect(url_for("settings.index"))
    uid = storage.users.create(username, password, role=role)
    storage.audit.record("user_create", details=f"user={username} role={role}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    flash(f"User '{username}' created (#{uid}).", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def set_role(user_id: int):
    storage = get_storage()
    role = (request.form.get("role") or "").strip()
    if role not in VALID_ROLES:
        abort(400)
    if user_id == current_user.user_id and role != "admin":
        flash("You cannot remove your own admin role.", "error")
        return redirect(url_for("settings.index"))
    if storage.users.set_role(user_id, role) == 0:
        abort(404)
    storage.audit.record("user_role", details=f"user_id={user_id} role={role}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    flash("Role updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/password", methods=["POST"])
@admin_required
def reset_password(user_id: int):
    storage = get_storage()
    password = request.form.get("password") or ""
    if not password:
        flash("Password is required.", "error")
        return redirect(url_for("settings.index"))
    if storage.users.set_password(user_id, password) == 0:
        abort(404)
    storage.audit.record("user_password", details=f"user_id={user_id}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    flash("Password updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    storage = get_storage()
    if user_id == current_user.user_id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("settings.index"))
    if storage.users.delete(user_id) == 0:
        abort(404)
    storage.audit.record("user_delete", details=f"user_id={user_id}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    flash("User deleted.", "success")
    return redirect(url_for("settings.index"))
