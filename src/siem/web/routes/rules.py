"""Rule management views (FR-55)."""
from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from siem.web.auth import admin_required
from siem.web.deps import get_storage

bp = Blueprint("rules", __name__, url_prefix="/rules")


@bp.route("/")
def index():
    storage = get_storage()
    rules = storage.rules.list()
    return render_template("rules.html", rules=rules)


@bp.route("/<rule_id>")
def detail(rule_id: str):
    storage = get_storage()
    rule = storage.rules.get(rule_id)
    if rule is None:
        abort(404)
    return render_template("rule_detail.html", rule=rule)


@bp.route("/<rule_id>/toggle", methods=["POST"])
@admin_required
def toggle(rule_id: str):
    storage = get_storage()
    existing = storage.rules.get(rule_id)
    if existing is None:
        abort(404)
    enabled = not existing["is_enabled"]
    storage.rules.set_enabled(rule_id, enabled)
    storage.audit.record(
        "rule_toggle", details=f"rule={rule_id} enabled={enabled}",
        user_id=current_user.user_id, ip_address=request.remote_addr,
    )
    if request.headers.get("Accept") == "application/json" or request.is_json:
        return jsonify(ok=True, rule_id=rule_id, is_enabled=enabled)
    flash(f"Rule {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(request.referrer or url_for("rules.index"))
