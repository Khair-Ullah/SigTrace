"""Incident views: list, detail and status updates (FR-54)."""
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

from siem.core.constants import VALID_SEVERITIES, VALID_STATUSES
from siem.web.auth import analyst_required
from siem.web.deps import get_storage
from siem.web.params import get_dt, get_str, page_meta, pagination
from siem.web.serializers import alert_to_dict, incident_to_dict

bp = Blueprint("incidents", __name__, url_prefix="/incidents")


def _filters():
    severity = get_str("severity")
    status = get_str("status")
    return {
        "severity": severity if severity in VALID_SEVERITIES else None,
        "status": status if status in VALID_STATUSES else None,
        "src_ip": get_str("src_ip"),
        "user_name": get_str("user_name"),
        "start": get_dt("start"),
        "end": get_dt("end"),
    }


@bp.route("/")
def index():
    storage = get_storage()
    filters = _filters()
    limit, offset, page = pagination()
    total = storage.incidents.count(status=filters["status"], severity=filters["severity"])
    incidents = storage.incidents.query(**filters, limit=limit, offset=offset)
    return render_template(
        "incidents.html",
        incidents=[incident_to_dict(i) for i in incidents],
        meta=page_meta(total, limit, page),
        filters=filters,
        severities=sorted(VALID_SEVERITIES),
        statuses=sorted(VALID_STATUSES),
    )


@bp.route("/<incident_id>")
def detail(incident_id: str):
    storage = get_storage()
    incident = storage.incidents.get(incident_id)
    if incident is None:
        abort(404)
    alerts = storage.alerts.query(incident_id=incident_id, limit=200)
    return render_template(
        "incident_detail.html",
        incident=incident_to_dict(incident),
        alerts=[alert_to_dict(a) for a in alerts],
        statuses=sorted(VALID_STATUSES),
    )


@bp.route("/<incident_id>/status", methods=["POST"])
@analyst_required
def update_status(incident_id: str):
    storage = get_storage()
    status = (request.form.get("status") or "").strip()
    if status not in VALID_STATUSES:
        abort(400)
    updated = storage.incidents.update_status(incident_id, status)
    if updated == 0:
        abort(404)
    storage.audit.record(
        "incident_status", details=f"incident={incident_id} status={status}",
        user_id=current_user.user_id, ip_address=request.remote_addr,
    )
    if request.headers.get("Accept") == "application/json" or request.is_json:
        return jsonify(ok=True, incident_id=incident_id, status=status)
    flash(f"Incident marked as {status}.", "success")
    return redirect(url_for("incidents.detail", incident_id=incident_id))
