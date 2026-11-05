"""Alert views: list, detail and acknowledgement (FR-53)."""
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

from siem.core.constants import VALID_SEVERITIES
from siem.web.auth import analyst_required
from siem.web.deps import get_storage
from siem.web.params import get_bool, get_dt, get_str, page_meta, pagination
from siem.web.serializers import alert_to_dict

bp = Blueprint("alerts", __name__, url_prefix="/alerts")


def _query_args():
    severity = get_str("severity")
    if severity not in VALID_SEVERITIES:
        severity = None
    return {
        "severity": severity,
        "src_ip": get_str("src_ip"),
        "incident_id": get_str("incident_id"),
        "acknowledged": get_bool("acknowledged"),
        "start": get_dt("start"),
        "end": get_dt("end"),
    }


@bp.route("/")
def index():
    storage = get_storage()
    filters = _query_args()
    limit, offset, page = pagination()
    total = storage.alerts.count(
        severity=filters["severity"], src_ip=filters["src_ip"],
        incident_id=filters["incident_id"], acknowledged=filters["acknowledged"],
        start=filters["start"], end=filters["end"],
    )
    alerts = storage.alerts.query(
        **filters, limit=limit, offset=offset,
    )
    return render_template(
        "alerts.html",
        alerts=[alert_to_dict(a) for a in alerts],
        meta=page_meta(total, limit, page),
        filters=filters,
        severities=sorted(VALID_SEVERITIES),
    )


@bp.route("/<alert_id>")
def detail(alert_id: str):
    storage = get_storage()
    alert = storage.alerts.get(alert_id)
    if alert is None:
        abort(404)
    incident = None
    if alert.incident_id:
        incident = storage.incidents.get(alert.incident_id)
    return render_template("alert_detail.html", alert=alert_to_dict(alert), incident=incident)


@bp.route("/<alert_id>/ack", methods=["POST"])
@analyst_required
def acknowledge(alert_id: str):
    storage = get_storage()
    acknowledged = request.form.get("acknowledged", "true").lower() in ("1", "true", "yes", "on")
    updated = storage.alerts.acknowledge(alert_id, acknowledged)
    if updated == 0:
        abort(404)
    storage.audit.record(
        "alert_ack" if acknowledged else "alert_unack",
        details=f"alert={alert_id}",
        user_id=current_user.user_id, ip_address=request.remote_addr,
    )
    if request.headers.get("Accept") == "application/json" or request.is_json:
        return jsonify(ok=True, alert_id=alert_id, acknowledged=acknowledged)
    flash(f"Alert {'acknowledged' if acknowledged else 're-opened'}.", "success")
    return redirect(request.referrer or url_for("alerts.detail", alert_id=alert_id))
