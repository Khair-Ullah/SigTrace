"""JSON REST API for the dashboard and external integrations (FR-57)."""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from siem.core.constants import VALID_SEVERITIES, VALID_STATUSES
from siem.web.auth import admin_required, analyst_required
from siem.web.deps import get_storage
from siem.web.params import get_bool, get_dt, get_str, page_meta, pagination
from siem.web.serializers import alert_to_dict, event_to_dict, incident_to_dict
from siem.web.stats import DashboardStats

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/health")
def health():
    return jsonify(status="ok", service="siem-web")


@bp.route("/stats")
@login_required
def stats():
    data = DashboardStats(get_storage()).summary()
    return jsonify(data)


@bp.route("/stats/timeline")
@login_required
def stats_timeline():
    hours = request.args.get("hours", "24")
    try:
        hours = max(1, min(168, int(hours)))
    except ValueError:
        hours = 24
    return jsonify(DashboardStats(get_storage()).timeline(hours=hours))


@bp.route("/alerts")
@login_required
def alerts():
    storage = get_storage()
    severity = get_str("severity")
    severity = severity if severity in VALID_SEVERITIES else None
    src_ip = get_str("src_ip")
    incident_id = get_str("incident_id")
    acknowledged = get_bool("acknowledged")
    start, end = get_dt("start"), get_dt("end")
    limit, offset, page = pagination()
    total = storage.alerts.count(severity=severity, src_ip=src_ip,
                                 incident_id=incident_id, acknowledged=acknowledged,
                                 start=start, end=end)
    rows = storage.alerts.query(severity=severity, src_ip=src_ip,
                                incident_id=incident_id, acknowledged=acknowledged,
                                start=start, end=end, limit=limit, offset=offset)
    return jsonify(items=[alert_to_dict(a) for a in rows],
                   meta=page_meta(total, limit, page))


@bp.route("/alerts/<alert_id>")
@login_required
def alert_detail(alert_id: str):
    alert = get_storage().alerts.get(alert_id)
    if alert is None:
        abort(404)
    return jsonify(alert_to_dict(alert))


@bp.route("/alerts/<alert_id>/ack", methods=["POST"])
@analyst_required
def alert_ack(alert_id: str):
    storage = get_storage()
    payload = request.get_json(silent=True) or {}
    acknowledged = payload.get("acknowledged", True)
    if request.form:
        acknowledged = request.form.get("acknowledged", "true").lower() in ("1", "true", "yes", "on")
    if storage.alerts.acknowledge(alert_id, bool(acknowledged)) == 0:
        abort(404)
    storage.audit.record("alert_ack" if acknowledged else "alert_unack",
                         details=f"alert={alert_id}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    return jsonify(ok=True, alert_id=alert_id, acknowledged=bool(acknowledged))


@bp.route("/incidents")
@login_required
def incidents():
    storage = get_storage()
    status = get_str("status")
    status = status if status in VALID_STATUSES else None
    severity = get_str("severity")
    severity = severity if severity in VALID_SEVERITIES else None
    limit, offset, page = pagination()
    total = storage.incidents.count(status=status, severity=severity)
    rows = storage.incidents.query(
        status=status, severity=severity, src_ip=get_str("src_ip"),
        user_name=get_str("user_name"), start=get_dt("start"), end=get_dt("end"),
        limit=limit, offset=offset,
    )
    return jsonify(items=[incident_to_dict(i) for i in rows],
                   meta=page_meta(total, limit, page))


@bp.route("/incidents/<incident_id>")
@login_required
def incident_detail(incident_id: str):
    storage = get_storage()
    incident = storage.incidents.get(incident_id)
    if incident is None:
        abort(404)
    alerts = storage.alerts.query(incident_id=incident_id, limit=200)
    data = incident_to_dict(incident)
    data["alerts"] = [alert_to_dict(a) for a in alerts]
    return jsonify(data)


@bp.route("/incidents/<incident_id>/status", methods=["POST"])
@analyst_required
def incident_status(incident_id: str):
    storage = get_storage()
    payload = request.get_json(silent=True) or {}
    status = payload.get("status") or request.form.get("status")
    if status not in VALID_STATUSES:
        abort(400)
    if storage.incidents.update_status(incident_id, status) == 0:
        abort(404)
    storage.audit.record("incident_status", details=f"incident={incident_id} status={status}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    return jsonify(ok=True, incident_id=incident_id, status=status)


@bp.route("/events")
@login_required
def events():
    storage = get_storage()
    severity = get_str("severity")
    severity = severity if severity in VALID_SEVERITIES else None
    limit, offset, page = pagination()
    kwargs = dict(
        src_ip=get_str("src_ip"), dst_ip=get_str("dst_ip"),
        event_type=get_str("event_type"), severity=severity,
        source_id=get_str("source_id"), user_name=get_str("user_name"),
        message_contains=get_str("q"),
        start=get_dt("start"), end=get_dt("end"),
    )
    total = storage.events.count(
        src_ip=kwargs["src_ip"], event_type=kwargs["event_type"],
        severity=severity, source_id=kwargs["source_id"],
        start=kwargs["start"], end=kwargs["end"],
    )
    rows = storage.events.query(**kwargs, limit=limit, offset=offset)
    return jsonify(items=[event_to_dict(e) for e in rows],
                   meta=page_meta(total, limit, page))


@bp.route("/rules")
@login_required
def rules():
    return jsonify(items=get_storage().rules.list())


@bp.route("/rules/<rule_id>/toggle", methods=["POST"])
@admin_required
def rule_toggle(rule_id: str):
    storage = get_storage()
    existing = storage.rules.get(rule_id)
    if existing is None:
        abort(404)
    payload = request.get_json(silent=True) or {}
    enabled = payload.get("is_enabled")
    if enabled is None:
        enabled = not existing["is_enabled"]
    storage.rules.set_enabled(rule_id, bool(enabled))
    storage.audit.record("rule_toggle", details=f"rule={rule_id} enabled={enabled}",
                         user_id=current_user.user_id, ip_address=request.remote_addr)
    return jsonify(ok=True, rule_id=rule_id, is_enabled=bool(enabled))


@bp.route("/notifications")
@login_required
def notifications():
    storage = get_storage()
    limit, offset, page = pagination()
    rows = storage.notifications.query(
        channel=get_str("channel"), status=get_str("status"),
        alert_id=get_str("alert_id"), incident_id=get_str("incident_id"),
        limit=limit, offset=offset,
    )
    total = storage.notifications.count(channel=get_str("channel"), status=get_str("status"))
    return jsonify(items=rows, meta=page_meta(total, limit, page))
