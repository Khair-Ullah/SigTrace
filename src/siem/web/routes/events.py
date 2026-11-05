"""Event search view (FR-43, FR-44)."""
from __future__ import annotations

from flask import Blueprint, render_template

from siem.core.constants import VALID_SEVERITIES
from siem.web.deps import get_storage
from siem.web.params import get_dt, get_str, page_meta, pagination
from siem.web.serializers import event_to_dict

bp = Blueprint("events", __name__, url_prefix="/events")


@bp.route("/")
def index():
    storage = get_storage()
    severity = get_str("severity")
    severity = severity if severity in VALID_SEVERITIES else None
    filters = {
        "src_ip": get_str("src_ip"),
        "dst_ip": get_str("dst_ip"),
        "event_type": get_str("event_type"),
        "severity": severity,
        "source_id": get_str("source_id"),
        "user_name": get_str("user_name"),
        "message_contains": get_str("q"),
        "start": get_dt("start"),
        "end": get_dt("end"),
    }
    limit, offset, page = pagination()
    total = storage.events.count(
        src_ip=filters["src_ip"], event_type=filters["event_type"],
        severity=filters["severity"], source_id=filters["source_id"],
        start=filters["start"], end=filters["end"],
    )
    events = storage.events.query(**filters, limit=limit, offset=offset)
    return render_template(
        "events.html",
        events=[event_to_dict(e) for e in events],
        meta=page_meta(total, limit, page),
        filters=filters,
        severities=sorted(VALID_SEVERITIES),
    )
