"""Dashboard overview page (FR-55)."""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from siem.web.deps import get_storage
from siem.web.serializers import alert_to_dict, incident_to_dict
from siem.web.stats import DashboardStats

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    storage = get_storage()
    stats = DashboardStats(storage)
    return render_template(
        "dashboard.html",
        summary=stats.summary(),
        timeline=stats.timeline(hours=24),
        top_src_ips=stats.top_src_ips(limit=5),
        recent_alerts=[alert_to_dict(a) for a in storage.alerts.query(limit=8)],
        recent_incidents=[incident_to_dict(i) for i in storage.incidents.query(limit=5)],
    )
