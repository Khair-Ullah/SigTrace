"""REST API tests (FR-57)."""
from helpers_web import make_alert, make_event, make_incident, make_rule


def test_health_no_auth(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_stats(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.alerts.add(make_alert("a1"))
    data = auth_client.get("/api/stats").get_json()
    assert data["alerts"] == 1
    assert set(data["severity"]) == {"low", "medium", "high", "critical"}


def test_timeline(auth_client):
    data = auth_client.get("/api/stats/timeline?hours=6").get_json()
    assert isinstance(data, list) and len(data) == 6


def test_alerts_list_and_filters(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.alerts.add(make_alert("a1", severity="high", src_ip="1.1.1.1"))
    storage.alerts.add(make_alert("a2", severity="low", src_ip="2.2.2.2"))

    all_alerts = auth_client.get("/api/alerts").get_json()
    assert len(all_alerts["items"]) == 2
    assert all_alerts["meta"]["total"] == 2

    high = auth_client.get("/api/alerts?severity=high").get_json()
    assert len(high["items"]) == 1
    assert high["items"][0]["alert_id"] == "a1"


def test_alert_detail_and_404(auth_client, web_app):
    web_app.extensions["siem_storage"].alerts.add(make_alert("a1"))
    assert auth_client.get("/api/alerts/a1").get_json()["alert_id"] == "a1"
    assert auth_client.get("/api/alerts/missing").status_code == 404


def test_alert_ack(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.alerts.add(make_alert("a1"))
    resp = auth_client.post("/api/alerts/a1/ack", json={"acknowledged": True})
    assert resp.get_json()["acknowledged"] is True
    assert storage.alerts.get("a1").acknowledged is True


def test_incidents_list_and_detail(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.incidents.upsert(make_incident("INC-1"))
    storage.alerts.add(make_alert("a1", incident_id="INC-1"))

    listing = auth_client.get("/api/incidents").get_json()
    assert listing["meta"]["total"] == 1

    detail = auth_client.get("/api/incidents/INC-1").get_json()
    assert detail["incident_id"] == "INC-1"
    assert len(detail["alerts"]) == 1


def test_incident_status_update(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.incidents.upsert(make_incident("INC-1"))
    resp = auth_client.post("/api/incidents/INC-1/status", json={"status": "closed"})
    assert resp.get_json()["status"] == "closed"
    assert storage.incidents.get("INC-1").status == "closed"


def test_incident_status_invalid(auth_client, web_app):
    web_app.extensions["siem_storage"].incidents.upsert(make_incident("INC-1"))
    resp = auth_client.post("/api/incidents/INC-1/status", json={"status": "bogus"})
    assert resp.status_code == 400


def test_events(auth_client, web_app):
    web_app.extensions["siem_storage"].events.add(make_event("e1", src_ip="9.9.9.9"))
    data = auth_client.get("/api/events?src_ip=9.9.9.9").get_json()
    assert data["meta"]["total"] == 1


def test_rules_and_toggle_admin(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.rules.sync([make_rule("r1")])
    listing = auth_client.get("/api/rules").get_json()
    assert listing["items"][0]["rule_id"] == "r1"

    resp = auth_client.post("/api/rules/r1/toggle", json={"is_enabled": False})
    assert resp.get_json()["is_enabled"] is False
    assert storage.rules.get("r1")["is_enabled"] is False


def test_rule_toggle_forbidden_for_analyst(web_app, client):
    storage = web_app.extensions["siem_storage"]
    storage.rules.sync([make_rule("r1")])
    storage.users.create("analyst", "pw", role="analyst")
    client.post("/login", data={"username": "analyst", "password": "pw"})
    assert client.post("/api/rules/r1/toggle").status_code == 403


def test_notifications(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    from siem.alerting.notification import NotificationResult

    storage.notifications.add(NotificationResult(channel="email", status="sent",
                                                 alert_id="a1", recipients=["x@y.z"]))
    data = auth_client.get("/api/notifications").get_json()
    assert data["meta"]["total"] == 1
    assert data["items"][0]["channel"] == "email"
