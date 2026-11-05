"""HTML page rendering tests (FR-55)."""
from helpers_web import make_alert, make_event, make_incident, make_rule


def test_dashboard_renders(auth_client):
    resp = auth_client.get("/")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_dashboard_with_data(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.alerts.add(make_alert("a1"))
    storage.incidents.upsert(make_incident("INC-1"))
    storage.events.add(make_event("e1"))
    resp = auth_client.get("/")
    assert resp.status_code == 200
    assert b"Test Rule" in resp.data
    assert b"Multi-Stage Intrusion" in resp.data


def test_alerts_list_and_detail(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.alerts.add(make_alert("a1", rule_name="Brute Force"))
    resp = auth_client.get("/alerts/")
    assert resp.status_code == 200
    assert b"Brute Force" in resp.data

    detail = auth_client.get("/alerts/a1")
    assert detail.status_code == 200
    assert b"Alert detail" in detail.data


def test_alert_detail_404(auth_client):
    assert auth_client.get("/alerts/nope").status_code == 404


def test_incidents_list_and_detail(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.incidents.upsert(make_incident("INC-1"))
    storage.alerts.add(make_alert("a1", incident_id="INC-1"))

    resp = auth_client.get("/incidents/")
    assert resp.status_code == 200
    assert b"Multi-Stage Intrusion" in resp.data

    detail = auth_client.get("/incidents/INC-1")
    assert detail.status_code == 200
    assert b"Linked alerts" in detail.data


def test_events_page(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.events.add(make_event("e1", message="suspicious login"))
    resp = auth_client.get("/events/")
    assert resp.status_code == 200
    assert b"suspicious login" in resp.data


def test_rules_list_and_detail(auth_client, web_app):
    storage = web_app.extensions["siem_storage"]
    storage.rules.sync([make_rule("r1")])
    resp = auth_client.get("/rules/")
    assert resp.status_code == 200
    assert b"Test Rule" in resp.data

    detail = auth_client.get("/rules/r1")
    assert detail.status_code == 200
    assert b"Definition" in detail.data


def test_settings_page_admin(auth_client):
    resp = auth_client.get("/settings/")
    assert resp.status_code == 200
    assert b"Users" in resp.data
    assert b"Configuration" in resp.data


def test_404_page(auth_client):
    resp = auth_client.get("/does-not-exist")
    assert resp.status_code == 404
    assert b"404" in resp.data
