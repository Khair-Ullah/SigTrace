"""Web authentication and authorization tests (FR-56, FR-58)."""
from helpers_web import make_alert


def test_login_page_renders(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Sign in" in resp.data


def test_protected_route_redirects_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_api_requires_auth_returns_401(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_login_success(auth_client):
    resp = auth_client.get("/")
    assert resp.status_code == 200


def test_login_failure(client, admin_user):
    resp = client.post("/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_authenticated_login_page_redirects(auth_client):
    resp = auth_client.get("/login")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_logout(auth_client):
    resp = auth_client.post("/logout")
    assert resp.status_code == 302
    assert auth_client.get("/").status_code == 302


def test_audit_log_records_login(web_app, client, admin_user):
    client.post("/login", data=admin_user)
    actions = [r["action"] for r in web_app.extensions["siem_storage"].audit.recent()]
    assert "login" in actions


def test_audit_log_records_failed_login(web_app, client, admin_user):
    client.post("/login", data={"username": "admin", "password": "bad"})
    actions = [r["action"] for r in web_app.extensions["siem_storage"].audit.recent()]
    assert "login_failed" in actions


def test_open_redirect_blocked(client, admin_user):
    resp = client.post("/login", data={**admin_user, "next": "//evil.example.com"})
    assert resp.status_code == 302
    # unsafe target ignored -> dashboard
    assert "evil.example.com" not in resp.headers["Location"]


def test_analyst_forbidden_from_settings(web_app, client):
    web_app.extensions["siem_storage"].users.create("analyst", "pw", role="analyst")
    client.post("/login", data={"username": "analyst", "password": "pw"})
    resp = client.get("/settings/")
    assert resp.status_code == 403


def test_viewer_cannot_acknowledge(web_app, client):
    storage = web_app.extensions["siem_storage"]
    storage.users.create("viewer", "pw", role="viewer")
    storage.alerts.add(make_alert("a1"))
    client.post("/login", data={"username": "viewer", "password": "pw"})
    resp = client.post("/alerts/a1/ack")
    assert resp.status_code == 403


def test_stale_session_user_is_logged_out(web_app):
    client = web_app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = "99999"
        sess["_fresh"] = True
    resp = client.get("/")
    assert resp.status_code == 302  # bounced back to login
