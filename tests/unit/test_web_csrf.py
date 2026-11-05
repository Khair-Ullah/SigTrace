"""CSRF protection tests (FR-59)."""


def _token(client):
    with client.session_transaction() as sess:
        return sess.get("_csrf_token")


def test_form_post_without_token_rejected(csrf_client):
    csrf_client.get("/login")  # establish a session/token
    resp = csrf_client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 400
    assert b"CSRF" in resp.data


def test_form_post_with_token_allowed(csrf_client):
    csrf_client.get("/login")
    token = _token(csrf_client)
    resp = csrf_client.post("/login", data={
        "username": "x", "password": "y", "_csrf_token": token,
    })
    assert resp.status_code == 200  # invalid creds -> login page again
    assert b"Invalid username or password" in resp.data


def test_api_post_without_token_rejected(csrf_client, web_app_csrf):
    from helpers_web import make_alert

    storage = web_app_csrf.extensions["siem_storage"]
    storage.users.create("admin", "pw", role="admin")
    storage.alerts.add(make_alert("a1"))

    csrf_client.get("/login")
    token = _token(csrf_client)
    csrf_client.post("/login", data={"username": "admin", "password": "pw",
                                     "_csrf_token": token})

    resp = csrf_client.post("/api/alerts/a1/ack", json={"acknowledged": True})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "csrf_failed"


def test_api_post_with_header_token_allowed(csrf_client, web_app_csrf):
    from helpers_web import make_alert

    storage = web_app_csrf.extensions["siem_storage"]
    storage.users.create("admin", "pw", role="admin")
    storage.alerts.add(make_alert("a1"))

    csrf_client.get("/login")
    token = _token(csrf_client)
    csrf_client.post("/login", data={"username": "admin", "password": "pw",
                                     "_csrf_token": token})

    resp = csrf_client.post("/api/alerts/a1/ack", json={"acknowledged": True},
                            headers={"X-CSRFToken": token})
    assert resp.status_code == 200
    assert resp.get_json()["acknowledged"] is True
