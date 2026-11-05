"""Realtime SocketIO alert push tests (FR-49, FR-51)."""
from helpers_web import make_alert, make_incident
from siem.web import realtime
from siem.web.extensions import socketio


def _socket_client(app):
    return socketio.test_client(app, namespace=realtime.NAMESPACE)


def test_client_connects(web_app):
    sc = _socket_client(web_app)
    assert sc.is_connected(realtime.NAMESPACE)
    sc.disconnect(realtime.NAMESPACE)


def test_push_alert_emits(web_app):
    sc = _socket_client(web_app)
    realtime.push_alert(make_alert("a1", rule_name="Brute Force"))
    received = sc.get_received(realtime.NAMESPACE)
    names = [m["name"] for m in received]
    assert "alert" in names
    alert_msg = next(m for m in received if m["name"] == "alert")
    assert alert_msg["args"][0]["alert"]["alert_id"] == "a1"
    sc.disconnect(realtime.NAMESPACE)


def test_push_alert_includes_incident(web_app):
    sc = _socket_client(web_app)
    realtime.push_alert(make_alert("a1"), make_incident("INC-1"))
    received = sc.get_received(realtime.NAMESPACE)
    payload = next(m for m in received if m["name"] == "alert")["args"][0]
    assert payload["incident"]["incident_id"] == "INC-1"
    sc.disconnect(realtime.NAMESPACE)


def test_socketio_callback_bridge(web_app):
    sc = _socket_client(web_app)
    callback = realtime.make_socketio_callback()
    callback(make_alert("a1"), make_incident("INC-1"))
    received = sc.get_received(realtime.NAMESPACE)
    names = {m["name"] for m in received}
    assert {"alert", "incident"} <= names
    sc.disconnect(realtime.NAMESPACE)
