"""Realtime alert push over SocketIO (FR-49, FR-51).

The ingestion/alerting pipeline calls :func:`push_alert` (directly or via the
:func:`make_socketio_callback` callback compatible with ``CallbackNotifier``) to
stream new alerts and incidents to connected dashboards.
"""
from __future__ import annotations

from flask import Flask, request

from siem.core.logger import get_logger
from siem.engine.models import Alert, Incident
from siem.web.extensions import socketio
from siem.web.serializers import alert_to_dict, incident_to_dict

log = get_logger("web.realtime")

NAMESPACE = "/realtime"


def alert_payload(alert: Alert, incident: Incident | None = None) -> dict:
    return {
        "alert": alert_to_dict(alert),
        "incident": incident_to_dict(incident) if incident is not None else None,
    }


def push_alert(alert: Alert, incident: Incident | None = None) -> None:
    """Emit a new alert (and optional incident) to all dashboards."""
    try:
        socketio.emit("alert", alert_payload(alert, incident), namespace=NAMESPACE)
    except Exception:  # never let a transport error break the pipeline
        log.exception("Failed to push realtime alert %s", alert.alert_id)


def push_incident(incident: Incident) -> None:
    try:
        socketio.emit("incident", incident_to_dict(incident), namespace=NAMESPACE)
    except Exception:
        log.exception("Failed to push realtime incident %s", incident.incident_id)


def make_socketio_callback():
    """Return a ``(alert, incident) -> None`` callback for CallbackNotifier."""

    def _callback(alert: Alert, incident: Incident | None = None) -> None:
        push_alert(alert, incident)
        if incident is not None:
            push_incident(incident)

    return _callback


def init_realtime(app: Flask) -> None:
    """Attach the SocketIO server to the Flask app and register handlers."""
    socketio.init_app(
        app,
        async_mode="threading",
        cors_allowed_origins=app.config.get("SOCKETIO_CORS", "*"),
        logger=False,
        engineio_logger=False,
    )

    @socketio.on("connect", namespace=NAMESPACE)
    def _on_connect(auth=None):  # noqa: ANN001
        log.debug("Realtime client connected from %s", request.remote_addr)
        socketio.emit("connected", {"namespace": NAMESPACE}, namespace=NAMESPACE)

    @socketio.on("disconnect", namespace=NAMESPACE)
    def _on_disconnect(reason=None):  # noqa: ANN001
        log.debug("Realtime client disconnected: %s", reason)

    app.extensions["siem_realtime"] = True
