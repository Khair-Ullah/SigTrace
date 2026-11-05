"""JSON serialization helpers for engine models and storage rows (FR-57)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from siem.engine.models import Alert, Incident


def iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "timestamp": iso(alert.timestamp),
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "user_name": alert.user_name,
        "event_ids": list(alert.event_ids or []),
        "count": alert.count,
        "incident_id": alert.incident_id,
        "description": alert.description,
        "acknowledged": bool(alert.acknowledged),
        "rule_tags": list(alert.rule_tags or []),
        "protocol": alert.protocol,
        "direction": alert.direction,
        "in_interface": alert.in_interface,
        "out_interface": alert.out_interface,
    }


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
        "src_ip": incident.src_ip,
        "user_name": incident.user_name,
        "first_seen": iso(incident.first_seen),
        "last_seen": iso(incident.last_seen),
        "alert_count": incident.alert_count,
        "alert_ids": list(incident.alert_ids or []),
        "rule_names": sorted(incident.rule_names or []),
        "categories": sorted(incident.categories or []),
        "correlation_rule_id": incident.correlation_rule_id,
        "created_at": iso(incident.created_at),
        "updated_at": iso(incident.updated_at),
        "protocol": incident.protocol,
        "direction": incident.direction,
        "in_interface": incident.in_interface,
        "out_interface": incident.out_interface,
    }


def event_to_dict(event) -> dict[str, Any]:
    data = event.to_dict(include_extra=True)
    return data
