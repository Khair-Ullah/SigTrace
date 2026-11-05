"""Convert between engine dataclasses and SQLAlchemy ORM rows."""
from __future__ import annotations

import json

from siem.engine.models import Alert as EngineAlert
from siem.engine.models import Incident as EngineIncident
from siem.parsing.models import NormalizedEvent
from siem.storage.models import Alert as OrmAlert
from siem.storage.models import Event as OrmEvent
from siem.storage.models import Incident as OrmIncident


def _dump_list(values) -> str:
    return json.dumps(list(values or []))


def _load_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return list(data) if isinstance(data, list) else []


def _load_extra(raw: str | None) -> dict:
    """Parse the JSON ``extra`` blob back into a dict."""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return dict(data) if isinstance(data, dict) else {}


# Extended event fields stored in dedicated columns (migration 004).
_EVENT_EXTRA_COLUMNS = ("protocol", "direction", "in_interface", "out_interface")


def _split_event_extra(event: NormalizedEvent) -> tuple[dict, dict]:
    """Split ``event.extra`` into (promoted columns, remaining JSON fields)."""
    remaining = dict(event.extra or {})
    columns: dict = {}
    for key in _EVENT_EXTRA_COLUMNS:
        if key in remaining:
            value = remaining.pop(key)
            columns[key] = str(value) if value is not None else None
    return columns, remaining


def _merge_event_extra(row: OrmEvent) -> dict:
    """Rebuild the ``extra`` dict from JSON + promoted columns."""
    extra = _load_extra(row.extra)
    for key in _EVENT_EXTRA_COLUMNS:
        value = getattr(row, key, None)
        if value not in (None, ""):
            extra[key] = value
    return extra


# -- events ----------------------------------------------------------------
def event_to_orm(event: NormalizedEvent) -> OrmEvent:
    columns, rest = _split_event_extra(event)
    return OrmEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_id=event.source_id,
        source_type=event.source_type,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        user_name=event.user_name,
        action=event.action,
        event_type=event.event_type,
        severity=event.severity,
        protocol=columns.get("protocol"),
        direction=columns.get("direction"),
        in_interface=columns.get("in_interface"),
        out_interface=columns.get("out_interface"),
        extra=json.dumps(rest) if rest else None,
        message=event.message,
        raw_log=event.raw_log,
        ingested_at=event.ingested_at,
    )


def event_to_row(event: NormalizedEvent) -> dict:
    """Flat dict for bulk core-insert."""
    columns, rest = _split_event_extra(event)
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "source_id": event.source_id,
        "source_type": event.source_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "user_name": event.user_name,
        "action": event.action,
        "event_type": event.event_type,
        "severity": event.severity,
        "protocol": columns.get("protocol"),
        "direction": columns.get("direction"),
        "in_interface": columns.get("in_interface"),
        "out_interface": columns.get("out_interface"),
        "extra": json.dumps(rest) if rest else None,
        "message": event.message,
        "raw_log": event.raw_log,
        "ingested_at": event.ingested_at,
    }


def orm_to_event(row: OrmEvent) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=row.event_id,
        timestamp=row.timestamp,
        source_id=row.source_id,
        source_type=row.source_type or "",
        raw_log=row.raw_log or "",
        message=row.message or "",
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        user_name=row.user_name,
        action=row.action,
        event_type=row.event_type,
        severity=row.severity or "low",
        ingested_at=row.ingested_at,
        extra=_merge_event_extra(row),
    )


# -- alerts ----------------------------------------------------------------
def alert_to_orm(alert: EngineAlert) -> OrmAlert:
    return OrmAlert(
        alert_id=alert.alert_id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        timestamp=alert.timestamp,
        severity=alert.severity,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        user_name=alert.user_name,
        event_ids=_dump_list(alert.event_ids),
        incident_id=alert.incident_id,
        acknowledged=1 if alert.acknowledged else 0,
        count=alert.count,
        description=alert.description or None,
        rule_tags=_dump_list(alert.rule_tags),
        protocol=alert.protocol,
        direction=alert.direction,
        in_interface=alert.in_interface,
        out_interface=alert.out_interface,
    )


def alert_to_row(alert: EngineAlert) -> dict:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "timestamp": alert.timestamp,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "user_name": alert.user_name,
        "event_ids": _dump_list(alert.event_ids),
        "incident_id": alert.incident_id,
        "acknowledged": 1 if alert.acknowledged else 0,
        "count": alert.count,
        "description": alert.description or None,
        "rule_tags": _dump_list(alert.rule_tags),
        "protocol": alert.protocol,
        "direction": alert.direction,
        "in_interface": alert.in_interface,
        "out_interface": alert.out_interface,
    }


def orm_to_alert(row: OrmAlert) -> EngineAlert:
    return EngineAlert(
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        rule_name=row.rule_name or "",
        timestamp=row.timestamp,
        severity=row.severity,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        user_name=row.user_name,
        event_ids=_load_list(row.event_ids),
        count=row.count or 1,
        incident_id=row.incident_id,
        description=row.description or "",
        acknowledged=bool(row.acknowledged),
        rule_tags=_load_list(row.rule_tags),
        protocol=row.protocol,
        direction=row.direction,
        in_interface=row.in_interface,
        out_interface=row.out_interface,
    )


# -- incidents -------------------------------------------------------------
def incident_to_orm(incident: EngineIncident) -> OrmIncident:
    return OrmIncident(
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description or None,
        severity=incident.severity,
        status=incident.status,
        src_ip=incident.src_ip,
        user_name=incident.user_name,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        alert_count=incident.alert_count,
        categories=_dump_list(sorted(incident.categories)),
        correlation_rule_id=incident.correlation_rule_id,
        protocol=incident.protocol,
        direction=incident.direction,
        in_interface=incident.in_interface,
        out_interface=incident.out_interface,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


def orm_to_incident(row: OrmIncident) -> EngineIncident:
    return EngineIncident(
        incident_id=row.incident_id,
        title=row.title,
        severity=row.severity,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        description=row.description or "",
        status=row.status or "open",
        src_ip=row.src_ip,
        user_name=row.user_name,
        alert_count=row.alert_count or 0,
        categories=set(_load_list(row.categories)),
        correlation_rule_id=row.correlation_rule_id,
        protocol=row.protocol,
        direction=row.direction,
        in_interface=row.in_interface,
        out_interface=row.out_interface,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )
