"""Data models for the rule engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from siem.core.constants import SEVERITY_MEDIUM


@dataclass
class Rule:
    """A parsed, validated detection rule."""

    rule_id: str
    title: str
    condition: str
    selections: dict[str, Any]
    detection: dict[str, Any]
    level: str = SEVERITY_MEDIUM
    description: str = ""
    logsource: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    status: str = "stable"
    author: str = ""
    date: str = ""
    timeframe: Optional[int] = None   # seconds
    threshold: Optional[int] = None
    group_by: list[str] = field(default_factory=list)
    enabled: bool = True
    raw_yaml: str = ""
    file_path: str = ""
    condition_ast: Any = None

    @property
    def is_stateful(self) -> bool:
        return bool(self.threshold and self.timeframe)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "description": self.description,
            "logsource": self.logsource,
            "tags": self.tags,
            "timeframe": self.timeframe,
            "threshold": self.threshold,
            "group_by": self.group_by,
            "enabled": self.enabled,
            "file_path": self.file_path,
        }


@dataclass
class Alert:
    """An alert produced when a rule matches."""

    alert_id: str
    rule_id: str
    rule_name: str
    timestamp: datetime
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user_name: Optional[str] = None
    event_ids: list[str] = field(default_factory=list)
    count: int = 1
    incident_id: Optional[str] = None
    description: str = ""
    acknowledged: bool = False
    rule_tags: list[str] = field(default_factory=list)
    protocol: Optional[str] = None
    direction: Optional[str] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user_name": self.user_name,
            "event_ids": self.event_ids,
            "count": self.count,
            "incident_id": self.incident_id,
            "description": self.description,
            "rule_tags": self.rule_tags,
            "protocol": self.protocol,
            "direction": self.direction,
            "in_interface": self.in_interface,
            "out_interface": self.out_interface,
        }


@dataclass
class Incident:
    """A correlated group of related alerts (FR-29, FR-31)."""

    incident_id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    status: str = "open"
    src_ip: Optional[str] = None
    user_name: Optional[str] = None
    alert_count: int = 0
    alert_ids: list[str] = field(default_factory=list)
    rule_names: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    keys: set[tuple[str, str]] = field(default_factory=set)
    correlation_rule_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "src_ip": self.src_ip,
            "user_name": self.user_name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alert_count": self.alert_count,
            "alert_ids": self.alert_ids,
            "rule_names": sorted(self.rule_names),
            "categories": sorted(self.categories),
            "correlation_rule_id": self.correlation_rule_id,
            "protocol": self.protocol,
            "direction": self.direction,
            "in_interface": self.in_interface,
            "out_interface": self.out_interface,
        }
