"""Alert correlation and incident generation (Phase 5, FR-28..FR-33).

Alerts that share common attributes (source IP, user, destination) within a
configurable window are grouped into incidents. Incidents are escalated when a
known multi-stage chain (see :mod:`siem.engine.correlation_rules`) is observed.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from siem.core.config import Config, get_config
from siem.core.constants import (
    DEFAULT_CORRELATION_WINDOW,
    DEFAULT_MIN_ALERTS_FOR_INCIDENT,
    SEVERITY_CRITICAL,
    SEVERITY_ORDER,
)
from siem.core.logger import get_logger
from siem.engine.models import Alert, Incident

log = get_logger("engine.correlator")

_TECHNIQUE_RE = re.compile(r"^t\d+$", re.IGNORECASE)

# Heuristic name -> category fallbacks for rules without attack.* tags.
_NAME_HINTS = [
    ("credential_access", ("brute", "failed", "password", "login failure")),
    ("discovery", ("scan", "recon", "enumeration")),
    ("initial_access", ("root", "login", "success", "exploit", "injection", "traversal")),
    ("impact", ("flood", "dos", "denial")),
    ("command_and_control", ("outbound", "backdoor", "beacon", "c2")),
]


@dataclass
class CorrelationResult:
    """Outcome of feeding one alert into the correlator."""

    action: str  # "created" | "updated" | "pending"
    incident: Optional[Incident] = None


def classify_alert(alert: Alert) -> set[str]:
    """Derive high-level attack categories for an alert (FR-29)."""
    categories: set[str] = set()
    for tag in alert.rule_tags:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        token = tag.split(".", 1)[1]
        if _TECHNIQUE_RE.match(token):
            continue
        categories.add(token)

    name = (alert.rule_name or "").lower()
    for category, hints in _NAME_HINTS:
        if any(h in name for h in hints):
            categories.add(category)
    return categories


def _severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


class Correlator:
    """Groups related alerts into incidents within a sliding time window."""

    def __init__(
        self,
        config: Optional[Config] = None,
        correlation_rules: Optional[list] = None,
    ):
        self.config = config or get_config()
        self.window_seconds = int(
            self.config.get("correlation.window_seconds", DEFAULT_CORRELATION_WINDOW)
        )
        self.min_alerts = int(
            self.config.get(
                "correlation.min_alerts_for_incident", DEFAULT_MIN_ALERTS_FOR_INCIDENT
            )
        )
        self.match_fields = list(
            self.config.get(
                "correlation.match_fields", ["src_ip", "user_name", "dst_ip"]
            )
        )
        self.correlation_rules = sorted(
            correlation_rules or [], key=lambda r: len(r.stages), reverse=True
        )

        self._incidents: dict[str, Incident] = {}
        self._pending: list[tuple[datetime, Alert, set]] = []
        self.stats = {"alerts_processed": 0, "incidents_created": 0,
                      "incidents_updated": 0, "alerts_pending": 0}

    # -- public API -------------------------------------------------------
    @property
    def incidents(self) -> list[Incident]:
        return list(self._incidents.values())

    def correlate(self, alert: Alert) -> CorrelationResult:
        """Correlate a single alert; returns what happened."""
        self.stats["alerts_processed"] += 1
        keys = self._keys(alert)
        self._prune(alert.timestamp)

        incident = self._find_incident(keys, alert.timestamp)
        if incident is not None:
            self._add_alert(incident, alert, keys)
            self.stats["incidents_updated"] += 1
            return CorrelationResult("updated", incident)

        partners = self._find_pending(keys, alert.timestamp)
        members = [p[1] for p in partners] + [alert]
        if len(members) >= self.min_alerts:
            if partners:
                partner_ids = {id(p[1]) for p in partners}
                self._pending = [p for p in self._pending if id(p[1]) not in partner_ids]
            incident = self._create_incident(members, alert.timestamp)
            self.stats["incidents_created"] += 1
            return CorrelationResult("created", incident)

        self._pending.append((alert.timestamp, alert, keys))
        self.stats["alerts_pending"] += 1
        return CorrelationResult("pending", None)

    # -- internals --------------------------------------------------------
    def _keys(self, alert: Alert) -> set[tuple[str, str]]:
        keys: set[tuple[str, str]] = set()
        for field_name in self.match_fields:
            value = getattr(alert, field_name, None)
            if value:
                keys.add((field_name, str(value)))
        return keys

    def _prune(self, now: datetime) -> None:
        self._pending = [
            p for p in self._pending
            if (now - p[0]).total_seconds() <= self.window_seconds
        ]

    def _find_incident(
        self, keys: set[tuple[str, str]], now: datetime
    ) -> Optional[Incident]:
        best: Optional[Incident] = None
        best_overlap = 0
        best_seen: Optional[datetime] = None
        for incident in self._incidents.values():
            if (now - incident.last_seen).total_seconds() > self.window_seconds:
                continue
            overlap = len(keys & incident.keys)
            if overlap == 0:
                continue
            if overlap > best_overlap or (
                overlap == best_overlap
                and (best_seen is None or incident.last_seen > best_seen)
            ):
                best, best_overlap, best_seen = incident, overlap, incident.last_seen
        return best

    def _find_pending(
        self, keys: set[tuple[str, str]], now: datetime
    ) -> list[tuple[datetime, Alert, set]]:
        matches = []
        for ts, pending_alert, pending_keys in self._pending:
            if (now - ts).total_seconds() > self.window_seconds:
                continue
            if keys & pending_keys:
                matches.append((ts, pending_alert, pending_keys))
        return matches

    def _create_incident(self, members: list[Alert], now: datetime) -> Incident:
        incident = Incident(
            incident_id=self._new_id(),
            title="",
            severity="low",
            first_seen=min(a.timestamp for a in members),
            last_seen=max(a.timestamp for a in members),
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident.incident_id] = incident
        for alert in members:
            self._add_alert(incident, alert, self._keys(alert))
        log.info("Incident created: %s severity=%s alerts=%d",
                 incident.incident_id, incident.severity, incident.alert_count)
        return incident

    def _add_alert(
        self, incident: Incident, alert: Alert, keys: set[tuple[str, str]]
    ) -> None:
        alert.incident_id = incident.incident_id
        incident.alert_ids.append(alert.alert_id)
        incident.alert_count += 1
        incident.keys |= keys
        incident.rule_names.add(alert.rule_name)
        incident.categories |= classify_alert(alert)
        incident.last_seen = max(incident.last_seen, alert.timestamp)
        for attr in ("protocol", "direction", "in_interface", "out_interface"):
            if getattr(incident, attr, None) is None:
                value = getattr(alert, attr, None)
                if value:
                    setattr(incident, attr, value)
        incident.first_seen = min(incident.first_seen, alert.timestamp)
        incident.updated_at = max(incident.last_seen, alert.timestamp)
        incident.severity = _severity_max(incident.severity, alert.severity)

        if incident.src_ip is None and alert.src_ip:
            incident.src_ip = alert.src_ip
        if incident.user_name is None and alert.user_name:
            incident.user_name = alert.user_name

        self._apply_correlation_rules(incident)
        if not getattr(incident, "_escalated", False):
            incident.title = self._default_title(incident)

    # -- escalation -------------------------------------------------------
    def _apply_correlation_rules(self, incident: Incident) -> None:
        """Escalate incidents that satisfy a multi-stage chain."""
        matched = False
        for rule in self.correlation_rules:
            if all(stage in incident.categories for stage in rule.stages):
                incident.severity = _severity_max(incident.severity, rule.escalate_to)
                incident.correlation_rule_id = rule.rule_id
                template = rule.title_template or rule.title
                incident.title = self._render_title(template, incident)
                incident.description = rule.description or incident.description
                incident._escalated = True
                matched = True
                break

        if not matched and self._is_multistage(incident.categories):
            incident.severity = _severity_max(incident.severity, SEVERITY_CRITICAL)
            incident.title = self._render_title(
                "Multi-Stage Attack Detected - {primary}", incident
            )
            incident._escalated = True

    @staticmethod
    def _is_multistage(categories: set[str]) -> bool:
        if len(categories) >= 3:
            return True
        has_setup = bool(categories & {"discovery", "credential_access"})
        return has_setup and "initial_access" in categories

    @staticmethod
    def _render_title(template: str, incident: Incident) -> str:
        primary = incident.src_ip or incident.user_name or "unknown entity"
        return template.replace("{primary}", primary)

    @staticmethod
    def _default_title(incident: Incident) -> str:
        primary = incident.src_ip or incident.user_name or "unknown entity"
        if len(incident.rule_names) == 1:
            return f"{next(iter(incident.rule_names))} - {primary}"
        return f"Correlated Incident ({len(incident.rule_names)} rules) - {primary}"

    @staticmethod
    def _new_id() -> str:
        return "INC-" + uuid.uuid4().hex[:12].upper()
