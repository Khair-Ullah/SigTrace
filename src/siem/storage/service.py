"""Convenience facade over the repositories used by the pipeline (Phase 6+)."""
from __future__ import annotations

from typing import Optional

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.engine.models import Alert, Incident, Rule
from siem.parsing.models import NormalizedEvent
from siem.storage.repositories.alert_repository import AlertRepository
from siem.storage.repositories.audit_repository import AuditRepository
from siem.storage.repositories.config_repository import ConfigRepository
from siem.storage.repositories.event_repository import EventRepository
from siem.storage.repositories.incident_repository import IncidentRepository
from siem.storage.repositories.notification_repository import NotificationRepository
from siem.storage.repositories.rule_repository import RuleRepository
from siem.storage.repositories.user_repository import UserRepository
from siem.storage.repositories.state_repository import StateRepository
from siem.storage.retention import RetentionManager

log = get_logger("storage.service")


class StorageService:
    """High-level persistence used by the processing pipeline and dashboard."""

    def __init__(self, session_factory=None, config: Optional[Config] = None):
        self.config = config or get_config()
        self.events = EventRepository(session_factory)
        self.alerts = AlertRepository(session_factory)
        self.incidents = IncidentRepository(session_factory)
        self.rules = RuleRepository(session_factory)
        self.settings = ConfigRepository(session_factory)
        self.audit = AuditRepository(session_factory)
        self.state = StateRepository(session_factory)
        self.notifications = NotificationRepository(session_factory)
        self.users = UserRepository(session_factory)
        self.retention = RetentionManager(self.config, session_factory)

    # -- events -----------------------------------------------------------
    def persist_event(self, event: NormalizedEvent) -> str:
        return self.events.add(event)

    def persist_events(self, events: list[NormalizedEvent]) -> int:
        return self.events.add_many(events)

    # -- rules ------------------------------------------------------------
    def sync_rules(self, rules: list[Rule]) -> int:
        return self.rules.sync(rules)

    # -- alerts -----------------------------------------------------------
    def persist_alert(self, alert: Alert) -> str:
        return self.alerts.add(alert)

    # -- incidents --------------------------------------------------------
    def persist_incident(self, incident: Incident, link_alerts: bool = True) -> str:
        incident_id = self.incidents.upsert(incident)
        if link_alerts and incident.alert_ids:
            self.alerts.link_incident(incident.alert_ids, incident_id)
        return incident_id

    def save_pipeline(
        self,
        events=(),
        alerts=(),
        incidents=(),
        rules=(),
    ) -> dict:
        """Persist pipeline output in FK-safe order.

        Order matters because alerts reference both rules and incidents:
          1. rules    (alerts.rule_id  -> rules.rule_id)
          2. incidents (alerts.incident_id -> incidents.incident_id)
          3. alerts
          4. link alerts to their incident
          5. events
        """
        events, alerts = list(events), list(alerts)
        incidents, rules = list(incidents), list(rules)

        if rules:
            self.sync_rules(rules)
        for incident in incidents:
            self.incidents.upsert(incident)
        if alerts:
            self.alerts.add_many(alerts)
        if events:
            self.persist_events(events)
        for incident in incidents:
            if incident.alert_ids:
                self.alerts.link_incident(incident.alert_ids, incident.incident_id)

        return {
            "events": len(events),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "rules": len(rules),
        }

    # -- maintenance ------------------------------------------------------
    def run_retention(self, dry_run: bool = False) -> dict:
        return self.retention.cleanup(dry_run=dry_run)
