"""Data models for the SOAR-Lite playbook engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(frozen=True)
class PlaybookMatch:
    """Conditions that decide whether a playbook applies to an incident."""

    severities: frozenset[str] = frozenset({"critical"})
    rule_ids: frozenset[str] = frozenset()
    rule_names: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    correlation_rule_ids: frozenset[str] = frozenset()
    min_alert_count: int = 1

    def matches(self, incident, alert=None) -> bool:
        """Return True when the incident (and current alert) satisfy the match."""
        if incident is None:
            return False

        severity = str(incident.severity or "").lower()
        if self.severities and severity not in self.severities:
            return False

        if int(incident.alert_count or 0) < self.min_alert_count:
            return False

        correlation_id = str(incident.correlation_rule_id or "").lower()
        if self.correlation_rule_ids and correlation_id not in self.correlation_rule_ids:
            return False

        categories = {str(item).lower() for item in incident.categories}
        if self.categories and not (self.categories & categories):
            return False

        rule_names = {str(item).lower() for item in incident.rule_names}
        if self.rule_names and not (self.rule_names & rule_names):
            return False

        if self.rule_ids:
            current_rule = str(getattr(alert, "rule_id", "") or "").lower()
            if current_rule not in self.rule_ids:
                return False

        return True


@dataclass(frozen=True)
class PlaybookAction:
    """A single automated response step."""

    kind: str
    name: str = ""
    enabled: bool = True
    require: tuple[str, ...] = ()
    continue_on_error: bool = True

    command: Any = None
    shell: bool = False
    working_directory: Optional[str] = None
    timeout_seconds: float = 15.0

    to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    subject: str = ""
    body: str = ""
    from_address: str = ""


@dataclass(frozen=True)
class Playbook:
    """A named collection of actions and the incidents it responds to."""

    playbook_id: str
    name: str
    description: str = ""
    enabled: bool = True
    match: PlaybookMatch = field(default_factory=PlaybookMatch)
    actions: tuple[PlaybookAction, ...] = ()


@dataclass(frozen=True)
class PlaybookConfig:
    """Parsed contents of ``playbooks.yaml``."""

    playbooks: tuple[Playbook, ...] = ()
    enabled: bool = True
    dry_run: bool = True
    max_runs_per_incident: int = 1
    path: Optional[str] = None


@dataclass
class ActionOutcome:
    """Result of one action within a playbook run."""

    action_name: str
    action_type: str
    status: str
    detail: str = ""
    output: str = ""
    recipients: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_type": self.action_type,
            "status": self.status,
            "detail": self.detail,
            "output": self.output,
            "recipients": list(self.recipients),
        }


@dataclass
class PlaybookRun:
    """Result of running one playbook against one incident."""

    playbook_id: str
    playbook_name: str
    incident_id: str
    status: str
    actions: list[ActionOutcome] = field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: str = ""

    @property
    def duration_seconds(self) -> float:
        if self.started_at is None or self.finished_at is None:
            return 0.0
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "incident_id": self.incident_id,
            "status": self.status,
            "actions": [action.to_dict() for action in self.actions],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }
