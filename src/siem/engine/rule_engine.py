"""Rule engine orchestrator: evaluate events against rules, emit alerts (FR-26, FR-27)."""
from __future__ import annotations

from typing import Optional

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.core.utils import generate_uuid
from siem.engine import rule_matcher
from siem.engine.models import Alert, Rule
from siem.engine.state_manager import StateManager
from siem.parsing.models import NormalizedEvent

log = get_logger("engine.engine")

# Fields copied from an event into the flat matching dict
_EVENT_FIELDS = (
    "event_id", "timestamp", "source_id", "source_type", "src_ip", "dst_ip",
    "src_port", "dst_port", "user_name", "action", "event_type", "severity",
    "message", "raw_log",
)


class RuleEngine:
    """Evaluates normalized events against a set of rules."""

    def __init__(
        self,
        rules: Optional[list[Rule]] = None,
        config: Optional[Config] = None,
        state_manager: Optional[StateManager] = None,
    ):
        self.config = config or get_config()
        self.rules: list[Rule] = rules or []
        self.state = state_manager or StateManager()
        self.stats = {
            "events_evaluated": 0,
            "alerts_generated": 0,
            "rule_matches": 0,
        }

    def set_rules(self, rules: list[Rule]) -> None:
        self.rules = rules

    @property
    def enabled_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.enabled]

    # -- public API -------------------------------------------------------
    def evaluate(self, event: NormalizedEvent) -> list[Alert]:
        """Evaluate a single event, returning any alerts it triggers."""
        flat = self._flatten(event)
        alerts: list[Alert] = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                alerts.extend(self._evaluate_rule(rule, flat, event))
            except Exception:
                log.exception("Rule evaluation error for rule %s", rule.rule_id)

        self.stats["events_evaluated"] += 1
        self.stats["alerts_generated"] += len(alerts)
        return alerts

    def _evaluate_rule(self, rule: Rule, flat: dict, event: NormalizedEvent) -> list[Alert]:
        if not rule_matcher.match_rule(rule, flat):
            return []

        self.stats["rule_matches"] += 1

        if rule.is_stateful:
            group_key = self._group_key(rule, flat)
            count, event_ids = self.state.increment(
                rule.rule_id, group_key, event.timestamp, rule.timeframe, event.event_id
            )
            if count >= (rule.threshold or 1):
                alert = self._build_alert(rule, flat, event, count, event_ids)
                self.state.reset(rule.rule_id, group_key)
                return [alert]
            return []

        return [self._build_alert(rule, flat, event, 1, [event.event_id])]

    # -- helpers ----------------------------------------------------------
    def _flatten(self, event: NormalizedEvent) -> dict:
        flat = {field: getattr(event, field) for field in _EVENT_FIELDS}
        if event.extra:
            flat.update(event.extra)
        return flat

    def _group_key(self, rule: Rule, flat: dict) -> str:
        if not rule.group_by:
            return "_"
        parts = [str(flat.get(f, "")) for f in rule.group_by]
        return "|".join(parts)

    def _build_alert(
        self,
        rule: Rule,
        flat: dict,
        event: NormalizedEvent,
        count: int,
        event_ids: list[str],
    ) -> Alert:
        alert = Alert(
            alert_id=generate_uuid(),
            rule_id=rule.rule_id,
            rule_name=rule.title,
            timestamp=event.timestamp,
            severity=rule.level,
            src_ip=flat.get("src_ip"),
            dst_ip=flat.get("dst_ip"),
            user_name=flat.get("user_name"),
            event_ids=event_ids,
            count=count,
            description=rule.description,
            rule_tags=list(rule.tags),
            protocol=flat.get("protocol"),
            direction=flat.get("direction"),
            in_interface=flat.get("in_interface"),
            out_interface=flat.get("out_interface"),
        )
        log.info("Alert generated: rule=%s severity=%s count=%d src=%s",
                 rule.title, rule.level, count, alert.src_ip)
        return alert
