"""Rule engine: loading, validation, matching, alerting and correlation."""
from siem.engine.condition import evaluate as evaluate_condition
from siem.engine.condition import parse as parse_condition
from siem.engine.correlation_rules import (
    CorrelationRule,
    CorrelationRuleLoader,
    build_correlation_rule,
)
from siem.engine.correlator import Correlator, CorrelationResult, classify_alert
from siem.engine.models import Alert, Incident, Rule
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader, discover_rule_files
from siem.engine.rule_matcher import match_rule, match_selection
from siem.engine.rule_validator import validate_rule
from siem.engine.state_manager import StateManager
from siem.engine.utils import parse_duration

__all__ = [
    "Alert",
    "Incident",
    "Rule",
    "CorrelationRule",
    "CorrelationRuleLoader",
    "CorrelationResult",
    "Correlator",
    "RuleEngine",
    "RuleLoader",
    "StateManager",
    "build_correlation_rule",
    "classify_alert",
    "discover_rule_files",
    "match_rule",
    "match_selection",
    "validate_rule",
    "parse_condition",
    "evaluate_condition",
    "parse_duration",
]
