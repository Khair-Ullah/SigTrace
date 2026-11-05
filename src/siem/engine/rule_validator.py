"""Validation of detection rules against the Sigma-compatible schema (FR-18, FR-58)."""
from __future__ import annotations

import fnmatch
from typing import Any

from siem.engine import condition as cond
from siem.engine.condition import ConditionError
from siem.engine.utils import parse_duration

# Sigma levels (informational maps down to 'low' later)
ACCEPTED_LEVELS = {"informational", "low", "medium", "high", "critical"}

RESERVED_DETECTION_KEYS = {"condition", "timeframe", "threshold", "group-by"}


def extract_selections(detection: dict) -> dict[str, Any]:
    """Return the selection entries (excluding condition/timeframe/etc.)."""
    return {k: v for k, v in detection.items() if k not in RESERVED_DETECTION_KEYS}


def validate_rule(data: Any) -> list[str]:
    """Validate a raw rule mapping. Returns a list of error strings (empty = ok)."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["rule root must be a mapping"]

    title = data.get("title")
    if not title or not isinstance(title, str):
        errors.append("missing or invalid 'title'")

    detection = data.get("detection")
    if not isinstance(detection, dict):
        errors.append("missing or invalid 'detection' mapping")
        detection = {}

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        errors.append("missing 'detection.condition'")

    selections = extract_selections(detection)
    if not selections:
        errors.append("no selection entries defined under 'detection'")

    if condition:
        selections = selections or {}
        try:
            ast = cond.parse(condition)
        except ConditionError as e:
            errors.append(f"invalid condition: {e}")
            ast = None
        if ast is not None:
            refs, patterns = cond.referenced_names(ast)
            names = list(selections.keys())
            for ref in refs:
                if ref not in selections:
                    errors.append(f"condition references unknown selection '{ref}'")
            for pattern in patterns:
                if not any(fnmatch.fnmatchcase(n.lower(), pattern.lower()) for n in names):
                    errors.append(f"condition pattern '{pattern}' matches no selection")

    level = data.get("level")
    if level is not None and str(level).lower() not in ACCEPTED_LEVELS:
        errors.append(f"invalid level '{level}' (expected one of {sorted(ACCEPTED_LEVELS)})")

    # logsource
    logsource = data.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append("'logsource' must be a mapping")

    # stateful fields
    threshold = detection.get("threshold")
    timeframe = detection.get("timeframe")
    if threshold is not None:
        try:
            if int(threshold) < 1:
                errors.append("'threshold' must be >= 1")
        except (TypeError, ValueError):
            errors.append("'threshold' must be an integer")
        if parse_duration(timeframe) is None:
            errors.append("'threshold' requires a valid 'timeframe' (e.g. 60s)")
    elif timeframe is not None:
        errors.append("'timeframe' given without 'threshold'")

    group_by = detection.get("group-by")
    if group_by is not None:
        if not isinstance(group_by, list) or not all(isinstance(x, str) for x in group_by):
            errors.append("'group-by' must be a list of field names")

    return errors
