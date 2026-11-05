"""Correlation rule definitions (multi-stage attack chains).

Correlation rules live alongside detection rules but use ``type: correlation``
and describe a *sequence of attack stages* that, when all observed for the same
entity within a window, escalate an incident (FR-29, B.1).
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.engine.utils import parse_duration
from siem.parsing.normalizer import coerce_severity

log = get_logger("engine.correlation_rules")

_EXTENSIONS = {".yml", ".yaml"}


@dataclass
class CorrelationRule:
    """A multi-stage correlation chain definition."""

    rule_id: str
    title: str
    stages: list[str]
    escalate_to: str = "critical"
    description: str = ""
    window: Optional[int] = None
    title_template: str = ""
    file_path: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "stages": self.stages,
            "escalate_to": self.escalate_to,
            "window": self.window,
            "file_path": self.file_path,
        }


def _stable_id(path: Path, data: dict) -> str:
    given = data.get("id")
    if given:
        return str(given)
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest[:32]))


def build_correlation_rule(path: Path, data: dict) -> CorrelationRule:
    stages = data.get("stages") or []
    if isinstance(stages, str):
        stages = [stages]
    return CorrelationRule(
        rule_id=_stable_id(path, data),
        title=str(data.get("title", "Correlation Rule")),
        stages=[str(s).lower() for s in stages],
        escalate_to=coerce_severity(data.get("escalate_to", "critical")),
        description=str(data.get("description", "")),
        window=parse_duration(data.get("window")),
        title_template=str(data.get("title_template", "")),
        file_path=str(path),
    )


class CorrelationRuleLoader:
    """Discovers and loads ``type: correlation`` YAML files."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self.last_errors: list[str] = []

    @property
    def directory(self) -> Path:
        value = self.config.get(
            "correlation.correlation_rules_path", "rules/builtin/correlation"
        )
        return self.config.project_root / value

    def load(self) -> list[CorrelationRule]:
        self.last_errors = []
        rules: dict[str, CorrelationRule] = {}
        directory = self.directory
        if not directory.exists():
            return []

        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _EXTENSIONS:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except (yaml.YAMLError, OSError) as e:
                self.last_errors.append(f"{path}: {e}")
                log.error("Failed to read correlation rule %s: %s", path, e)
                continue

            if not isinstance(data, dict):
                self.last_errors.append(f"{path}: not a mapping")
                continue
            if str(data.get("type", "")).lower() != "correlation":
                continue

            rule = build_correlation_rule(path, data)
            if not rule.stages:
                self.last_errors.append(f"{path}: no stages defined")
                continue
            if rule.rule_id in rules:
                log.warning("Duplicate correlation rule id %s", rule.rule_id)
            rules[rule.rule_id] = rule

        log.info("Loaded %d correlation rule(s)", len(rules))
        return list(rules.values())
