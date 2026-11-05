"""Loading and validation for ``playbooks.yaml``."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from siem.core import paths
from siem.core.config import Config
from siem.soar.models import (
    Playbook,
    PlaybookAction,
    PlaybookConfig,
    PlaybookMatch,
)

SUPPORTED_ACTIONS = frozenset({"command", "email"})
DEFAULT_PLAYBOOKS_FILE = "config/playbooks.yaml"


def resolve_playbooks_path(
    config: Optional[Config] = None, path: Optional[str | Path] = None
) -> Path:
    """Resolve the active playbook file from an argument, env or config."""
    if path is not None:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            root = config.project_root if config else paths.data_dir()
            candidate = Path(root) / candidate
        return candidate

    override = os.environ.get("SIEM_PLAYBOOKS")
    if override:
        candidate = Path(override).expanduser()
        if not candidate.is_absolute():
            root = config.project_root if config else paths.data_dir()
            candidate = Path(root) / candidate
        return candidate

    if config is not None:
        configured = config.get("soar.playbooks_path")
        if configured:
            candidate = Path(str(configured)).expanduser()
            if not candidate.is_absolute():
                candidate = Path(config.project_root) / candidate
            return candidate

    return paths.config_dir() / "playbooks.yaml"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _as_lower_set(value: Any) -> frozenset[str]:
    return frozenset(str(item).strip().lower() for item in _as_list(value) if str(item).strip())


def _as_string_tuple(value: Any) -> tuple[str, ...]:
    return tuple(str(item).strip() for item in _as_list(value) if str(item).strip())


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _parse_action(raw: Any, playbook_id: str, index: int) -> PlaybookAction:
    if not isinstance(raw, dict):
        raise ValueError(f"playbook {playbook_id!r} action #{index + 1} must be a mapping")

    kind = str(raw.get("type") or raw.get("action") or "").strip().lower()
    if kind not in SUPPORTED_ACTIONS:
        supported = ", ".join(sorted(SUPPORTED_ACTIONS))
        raise ValueError(
            f"playbook {playbook_id!r} action #{index + 1} has unsupported type "
            f"{kind!r}; expected one of: {supported}"
        )

    name = str(raw.get("name") or "").strip()
    if not name:
        name = f"{kind} action {index + 1}"

    require = _as_string_tuple(raw.get("require"))
    continue_on_error = _as_bool(raw.get("continue_on_error"), True)

    if kind == "command":
        command = raw.get("command")
        if not command:
            raise ValueError(f"playbook {playbook_id!r} action {name!r} requires a command")
        if not isinstance(command, (str, list, tuple)):
            raise ValueError(
                f"playbook {playbook_id!r} action {name!r} command must be a "
                "string or list of strings"
            )
        timeout = float(raw.get("timeout_seconds", 15) or 15)
        if timeout <= 0:
            raise ValueError(
                f"playbook {playbook_id!r} action {name!r} timeout_seconds must be > 0"
            )
        working_directory = raw.get("working_directory")
        if working_directory is not None:
            working_directory = str(working_directory)
        return PlaybookAction(
            kind=kind,
            name=name,
            enabled=_as_bool(raw.get("enabled"), True),
            require=require,
            continue_on_error=continue_on_error,
            command=command,
            shell=_as_bool(raw.get("shell"), False),
            working_directory=working_directory,
            timeout_seconds=timeout,
        )

    recipients = _as_string_tuple(raw.get("to"))
    if not recipients:
        raise ValueError(
            f"playbook {playbook_id!r} email action {name!r} requires at least one 'to' recipient"
        )
    subject = str(raw.get("subject") or "[SIEM][SOAR] {severity} incident {incident_id}")
    body = str(raw.get("body") or "")

    return PlaybookAction(
        kind=kind,
        name=name,
        enabled=_as_bool(raw.get("enabled"), True),
        require=require,
        continue_on_error=continue_on_error,
        to=recipients,
        cc=_as_string_tuple(raw.get("cc")),
        subject=subject,
        body=body,
        from_address=str(raw.get("from_address") or ""),
    )


def _parse_playbook(raw: Any, index: int) -> Playbook:
    if not isinstance(raw, dict):
        raise ValueError(f"playbook #{index + 1} must be a mapping")

    playbook_id = str(raw.get("id") or "").strip()
    if not playbook_id:
        raise ValueError(f"playbook #{index + 1} is missing a non-empty 'id'")

    match_raw = raw.get("match") or {}
    if not isinstance(match_raw, dict):
        raise ValueError(f"playbook {playbook_id!r} match must be a mapping")

    match = PlaybookMatch(
        severities=_as_lower_set(match_raw.get("severities", ["critical"])),
        rule_ids=_as_lower_set(match_raw.get("rule_ids")),
        rule_names=_as_lower_set(match_raw.get("rule_names")),
        categories=_as_lower_set(match_raw.get("categories")),
        correlation_rule_ids=_as_lower_set(match_raw.get("correlation_rule_ids")),
        min_alert_count=max(1, int(match_raw.get("min_alert_count", 1) or 1)),
    )

    raw_actions = raw.get("actions") or []
    if not isinstance(raw_actions, list):
        raise ValueError(f"playbook {playbook_id!r} actions must be a list")
    actions = tuple(
        _parse_action(action_raw, playbook_id, action_index)
        for action_index, action_raw in enumerate(raw_actions)
    )
    if not actions:
        raise ValueError(f"playbook {playbook_id!r} must define at least one action")

    name = str(raw.get("name") or playbook_id).strip()
    return Playbook(
        playbook_id=playbook_id,
        name=name,
        description=str(raw.get("description") or ""),
        enabled=_as_bool(raw.get("enabled"), True),
        match=match,
        actions=actions,
    )


def load_playbook_config(
    path: Optional[str | Path] = None, config: Optional[Config] = None
) -> PlaybookConfig:
    """Load and validate a playbook file. Missing files disable SOAR."""
    resolved = resolve_playbooks_path(config, path)
    if not resolved.is_file():
        return PlaybookConfig(enabled=False, path=str(resolved))

    with open(resolved, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("playbooks.yaml root must be a mapping")

    raw_playbooks = data.get("playbooks") or []
    if not isinstance(raw_playbooks, list):
        raise ValueError("playbooks.yaml 'playbooks' must be a list")

    playbooks: list[Playbook] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_playbooks):
        playbook = _parse_playbook(raw, index)
        if playbook.playbook_id in seen:
            raise ValueError(f"duplicate playbook id {playbook.playbook_id!r}")
        seen.add(playbook.playbook_id)
        playbooks.append(playbook)

    max_runs = int(data.get("max_runs_per_incident", 1) or 1)
    return PlaybookConfig(
        playbooks=tuple(playbooks),
        enabled=_as_bool(data.get("enabled"), True),
        dry_run=_as_bool(data.get("dry_run"), True),
        max_runs_per_incident=max(1, max_runs),
        path=str(resolved),
    )
