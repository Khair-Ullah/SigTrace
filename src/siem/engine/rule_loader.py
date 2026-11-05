"""Rule discovery, loading and hot-reload (FR-17, FR-24, FR-56, FR-59)."""
from __future__ import annotations

import hashlib
import threading
import uuid
from pathlib import Path
from typing import Callable, Optional

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from siem.core.config import Config, get_config
from siem.core.exceptions import RuleError
from siem.core.logger import get_logger
from siem.engine import condition as cond
from siem.engine.models import Rule
from siem.engine.rule_validator import extract_selections, validate_rule
from siem.engine.utils import parse_duration
from siem.parsing.normalizer import coerce_severity

log = get_logger("engine.loader")

_RULE_EXTENSIONS = {".yml", ".yaml"}


def _stable_id(path: Path, data: dict) -> str:
    given = data.get("id")
    if given:
        return str(given)
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest[:32]))


def discover_rule_files(directories: list[Path]) -> list[Path]:
    files: list[Path] = []
    for directory in directories:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix.lower() in _RULE_EXTENSIONS:
                files.append(path)
    return files


def build_rule(path: Path, data: dict, raw_yaml: str) -> Rule:
    detection = data.get("detection") or {}
    selections = extract_selections(detection)
    condition = detection.get("condition", "")
    threshold = detection.get("threshold")
    timeframe = parse_duration(detection.get("timeframe"))
    group_by = detection.get("group-by") or []

    level = coerce_severity(data.get("level", "medium"))

    return Rule(
        rule_id=_stable_id(path, data),
        title=str(data.get("title", "Untitled Rule")),
        condition=str(condition),
        selections=selections,
        detection=detection,
        level=level,
        description=str(data.get("description", "")),
        logsource=data.get("logsource") or {},
        tags=list(data.get("tags") or []),
        falsepositives=list(data.get("falsepositives") or []),
        status=str(data.get("status", "stable")),
        author=str(data.get("author", "")),
        date=str(data.get("date", "")),
        timeframe=timeframe,
        threshold=int(threshold) if threshold is not None else None,
        group_by=[str(x) for x in group_by],
        raw_yaml=raw_yaml,
        file_path=str(path),
        condition_ast=cond.parse(condition) if condition else None,
    )


class RuleLoader:
    """Loads and validates rules from the configured directories."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._rules: dict[str, Rule] = {}
        self._observer: Optional[Observer] = None
        self._on_change: Optional[Callable[[list[Rule]], None]] = None
        self.last_errors: list[str] = []

    @property
    def directories(self) -> list[Path]:
        root = self.config.project_root
        dirs = []
        for key in ("rules.builtin_path", "rules.custom_path"):
            value = self.config.get(key)
            if value:
                dirs.append(root / value)
        return dirs

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    # -- loading ----------------------------------------------------------
    def load(self) -> list[Rule]:
        """Load all valid rules, replacing the current set. Returns the rules."""
        loaded: dict[str, Rule] = {}
        self.last_errors = []

        for path in discover_rule_files(self.directories):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = f.read()
                data = yaml.safe_load(raw)
            except (yaml.YAMLError, OSError) as e:
                msg = f"{path}: YAML error - {e}"
                self.last_errors.append(msg)
                log.error("Failed to read rule %s: %s", path, e)
                continue

            # Correlation definitions are handled by the correlator, not the
            # detection-rule matcher (Phase 5).
            if isinstance(data, dict) and str(data.get("type", "")).lower() == "correlation":
                continue

            errors = validate_rule(data)
            if errors:
                for err in errors:
                    msg = f"{path}: {err}"
                    self.last_errors.append(msg)
                    log.error("Invalid rule %s: %s", path, err)
                continue

            try:
                rule = build_rule(path, data, raw)
            except Exception as e:  # defensive
                self.last_errors.append(f"{path}: {e}")
                log.exception("Failed to build rule %s", path)
                continue

            if rule.rule_id in loaded:
                log.warning("Duplicate rule id %s (overriding %s)",
                            rule.rule_id, loaded[rule.rule_id].file_path)
            loaded[rule.rule_id] = rule

        self._rules = loaded
        log.info("Loaded %d rule(s) from %d directory(ies)", len(loaded), len(self.directories))
        return self.rules

    def reload(self) -> list[Rule]:
        """Hot-reload rules from disk (FR-59)."""
        log.info("Reloading rules...")
        return self.load()

    # -- hot reload watcher ----------------------------------------------
    def watch(self, on_change: Optional[Callable[[list[Rule]], None]] = None) -> None:
        """Watch rule directories and reload on change (FR-24)."""
        self._on_change = on_change
        handler = _RuleChangeHandler(self)
        self._observer = Observer()
        for directory in self.directories:
            directory.mkdir(parents=True, exist_ok=True)
            self._observer.schedule(handler, str(directory), recursive=True)
        self._observer.start()
        log.info("Rule hot-reload watcher started on %d directories", len(self.directories))

    def stop_watch(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    def _handle_change(self) -> None:
        try:
            rules = self.reload()
            if self._on_change:
                self._on_change(rules)
        except Exception:
            log.exception("Rule reload failed")


class _RuleChangeHandler(FileSystemEventHandler):
    def __init__(self, loader: RuleLoader):
        self._loader = loader

    def _relevant(self, path: str) -> bool:
        return Path(path).suffix.lower() in _RULE_EXTENSIONS

    def on_modified(self, event):
        if not event.is_directory and self._relevant(event.src_path):
            self._loader._handle_change()

    def on_created(self, event):
        if not event.is_directory and self._relevant(event.src_path):
            self._loader._handle_change()

    def on_deleted(self, event):
        if not event.is_directory and self._relevant(event.src_path):
            self._loader._handle_change()
