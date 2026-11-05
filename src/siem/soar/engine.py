"""SOAR-Lite playbook engine.

The engine evaluates playbooks against correlated incidents and executes the
configured response actions. It is intentionally small and local: playbooks are
YAML files, commands run through ``subprocess`` and email uses the existing
``alerting.email`` SMTP settings. Dry-run mode is enabled by default.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Optional

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.soar.actions import (
    build_email,
    command_argv,
    default_command_runner,
    default_email_sender,
    missing_requirements,
    render_template,
)
from siem.soar.models import (
    ActionOutcome,
    Playbook,
    PlaybookConfig,
    PlaybookRun,
)
from siem.soar.playbooks import load_playbook_config, resolve_playbooks_path

log = get_logger("soar.engine")

ACTION_SUCCESS = "success"
ACTION_FAILED = "failed"
ACTION_SKIPPED = "skipped"
ACTION_DRY_RUN = "dry_run"

RUN_COMPLETED = "completed"
RUN_PARTIAL = "partial"
RUN_FAILED = "failed"
RUN_SKIPPED = "skipped"
RUN_DRY_RUN = "dry_run"

CommandRunner = Callable[[str | list[str], float, Optional[str], bool], tuple[int, str, str]]
EmailSender = Callable[[object, Config], None]


class PlaybookEngine:
    """Loads playbooks and runs matching responses for incidents."""

    def __init__(
        self,
        config: Optional[Config] = None,
        path: Optional[str | Path] = None,
        *,
        command_runner: Optional[CommandRunner] = None,
        email_sender: Optional[EmailSender] = None,
    ):
        self.config = config or get_config()
        self._explicit_path = path
        self.command_runner = command_runner or default_command_runner
        self.email_sender = email_sender or default_email_sender

        self.path = resolve_playbooks_path(self.config, path)
        self.playbooks: list[Playbook] = []
        self.enabled = False
        self.dry_run = True
        self.max_runs_per_incident = 1
        self.load_error = ""
        self._data = PlaybookConfig()

        self._lock = threading.RLock()
        self._run_counts: dict[tuple[str, str], int] = {}

        self.stats = {
            "evaluations": 0,
            "runs": 0,
            "completed": 0,
            "partial": 0,
            "failed": 0,
            "skipped": 0,
            "dry_run": 0,
            "actions": 0,
            "actions_success": 0,
            "actions_dry_run": 0,
            "actions_skipped": 0,
            "actions_failed": 0,
        }
        self.reload()

    def reload(self) -> None:
        """Reload playbooks from disk. Invalid files disable SOAR safely."""
        try:
            loaded = load_playbook_config(self._explicit_path, self.config)
        except Exception as exc:
            self._data = PlaybookConfig()
            self.playbooks = []
            self.enabled = False
            self.dry_run = True
            self.max_runs_per_incident = 1
            self.load_error = str(exc)
            self.path = resolve_playbooks_path(self.config, self._explicit_path)
            log.exception("Failed to load SOAR playbooks from %s", self.path)
            return

        self._data = loaded
        self.playbooks = list(loaded.playbooks)
        self.path = Path(loaded.path) if loaded.path else self.path
        self.enabled = bool(loaded.enabled) and bool(self.config.get("soar.enabled", True))
        self.dry_run = bool(loaded.dry_run)
        self.max_runs_per_incident = max(1, int(loaded.max_runs_per_incident))
        self.load_error = ""
        if self.playbooks:
            log.info(
                "Loaded %d SOAR playbook(s) from %s (dry_run=%s)",
                len(self.playbooks),
                self.path,
                self.dry_run,
            )

    def evaluate(self, incident, alert=None, now=None) -> list[PlaybookRun]:
        """Run every matching playbook once per incident."""
        if not self.enabled or not self.playbooks or incident is None:
            return []

        self.stats["evaluations"] += 1
        now = now or utcnow()
        runs: list[PlaybookRun] = []
        for playbook in self.playbooks:
            if not playbook.enabled or not playbook.match.matches(incident, alert):
                continue
            if not self._claim(playbook.playbook_id, incident.incident_id):
                continue
            runs.append(self._execute_playbook(playbook, incident, alert, now))
        return runs

    def summary(self) -> dict:
        return {
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "path": str(self.path),
            "playbooks": len(self.playbooks),
            "max_runs_per_incident": self.max_runs_per_incident,
            "load_error": self.load_error,
            "stats": dict(self.stats),
        }

    def _claim(self, playbook_id: str, incident_id: str) -> bool:
        key = (playbook_id, incident_id)
        with self._lock:
            count = self._run_counts.get(key, 0)
            if count >= self.max_runs_per_incident:
                return False
            self._run_counts[key] = count + 1
            return True

    def _execute_playbook(self, playbook: Playbook, incident, alert, now) -> PlaybookRun:
        context = self._context(incident, alert, playbook)
        started = now
        outcomes: list[ActionOutcome] = []
        error = ""

        for action in playbook.actions:
            if not action.enabled:
                outcome = ActionOutcome(
                    action.name, action.kind, ACTION_SKIPPED, detail="action disabled"
                )
            else:
                try:
                    outcome = self._execute_action(action, context)
                except Exception as exc:
                    log.exception(
                        "SOAR action %s failed in playbook %s",
                        action.name,
                        playbook.playbook_id,
                    )
                    outcome = ActionOutcome(
                        action.name, action.kind, ACTION_FAILED, detail=str(exc)
                    )

            outcomes.append(outcome)
            self._count_action(outcome)
            if outcome.status == ACTION_FAILED and not action.continue_on_error:
                error = f"stopped after failed action {action.name!r}"
                break

        status = self._run_status(outcomes)
        run = PlaybookRun(
            playbook_id=playbook.playbook_id,
            playbook_name=playbook.name,
            incident_id=incident.incident_id,
            status=status,
            actions=outcomes,
            started_at=started,
            finished_at=utcnow(),
            error=error,
        )
        self.stats["runs"] += 1
        self.stats[status] = self.stats.get(status, 0) + 1
        log.info(
            "SOAR playbook %s ran for incident %s: %s",
            playbook.playbook_id,
            incident.incident_id,
            status,
        )
        return run

    def _execute_action(self, action, context: dict[str, str]) -> ActionOutcome:
        missing = missing_requirements(action.require, context)
        if missing:
            return ActionOutcome(
                action.name,
                action.kind,
                ACTION_SKIPPED,
                detail=f"required field {missing!r} is empty",
            )

        if self.dry_run:
            preview = self._preview(action, context)
            log.info(
                "SOAR dry-run: playbook=%s action=%s preview=%s",
                context.get("playbook_id", ""),
                action.name,
                preview,
            )
            return ActionOutcome(
                action.name,
                action.kind,
                ACTION_DRY_RUN,
                detail="dry_run is enabled; action was not executed",
                output=preview,
                recipients=[self._render(item, context) for item in action.to],
            )

        if action.kind == "command":
            return self._execute_command(action, context)
        if action.kind == "email":
            return self._execute_email(action, context)
        return ActionOutcome(
            action.name, action.kind, ACTION_FAILED, detail="unsupported action type"
        )

    def _execute_command(self, action, context: dict[str, str]) -> ActionOutcome:
        argv = command_argv(action.command, context, action.shell)
        if not argv:
            return ActionOutcome(
                action.name, action.kind, ACTION_SKIPPED, detail="command is empty"
            )

        cwd = self._resolve_working_directory(action.working_directory)
        try:
            returncode, stdout, stderr = self.command_runner(
                argv, action.timeout_seconds, cwd, action.shell
            )
        except Exception as exc:
            return ActionOutcome(action.name, action.kind, ACTION_FAILED, detail=str(exc))

        output = (stdout or "").strip()
        if returncode == 0:
            return ActionOutcome(action.name, action.kind, ACTION_SUCCESS, output=output)
        detail = (stderr or stdout or "").strip() or f"command exited with {returncode}"
        return ActionOutcome(action.name, action.kind, ACTION_FAILED, detail=detail, output=output)

    def _execute_email(self, action, context: dict[str, str]) -> ActionOutcome:
        if not bool(self.config.get("alerting.email.enabled", False)):
            return ActionOutcome(
                action.name,
                action.kind,
                ACTION_SKIPPED,
                detail="alerting.email.enabled is false",
            )

        try:
            message = build_email(action, context, self.config)
            self.email_sender(message, self.config)
        except Exception as exc:
            return ActionOutcome(action.name, action.kind, ACTION_FAILED, detail=str(exc))

        recipients = [self._render(item, context) for item in action.to]
        return ActionOutcome(
            action.name,
            action.kind,
            ACTION_SUCCESS,
            output=str(message["Subject"]),
            recipients=recipients,
        )

    def _preview(self, action, context: dict[str, str]) -> str:
        if action.kind == "command":
            argv = command_argv(action.command, context, action.shell)
            return " ".join(argv) if isinstance(argv, list) else str(argv)
        subject = action.subject or "[SIEM][SOAR] {severity} incident {incident_id}"
        return f"email to {', '.join(action.to)}: {self._render(subject, context)}"

    def _context(self, incident, alert, playbook: Playbook) -> dict[str, str]:
        return {
            "incident_id": str(incident.incident_id),
            "title": str(incident.title or ""),
            "description": str(incident.description or ""),
            "severity": str(incident.severity or ""),
            "status": str(incident.status or ""),
            "src_ip": str(incident.src_ip or ""),
            "dst_ip": str(getattr(alert, "dst_ip", "") or ""),
            "user_name": str(incident.user_name or ""),
            "alert_count": str(incident.alert_count or 0),
            "categories": ", ".join(sorted(str(item) for item in incident.categories)),
            "rule_names": ", ".join(sorted(str(item) for item in incident.rule_names)),
            "correlation_rule_id": str(incident.correlation_rule_id or ""),
            "first_seen": self._format_time(getattr(incident, "first_seen", None)),
            "last_seen": self._format_time(getattr(incident, "last_seen", None)),
            "alert_id": str(getattr(alert, "alert_id", "") or ""),
            "rule_id": str(getattr(alert, "rule_id", "") or ""),
            "rule_name": str(getattr(alert, "rule_name", "") or ""),
            "alert_description": str(getattr(alert, "description", "") or ""),
            "timestamp": self._format_time(getattr(alert, "timestamp", None)),
            "playbook_id": playbook.playbook_id,
            "playbook_name": playbook.name,
        }

    def _resolve_working_directory(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path(self.config.project_root) / candidate
        return str(candidate)

    @staticmethod
    def _format_time(value) -> str:
        return value.isoformat() if value is not None else ""

    @staticmethod
    def _render(value: str, context: dict[str, str]) -> str:
        return render_template(value, context)

    def _count_action(self, outcome: ActionOutcome) -> None:
        self.stats["actions"] += 1
        if outcome.status == ACTION_SUCCESS:
            self.stats["actions_success"] += 1
        elif outcome.status == ACTION_DRY_RUN:
            self.stats["actions_dry_run"] += 1
        elif outcome.status == ACTION_SKIPPED:
            self.stats["actions_skipped"] += 1
        elif outcome.status == ACTION_FAILED:
            self.stats["actions_failed"] += 1

    @staticmethod
    def _run_status(outcomes: list[ActionOutcome]) -> str:
        if not outcomes:
            return RUN_SKIPPED
        if all(outcome.status == ACTION_SKIPPED for outcome in outcomes):
            return RUN_SKIPPED
        if any(outcome.status == ACTION_FAILED for outcome in outcomes):
            if any(outcome.status in (ACTION_SUCCESS, ACTION_DRY_RUN) for outcome in outcomes):
                return RUN_PARTIAL
            return RUN_FAILED
        if any(outcome.status == ACTION_DRY_RUN for outcome in outcomes):
            return RUN_DRY_RUN
        if any(outcome.status == ACTION_SUCCESS for outcome in outcomes):
            return RUN_COMPLETED
        return RUN_SKIPPED
