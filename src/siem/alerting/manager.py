"""Alert notification manager: severity filtering, de-duplication, rate
limiting and channel dispatch (FR-47..FR-52)."""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Optional

from siem.alerting.notification import (
    STATUS_DUPLICATE,
    STATUS_FAILED,
    STATUS_RATE_LIMITED,
    STATUS_SENT,
    NotificationResult,
)
from siem.alerting.notifiers import BaseNotifier, build_default_notifiers
from siem.alerting.rate_limiter import SlidingWindowRateLimiter
from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.engine.models import Alert, Incident

log = get_logger("alerting.manager")


class AlertNotifier:
    """Fan an alert out to the configured notification channels."""

    def __init__(
        self,
        config: Optional[Config] = None,
        notifiers: Optional[list[BaseNotifier]] = None,
        notification_repo=None,
    ):
        self.config = config or get_config()
        self.notifiers = notifiers if notifiers is not None else build_default_notifiers(self.config)
        self.notification_repo = notification_repo

        max_per_minute = int(self.config.get("alerting.rate_limit.max_per_minute", 60))
        self.rate_limiter = SlidingWindowRateLimiter(max_per_minute, window_seconds=60)
        self.dedup_window = int(self.config.get("alerting.dedup_window_seconds", 300))

        self._last_sent: dict[str, datetime] = {}
        self._lock = threading.Lock()
        self.stats = {"notifications": 0, "sent": 0, "failed": 0,
                      "duplicates": 0, "rate_limited": 0, "skipped": 0}

    # -- public API -------------------------------------------------------
    def notify(
        self,
        alert: Alert,
        incident: Optional[Incident] = None,
        now: Optional[datetime] = None,
    ) -> list[NotificationResult]:
        now = now or utcnow()
        self.stats["notifications"] += 1

        key = self._dedup_key(alert)
        with self._lock:
            last = self._last_sent.get(key)
            if last is not None and (now - last).total_seconds() < self.dedup_window:
                self.stats["duplicates"] += 1
                return [NotificationResult("manager", STATUS_DUPLICATE, alert.alert_id,
                                           incident_id=self._incident_id(alert, incident),
                                           detail="duplicate within window")]
            if not self.rate_limiter.allow(now):
                self.stats["rate_limited"] += 1
                return [NotificationResult("manager", STATUS_RATE_LIMITED, alert.alert_id,
                                           incident_id=self._incident_id(alert, incident),
                                           detail="rate limit exceeded")]
            self._last_sent[key] = now

        results = [self._dispatch(n, alert, incident) for n in self.notifiers]
        self._record(results, alert, incident)
        return results

    def notify_many(
        self, alerts: list[Alert], incidents_by_alert: Optional[dict] = None
    ) -> list[NotificationResult]:
        out: list[NotificationResult] = []
        for alert in alerts:
            incident = None
            if incidents_by_alert:
                incident = incidents_by_alert.get(alert.alert_id)
            out.extend(self.notify(alert, incident))
        return out

    def reset_dedup(self) -> None:
        with self._lock:
            self._last_sent.clear()

    # -- internals --------------------------------------------------------
    def _dispatch(self, notifier: BaseNotifier, alert: Alert,
                  incident: Optional[Incident]) -> NotificationResult:
        if not notifier.accepts(alert):
            self.stats["skipped"] += 1
            return NotificationResult(
                notifier.channel, "skipped", alert.alert_id,
                incident_id=self._incident_id(alert, incident),
                detail=f"below min_severity ({notifier.min_severity})",
            )
        result = notifier.send(alert, incident)
        result.incident_id = self._incident_id(alert, incident)
        if result.status == STATUS_SENT:
            self.stats["sent"] += 1
        elif result.status == STATUS_FAILED:
            self.stats["failed"] += 1
        return result

    def _record(self, results: list[NotificationResult], alert: Alert,
                incident: Optional[Incident]) -> None:
        if self.notification_repo is None:
            return
        for result in results:
            if result.status in (STATUS_SENT, STATUS_FAILED, STATUS_RATE_LIMITED):
                try:
                    self.notification_repo.add(result)
                except Exception:  # never fail alerting because of logging
                    log.exception("Failed to record notification result")

    def _dedup_key(self, alert: Alert) -> str:
        return f"{alert.rule_id}|{alert.src_ip or ''}|{alert.user_name or ''}"

    @staticmethod
    def _incident_id(alert: Alert, incident: Optional[Incident]) -> Optional[str]:
        return incident.incident_id if incident is not None else alert.incident_id
