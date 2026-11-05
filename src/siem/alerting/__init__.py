"""Alerting: notification channels, de-duplication and rate limiting."""
from siem.alerting.manager import AlertNotifier
from siem.alerting.notification import (
    STATUS_DUPLICATE,
    STATUS_FAILED,
    STATUS_RATE_LIMITED,
    STATUS_SENT,
    STATUS_SKIPPED,
    NotificationResult,
)
from siem.alerting.notifiers import (
    BaseNotifier,
    CallbackNotifier,
    EmailNotifier,
    LogFileNotifier,
    build_default_notifiers,
)
from siem.alerting.rate_limiter import SlidingWindowRateLimiter

__all__ = [
    "AlertNotifier",
    "NotificationResult",
    "BaseNotifier",
    "CallbackNotifier",
    "EmailNotifier",
    "LogFileNotifier",
    "build_default_notifiers",
    "SlidingWindowRateLimiter",
    "STATUS_SENT",
    "STATUS_SKIPPED",
    "STATUS_FAILED",
    "STATUS_RATE_LIMITED",
    "STATUS_DUPLICATE",
]
