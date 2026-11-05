"""CLI command to verify notification channel configuration."""
from __future__ import annotations

import uuid
from typing import Optional

from siem.alerting.manager import AlertNotifier
from siem.core.config import Config, get_config
from siem.core.utils import utcnow
from siem.engine.models import Alert


def cmd_notify_test(args, config: Optional[Config] = None) -> int:
    """Send a synthetic alert through every configured notification channel."""
    config = config or get_config()

    notification_repo = None
    try:
        from siem.cli.commands.engine import build_storage

        storage = build_storage(config)
        notification_repo = getattr(storage, "notifications", None)
    except Exception as e:  # database optional for a connectivity test
        print(f"(note) could not open storage for notification logging: {e}")

    notifier = AlertNotifier(config, notification_repo=notification_repo)

    alert = Alert(
        alert_id="TEST-" + uuid.uuid4().hex[:8].upper(),
        rule_id="notification-test",
        rule_name="Notification Channel Test",
        timestamp=utcnow(),
        severity=getattr(args, "severity", None) or "high",
        src_ip="127.0.0.1",
        user_name="siem-admin",
        description="Synthetic test notification from `siem notify test`.",
    )

    print(f"Testing notification channels (severity={alert.severity})...")
    results = notifier.notify(alert)

    if not results:
        print("No notification channels are configured/enabled.")
        return 1

    sent = 0
    for r in results:
        if r.status == "sent":
            sent += 1
        detail = f" - {r.detail}" if getattr(r, "detail", None) else ""
        print(f"  [{r.status.upper():12}] {r.channel}{detail}")

    print(f"\n{sent}/{len(results)} channel(s) delivered successfully.")
    return 0 if sent else 1
