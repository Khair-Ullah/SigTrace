"""CLI commands for querying stored alerts/incidents (Phase 9)."""
from __future__ import annotations

from typing import Optional

from siem.core.config import Config, get_config
from siem.cli.commands.engine import build_storage


def cmd_alerts_list(args, config: Optional[Config] = None) -> int:
    config = config or get_config()
    storage = build_storage(config)

    alerts = storage.alerts.query(
        severity=getattr(args, "severity", None),
        src_ip=getattr(args, "src_ip", None),
        limit=int(getattr(args, "limit", 50)),
    )
    if not alerts:
        print("No alerts found.")
        return 0

    header = f"{'TIMESTAMP':<20} {'SEVERITY':<9} {'SRC':<16} {'ACK':<4} RULE"
    print(header)
    print("-" * len(header))
    for alert in alerts:
        ts = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts:<20} {alert.severity:<9} {str(alert.src_ip or '-'):<16} "
              f"{'yes' if alert.acknowledged else 'no':<4} {alert.rule_name}")
    print(f"\n{len(alerts)} alert(s).")
    return 0
