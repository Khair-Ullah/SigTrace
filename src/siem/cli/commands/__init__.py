"""CLI command handlers (Phase 9)."""
from siem.cli.commands.demo import cmd_demo
from siem.cli.commands.engine import (
    build_storage,
    cmd_ingest,
    cmd_run,
    cmd_serve,
    cmd_simulate,
)
from siem.cli.commands.notify import cmd_notify_test
from siem.cli.commands.query import cmd_alerts_list
from siem.cli.commands.reset import cmd_reset
from siem.cli.commands.rules import (
    cmd_rules_import_sigma,
    cmd_rules_list,
    cmd_rules_validate,
)

__all__ = [
    "build_storage",
    "cmd_run",
    "cmd_serve",
    "cmd_simulate",
    "cmd_ingest",
    "cmd_demo",
    "cmd_reset",
    "cmd_notify_test",
    "cmd_rules_list",
    "cmd_rules_validate",
    "cmd_rules_import_sigma",
    "cmd_alerts_list",
]
