"""Command-line interface for the SIEM engine."""
from __future__ import annotations

import argparse
import sys

from siem.version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem",
        description="SIEM Log Correlation Engine",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    # db ------------------------------------------------------------------
    db = sub.add_parser("db", help="Database operations")
    db_sub = db.add_subparsers(dest="db_command")
    db_init = db_sub.add_parser("init", help="Initialize the database")
    db_init.add_argument("--force", action="store_true", help="Drop and recreate")
    db_reset = db_sub.add_parser(
        "reset", help="Delete and recreate a fresh migrated database"
    )
    db_reset.add_argument(
        "--db", type=str, help="Database file to reset (default: active config)"
    )

    # status --------------------------------------------------------------
    sub.add_parser("status", help="Show system status")

    # run -----------------------------------------------------------------
    run = sub.add_parser("run", help="Start ingestion + correlation engine")
    run.add_argument(
        "--web", action="store_true", help="Also start the web dashboard and stream alerts to it"
    )
    run.add_argument("--host", help="Dashboard bind host (with --web)")
    run.add_argument("--port", type=int, help="Dashboard bind port (with --web)")
    run.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    # simulate ------------------------------------------------------------
    simulate = sub.add_parser("simulate", help="Generate synthetic traffic through the engine")
    simulate.add_argument(
        "--scenario", action="append", help="Scenario name (repeatable; use 'all')"
    )
    simulate.add_argument("--count", type=int, help="Override per-scenario line count")
    simulate.add_argument("--seed", type=int, help="Random seed for reproducibility")
    simulate.add_argument("--write", help="Also write raw lines to this file")

    # demo ----------------------------------------------------------------
    demo = sub.add_parser(
        "demo", help="Run the multi-stage attack demo (Port Scan -> Brute Force -> Login)"
    )
    demo.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and evaluate but do not persist to the database",
    )
    demo.add_argument(
        "--db", type=str, help="Database file to write to (default: active config)"
    )

    # ingest --------------------------------------------------------------
    ingest = sub.add_parser("ingest", help="Ingest a single log file")
    ingest.add_argument("path", help="Path to the log file")
    ingest.add_argument("--source-id", help="Source identifier (default: file stem)")
    ingest.add_argument("--source-type", default="custom", help="Source type label")

    # rules ---------------------------------------------------------------
    rules = sub.add_parser("rules", help="Inspect detection rules")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rules_sub.add_parser("list", help="List loaded rules")
    rules_sub.add_parser("validate", help="Validate all rule files")
    imp = rules_sub.add_parser(
        "import-sigma",
        help="Import SigmaHQ-style rule files (converts to the engine dialect)",
    )
    imp.add_argument(
        "path", help="Sigma rule file or directory (e.g. an " "extracted SigmaHQ rules/ folder)"
    )
    imp.add_argument("--out", help="Output directory " "(default: rules/custom/sigma)")
    imp.add_argument(
        "--overwrite", action="store_true", help="Replace previously imported output files"
    )
    imp.add_argument(
        "--dry-run", action="store_true", help="Report what would be imported without writing"
    )
    imp.add_argument(
        "--include-deprecated",
        action="store_true",
        help="Also import rules with status deprecated/unsupported",
    )
    imp.add_argument(
        "--no-field-map",
        action="store_true",
        help="Keep raw Sigma field names (no translation to the " "normalized schema)",
    )
    imp.add_argument("--limit", type=int, metavar="N", help="Import at most N rule files")

    # alerts --------------------------------------------------------------
    alerts = sub.add_parser("alerts", help="Query stored alerts")
    alerts_sub = alerts.add_subparsers(dest="alerts_command")
    al = alerts_sub.add_parser("list", help="List recent alerts")
    al.add_argument("--severity", help="Filter by severity")
    al.add_argument("--src-ip", dest="src_ip", help="Filter by source IP")
    al.add_argument("--limit", type=int, default=50, help="Max rows (default 50)")

    # web -----------------------------------------------------------------
    web = sub.add_parser("web", help="Run the web dashboard (development server)")
    web.add_argument("--host", help="Bind host (default from config)")
    web.add_argument("--port", type=int, help="Bind port (default from config)")
    web.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    # serve ---------------------------------------------------------------
    serve = sub.add_parser("serve", help="Run the dashboard (production WSGI server)")
    serve.add_argument("--host", help="Bind host (default from config)")
    serve.add_argument("--port", type=int, help="Bind port (default from config)")
    serve.add_argument("--workers", type=int, help="Worker processes (default from config)")
    serve.add_argument(
        "--server",
        choices=["auto", "gunicorn", "waitress"],
        default="auto",
        help="WSGI server to use (default: auto)",
    )

    # notify --------------------------------------------------------------
    notify = sub.add_parser("notify", help="Notification channel utilities")
    notify_sub = notify.add_subparsers(dest="notify_command")
    nt = notify_sub.add_parser("test", help="Send a test notification")
    nt.add_argument("--severity", help="Severity of the test alert (default high)")

    # user ----------------------------------------------------------------
    sub.add_parser(
        "user", help="Manage dashboard users (use: siem user create ...)", add_help=False
    )

    return parser


def _cmd_status() -> int:
    from siem.core.config import get_config

    config = get_config()
    print(f"{config.get('system.name')} v{config.get('system.version')}")
    print(f"Config root : {config.project_root}")
    print(f"Database    : {config.get('database.url')}")
    try:
        from siem.cli.commands.engine import build_storage

        storage = build_storage(config)
        print(
            "Counts      : "
            f"events={storage.events.count()} "
            f"alerts={storage.alerts.count()} "
            f"incidents={storage.incidents.count()} "
            f"rules={storage.rules.count()}"
        )
    except Exception as e:  # database not initialized yet
        print(f"Counts      : unavailable ({e})")
    return 0


def cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # ``siem user ...`` delegates to the packaged user-management commands
    if argv and argv[0] == "user":
        from siem.cli.commands.users import main as user_main

        return user_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "db" and args.db_command == "init":
        from siem.storage.bootstrap import init_database

        return init_database(force=args.force)

    if args.command == "db" and args.db_command == "reset":
        from pathlib import Path

        from siem.cli.commands import cmd_reset

        if args.db:
            args.db = Path(args.db)
        return cmd_reset(args)

    if args.command == "status":
        return _cmd_status()

    if args.command == "run":
        from siem.cli.commands import cmd_run

        return cmd_run(args)

    if args.command == "simulate":
        from siem.cli.commands import cmd_simulate

        return cmd_simulate(args)

    if args.command == "demo":
        from pathlib import Path

        from siem.cli.commands import cmd_demo

        if args.db:
            args.db = Path(args.db)
        return cmd_demo(args)

    if args.command == "ingest":
        from siem.cli.commands import cmd_ingest

        return cmd_ingest(args)

    if args.command == "rules":
        from siem.cli.commands import (
            cmd_rules_import_sigma,
            cmd_rules_list,
            cmd_rules_validate,
        )

        if args.rules_command == "validate":
            return cmd_rules_validate(args)
        if args.rules_command == "import-sigma":
            return cmd_rules_import_sigma(args)
        return cmd_rules_list(args)

    if args.command == "alerts":
        from siem.cli.commands import cmd_alerts_list

        return cmd_alerts_list(args)

    if args.command == "web":
        from siem.core.config import get_config
        from siem.web.app import run_server

        config = get_config()
        run_server(config, host=args.host, port=args.port, debug=args.debug or None)
        return 0

    if args.command == "serve":
        from siem.cli.commands import cmd_serve
        from siem.core.config import get_config

        return cmd_serve(args, get_config())

    if args.command == "notify":
        from siem.cli.commands import cmd_notify_test
        from siem.core.config import get_config

        if args.notify_command == "test":
            return cmd_notify_test(args, get_config())
        print("Usage: siem notify test [--severity LEVEL]")
        return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
