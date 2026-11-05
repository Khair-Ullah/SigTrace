"""Packaged multi-stage attack demo (formerly ``scripts/run_demo.py``).

Lives inside the package so the same command works from a source checkout and
from a frozen PyInstaller build, where the ``scripts`` directory is not
shipped. The script remains as a thin wrapper for backwards compatibility.

The demo simulates Port Scan -> SSH Brute Force -> Successful Login and feeds
the events through the real rule engine and correlator before persisting them
into the active database.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from siem.core import paths
from siem.core.config import Config, get_config
from siem.core.utils import utcnow
from siem.engine.correlation_rules import CorrelationRuleLoader
from siem.engine.correlator import Correlator
from siem.engine.models import Alert, Incident, Rule
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.parsing.models import NormalizedEvent
from siem.storage.bootstrap import resolve_db_file
from siem.storage.migrations import run_migrations
from siem.storage.service import StorageService


@dataclass
class DemoResult:
    """Summary of a demo run."""

    events: list[NormalizedEvent] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    db_path: Optional[Path] = None
    persisted: bool = False


def _ev(event_id: str, ts: datetime, **kw) -> NormalizedEvent:
    base = {
        "event_id": event_id,
        "timestamp": ts,
        "source_id": "demo-simulator",
        "source_type": kw.pop("source_type", "custom"),
        "raw_log": kw.pop("raw_log", "demo-generated"),
    }
    base.update(kw)
    return NormalizedEvent(**base)


def _ensure_runtime() -> None:
    """Create the data layout and seed defaults on a packaged first run."""
    paths.bootstrap_env()
    if not paths.default_config_path().exists():
        from siem.desktop.bootstrap import prepare_runtime

        prepare_runtime()


def _load_config() -> Config:
    """Load (and cache) the configuration after the runtime is prepared."""
    try:
        return get_config()
    except Exception:
        from siem.core.config import load_config, set_config

        config = load_config()
        set_config(config)
        return config


def simulate(
    dry_run: bool = False,
    db_path: Optional[Path] = None,
    config: Optional[Config] = None,
) -> DemoResult:
    """Generate the attack chain and persist it unless ``dry_run`` is set."""
    config = config or get_config()

    T0 = utcnow()

    rules = RuleLoader(config).load()
    engine = RuleEngine(rules, config)
    correlator = Correlator(
        config, correlation_rules=CorrelationRuleLoader(config).load()
    )

    events: list[NormalizedEvent] = []
    alerts: list[Alert] = []
    incidents: list[Incident] = []

    def feed(ev: NormalizedEvent) -> None:
        events.append(ev)
        for alert in engine.evaluate(ev):
            alerts.append(alert)
            result = correlator.correlate(alert)
            inc = result.incident
            if inc and inc not in incidents:
                incidents.append(inc)

    # Stage 1: Port Scan (firewall denies)
    attacker = "198.51.100.88"
    for i in range(20):
        feed(
            _ev(
                f"demo-ps-{i}",
                T0 + timedelta(seconds=i * 0.1),
                event_type="firewall_deny",
                action="denied",
                source_type="firewall",
                src_ip=attacker,
                dst_ip="10.0.0.50",
                dst_port=20000 + i,
                severity="medium",
                extra={"protocol": "tcp", "direction": "in", "in_interface": "ens33"},
            )
        )

    # Stage 2: SSH Brute Force (failed logins)
    for i in range(6):
        feed(
            _ev(
                f"demo-bf-{i}",
                T0 + timedelta(seconds=5 + i),
                event_type="failed_login",
                action="failure",
                source_type="ssh",
                src_ip=attacker,
                user_name="admin",
                severity="medium",
            )
        )

    # Stage 3: Successful Login (privilege/compromise)
    feed(
        _ev(
            "demo-ok-0",
            T0 + timedelta(seconds=12),
            event_type="successful_login",
            action="success",
            source_type="ssh",
            src_ip=attacker,
            user_name="root",
            severity="high",
        )
    )

    print(
        f"[demo] Generated {len(events)} events, {len(alerts)} alerts, "
        f"{len(incidents)} incidents"
    )
    for inc in incidents:
        print(
            f"[demo] INCIDENT: {inc.incident_id} | severity={inc.severity} | "
            f"title={inc.title} | categories={sorted(inc.categories)}"
        )

    result = DemoResult(
        events=events, alerts=alerts, incidents=incidents, rules=rules
    )
    if dry_run:
        print("[demo] Dry-run complete (not persisted).")
        return result

    target = Path(db_path).expanduser().resolve() if db_path else resolve_db_file(config)
    target.parent.mkdir(parents=True, exist_ok=True)
    run_migrations(target)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine_obj = create_engine(f"sqlite:///{target.as_posix()}", future=True)
    session_factory = sessionmaker(
        bind=engine_obj, expire_on_commit=False, future=True
    )
    try:
        storage = StorageService(session_factory, config)
        summary = storage.save_pipeline(
            rules=rules, events=events, alerts=alerts, incidents=incidents
        )
    finally:
        engine_obj.dispose()

    result.db_path = target
    result.persisted = True
    print(f"[demo] Persisted: {summary}")
    print(f"[demo] DB: {target}")
    print(
        "[demo] Now run: python -m siem run --web "
        "(or launch the desktop app) and open the dashboard."
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the multi-stage attack demo")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and evaluate but do not persist to the database",
    )
    parser.add_argument(
        "--db",
        type=Path,
        help="Database file to write to (default: the active configured database)",
    )
    return parser


def cmd_demo(args, config: Optional[Config] = None) -> int:
    _ensure_runtime()
    config = config or _load_config()
    try:
        simulate(dry_run=args.dry_run, db_path=args.db, config=config)
    except Exception as exc:  # pragma: no cover - CLI boundary
        print(f"[demo] ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    return cmd_demo(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
