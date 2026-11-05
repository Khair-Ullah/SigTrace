"""CLI commands that drive the end-to-end pipeline (Phase 9)."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from siem.core.config import Config, get_config
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.pipeline import Pipeline
from siem.simulators import LogSimulator

log = get_logger("cli.engine")


def build_storage(config: Optional[Config] = None):
    """Initialize the database engine and return a ``StorageService``."""
    from siem.storage import database
    from siem.storage.service import StorageService

    database.init_engine()
    return StorageService(database.get_session_factory(), config or get_config())


def _print_summary(pipeline: Pipeline, results: list) -> None:
    stats = pipeline.stats
    print(
        f"Events: {stats.parsed}  Alerts: {stats.alerts}  "
        f"Incidents: {stats.incidents_created}  "
        f"Notifications sent: {stats.notifications_sent}  "
        f"Parse failures: {stats.parse_failures}"
    )
    for entry in results:
        incident = entry.incident.incident_id if entry.incident else "-"
        print(
            f"  [{entry.alert.severity.upper():8}] {entry.alert.rule_name} "
            f"src={entry.alert.src_ip or '-'} user={entry.alert.user_name or '-'} "
            f"count={entry.alert.count} incident={incident}"
        )


def cmd_run(args, config: Optional[Config] = None) -> int:
    """Start ingestion + processing (optionally with the web dashboard)."""
    config = config or get_config()
    storage = build_storage(config)
    pipeline = Pipeline(config, storage)

    if getattr(args, "web", False):
        from siem.web import realtime
        from siem.web.app import create_app, run_server

        app = create_app(config, storage=storage)
        # Let POST /api/ingest hand batches to the running streaming queue.
        app.extensions["siem_pipeline"] = pipeline
        pipeline.on_alert = realtime.make_socketio_callback()
        pipeline.run(block=False)
        print(f"Engine + dashboard starting "
              f"(events -> {config.get('database.url')})")
        try:
            run_server(config, host=args.host, port=args.port,
                       debug=args.debug, app=app)
        finally:
            pipeline.stop()
        return 0

    print(f"Engine starting (events -> {config.get('database.url')}). "
          f"Press Ctrl+C to stop.")
    pipeline.run(block=True)
    _print_summary(pipeline, [])
    return 0


def cmd_simulate(args, config: Optional[Config] = None) -> int:
    """Generate synthetic traffic and feed it through the pipeline."""
    config = config or get_config()
    scenarios = list(args.scenario or ["multi_stage"])
    if "all" in scenarios:
        scenarios = LogSimulator.scenario_names()

    base: datetime = utcnow()
    sim = LogSimulator(seed=args.seed)
    logs: list = []
    for name in scenarios:
        try:
            logs.extend(sim.generate(name, count=args.count, base=base))
        except ValueError as e:
            print(f"Error: {e}")
            return 2
    logs.sort(key=lambda entry: entry.timestamp or base)

    if args.write:
        _write_logs(logs, args.write)
        print(f"Wrote {len(logs)} log line(s) to {args.write}")

    storage = build_storage(config)
    pipeline = Pipeline(config, storage)
    print(f"Feeding {len(logs)} simulated line(s) from: {', '.join(scenarios)}")
    results = pipeline.ingest_simulated(logs)
    _print_summary(pipeline, results)
    return 0


def cmd_ingest(args, config: Optional[Config] = None) -> int:
    """Ingest a single log file through the full pipeline."""
    config = config or get_config()
    path = Path(args.path)
    if not path.is_absolute():
        path = config.project_root / path
    if not path.exists():
        print(f"Error: file not found: {path}")
        return 2

    storage = build_storage(config)
    pipeline = Pipeline(config, storage)
    print(f"Ingesting {path}")
    results = pipeline.ingest_file(
        path, source_id=args.source_id, source_type=args.source_type
    )
    _print_summary(pipeline, results)
    return 0


def cmd_serve(args, config: Optional[Config] = None) -> int:
    """Run the dashboard under a production WSGI server.

    Prefers gunicorn (POSIX/Linux/containers); falls back to waitress
    (cross-platform) on Windows or when gunicorn is unavailable.
    """
    config = config or get_config()

    from siem.storage import database
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    database.init_engine()
    storage = StorageService(database.get_session_factory(), config)
    app = create_app(config, storage=storage)

    host = getattr(args, "host", None) or config.get("web.host", "0.0.0.0")
    port = getattr(args, "port", None) or int(config.get("web.port", 5000))
    workers = getattr(args, "workers", None) or int(config.get("web.workers", 1))
    threads = int(config.get("web.threads", 8))
    choice = getattr(args, "server", None) or "auto"

    if choice in ("auto", "gunicorn"):
        try:
            return _serve_gunicorn(app, host, port, workers, threads, config)
        except ImportError as e:
            if choice == "gunicorn":
                print(
                    f"gunicorn is unavailable ({e}).\n"
                    "Install production dependencies with: "
                    "pip install -r requirements-prod.txt",
                    file=sys.stderr,
                )
                return 1
            # fall through to waitress on 'auto'
        except OSError as e:
            # e.g. gunicorn imported but unusable on this platform (Windows)
            if choice == "gunicorn":
                print(f"gunicorn cannot run here: {e}", file=sys.stderr)
                return 1

    if choice in ("auto", "waitress"):
        try:
            return _serve_waitress(app, host, port, threads)
        except ImportError:
            print(
                "No production server available. Install production dependencies:\n"
                "    pip install -r requirements-prod.txt",
                file=sys.stderr,
            )
            return 1

    print(f"Unknown server choice: {choice}", file=sys.stderr)
    return 2


def _serve_gunicorn(app, host: str, port: int, workers: int, threads: int,
                    config: Config) -> int:
    from gunicorn.app.base import BaseApplication

    options = {
        "bind": f"{host}:{port}",
        "workers": workers,
        "threads": threads,
        "worker_class": "gthread",
        "timeout": 120,
        "graceful_timeout": 30,
        "keepalive": 5,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": str(config.get("system.log_level", "INFO")).lower(),
    }

    class _StandaloneApp(BaseApplication):
        def __init__(self, application, opts):
            self._application = application
            self._options = opts
            super().__init__()

        def load_config(self):
            for key, value in self._options.items():
                if value is not None and key in self.cfg.settings:
                    self.cfg.set(key.lower(), value)

        def load(self):
            return self._application

    print(f"Serving SIEM dashboard via gunicorn on http://{host}:{port} "
          f"(workers={workers}, threads={threads})")
    _StandaloneApp(app, options).run()
    return 0


def _serve_waitress(app, host: str, port: int, threads: int) -> int:
    from waitress import serve

    print(f"Serving SIEM dashboard via waitress on http://{host}:{port} "
          f"(threads={threads})")
    serve(app, host=host, port=port, threads=threads)
    return 0


def _write_logs(logs: list, destination: str) -> None:
    path = Path(destination)
    if not path.is_absolute():
        path = get_config().project_root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in logs:
            f.write(entry.raw + "\n")
