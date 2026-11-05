"""End-to-end processing pipeline (Phase 9).

Ties the layers together:

    ingestion -> parsing -> rule engine -> correlation -> storage -> alerting

The pipeline can run in two modes:

* **synchronous** — feed individual raw lines/events/files (used by the ``siem
  ingest``/``siem simulate`` CLI commands and by tests); and
* **streaming** — start the configured ingestors and consume their queue on a
  background worker thread (used by ``siem run``).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from siem.alerting.manager import AlertNotifier
from siem.alerting.notification import NotificationResult
from siem.core.config import Config, get_config
from siem.core.constants import EVENT_BATCH_SECONDS, EVENT_BATCH_SIZE
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.engine.correlation_rules import CorrelationRuleLoader
from siem.engine.correlator import Correlator
from siem.engine.models import Alert, Incident, Rule
from siem.engine.rule_engine import RuleEngine
from siem.engine.rule_loader import RuleLoader
from siem.ingestion.base import RawLogRecord
from siem.ingestion.factory import build_ingestors
from siem.ingestion.queue_manager import SHUTDOWN_SENTINEL, LogQueue
from siem.parsing.parser import LogParser
from siem.soar.engine import PlaybookEngine
from siem.soar.models import PlaybookRun

log = get_logger("pipeline")

AlertCallback = Callable[[Alert, Optional[Incident]], None]


@dataclass
class ProcessedAlert:
    """A single alert produced by the pipeline, with its context."""

    alert: Alert
    incident: Optional[Incident] = None
    notifications: list[NotificationResult] = field(default_factory=list)
    playbook_runs: list[PlaybookRun] = field(default_factory=list)


@dataclass
class PipelineStats:
    """Running counters for the pipeline."""

    records: int = 0
    parsed: int = 0
    parse_failures: int = 0
    alerts: int = 0
    incidents_created: int = 0
    notifications_sent: int = 0
    soar_runs: int = 0
    soar_actions: int = 0
    soar_failures: int = 0
    errors: int = 0

    def as_dict(self) -> dict:
        return {
            "records": self.records,
            "parsed": self.parsed,
            "parse_failures": self.parse_failures,
            "alerts": self.alerts,
            "incidents_created": self.incidents_created,
            "notifications_sent": self.notifications_sent,
            "soar_runs": self.soar_runs,
            "soar_actions": self.soar_actions,
            "soar_failures": self.soar_failures,
            "errors": self.errors,
        }


class Pipeline:
    """Coordinates parsing, detection, correlation, persistence and alerting."""

    def __init__(
        self,
        config: Optional[Config] = None,
        storage=None,
        *,
        parser: Optional[LogParser] = None,
        rule_loader: Optional[RuleLoader] = None,
        rules: Optional[list[Rule]] = None,
        engine: Optional[RuleEngine] = None,
        correlator: Optional[Correlator] = None,
        notifier: Optional[AlertNotifier] = None,
        playbook_engine: Optional[PlaybookEngine] = None,
        enable_soar: bool = True,
        on_alert: Optional[AlertCallback] = None,
        persist: bool = True,
    ):
        self.config = config or get_config()
        self.storage = storage
        self.persist = bool(persist and storage is not None)
        self.on_alert = on_alert

        self.parser = parser or LogParser(self.config)
        self.rule_loader = rule_loader or RuleLoader(self.config)
        if rules is None:
            rules = self.rule_loader.load()
        self.rules = list(rules)
        self.engine = engine or RuleEngine(self.rules, self.config)
        self.correlator = correlator or Correlator(
            self.config, correlation_rules=CorrelationRuleLoader(self.config).load()
        )
        notification_repo = getattr(storage, "notifications", None) if storage else None
        self.notifier = notifier or AlertNotifier(self.config, notification_repo=notification_repo)
        self.playbook_engine = playbook_engine
        if self.playbook_engine is None and enable_soar:
            self.playbook_engine = PlaybookEngine(self.config)

        self.stats = PipelineStats()

        # Streaming state
        self._queue: Optional[LogQueue] = None
        self._ingestors: list = []
        self._worker: Optional[threading.Thread] = None
        self._retention_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._running = False
        self._streaming = False
        self._last_retention: Optional[dict] = None

        # Streaming event persistence buffer (see _buffer_event)
        self._event_buffer: list = []
        self._event_buffer_started: Optional[float] = None

        if self.persist:
            self.storage.sync_rules(self.rules)

    # -- synchronous processing ------------------------------------------
    def process_record(self, record: RawLogRecord) -> list[ProcessedAlert]:
        """Parse and process one raw record."""
        self.stats.records += 1
        event = self.parser.parse(record, format_hint=record.format_hint)
        if event is None:
            self.stats.parse_failures += 1
            return []
        return self._process_event(event)

    def process_raw(
        self,
        raw: str,
        source_id: str = "manual",
        source_type: str = "custom",
        transport: str = "manual",
        received_at=None,
    ) -> list[ProcessedAlert]:
        """Convenience wrapper to process a raw log line."""
        record = RawLogRecord(
            raw=raw,
            source_id=source_id,
            source_type=source_type,
            transport=transport,
            received_at=received_at or utcnow(),
        )
        return self.process_record(record)

    def ingest_lines(
        self,
        lines: Iterable[str],
        source_id: str = "manual",
        source_type: str = "custom",
    ) -> list[ProcessedAlert]:
        results: list[ProcessedAlert] = []
        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            results.extend(
                self.process_raw(
                    line, source_id=source_id, source_type=source_type, transport="file"
                )
            )
        return results

    def ingest_file(
        self,
        path: str | Path,
        source_id: Optional[str] = None,
        source_type: str = "custom",
    ) -> list[ProcessedAlert]:
        """Read a file line-by-line and process it through the pipeline."""
        p = Path(path)
        if not p.is_absolute():
            p = self.config.project_root / p
        src = source_id or p.stem
        log.info("Ingesting file %s (source_id=%s)", p, src)
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return self.ingest_lines(f, source_id=src, source_type=source_type)

    def ingest_simulated(self, logs: Iterable) -> list[ProcessedAlert]:
        """Process a sequence of ``simulators.SimulatedLog`` objects."""
        results: list[ProcessedAlert] = []
        for entry in logs:
            results.extend(
                self.process_raw(
                    entry.raw,
                    source_id=entry.source_id,
                    source_type=entry.source_type,
                    transport="simulator",
                    received_at=getattr(entry, "timestamp", None),
                )
            )
        return results

    # -- event processing core -------------------------------------------
    def _process_event(self, event) -> list[ProcessedAlert]:
        self.stats.parsed += 1
        if self.persist:
            if self._streaming:
                self._buffer_event(event)
            else:
                self.storage.persist_event(event)

        processed: list[ProcessedAlert] = []
        for alert in self.engine.evaluate(event):
            result = self.correlator.correlate(alert)
            incident = result.incident

            if self.persist:
                if incident is not None:
                    self.storage.persist_incident(incident)
                self.storage.persist_alert(alert)

            notifications = self.notifier.notify(alert, incident) if self.notifier else []
            playbook_runs = self._run_playbooks(alert, incident)

            self.stats.alerts += 1
            if result.action == "created":
                self.stats.incidents_created += 1
            self.stats.notifications_sent += sum(1 for n in notifications if n.status == "sent")

            processed.append(
                ProcessedAlert(
                    alert=alert,
                    incident=incident,
                    notifications=notifications,
                    playbook_runs=playbook_runs,
                )
            )
            self._emit(alert, incident)
        return processed

    def _run_playbooks(self, alert: Alert, incident: Optional[Incident]) -> list[PlaybookRun]:
        if incident is None or self.playbook_engine is None:
            return []
        try:
            runs = self.playbook_engine.evaluate(incident, alert)
        except Exception:  # automated response must never break detection
            self.stats.errors += 1
            log.exception("SOAR playbook evaluation failed for incident %s", incident.incident_id)
            return []

        self.stats.soar_runs += len(runs)
        self.stats.soar_actions += sum(len(run.actions) for run in runs)
        self.stats.soar_failures += sum(1 for run in runs if run.status in ("failed", "partial"))
        return runs

    def _emit(self, alert: Alert, incident: Optional[Incident]) -> None:
        if self.on_alert is None:
            return
        try:
            self.on_alert(alert, incident)
        except Exception:  # a listener must never break the pipeline
            log.exception("on_alert callback failed for alert %s", alert.alert_id)

    # -- streaming event batching ----------------------------------------
    def _buffer_event(self, event) -> None:
        """Queue a parsed event for bulk persistence (streaming mode only)."""
        now = time.monotonic()
        if not self._event_buffer:
            self._event_buffer_started = now
        self._event_buffer.append(event)
        aged_out = (
            self._event_buffer_started is not None
            and now - self._event_buffer_started >= EVENT_BATCH_SECONDS
        )
        if len(self._event_buffer) >= EVENT_BATCH_SIZE or aged_out:
            self._flush_event_buffer()

    def _flush_event_buffer(self) -> None:
        """Bulk-persist buffered events; never raises (loss is logged)."""
        if not self._event_buffer:
            return
        batch, self._event_buffer = self._event_buffer, []
        self._event_buffer_started = None
        try:
            self.storage.persist_events(batch)
        except Exception:
            self.stats.errors += 1
            log.exception("Failed to persist batch of %d events", len(batch))

    # -- HTTP ingest entry point -----------------------------------------
    def enqueue_records(self, records: list[RawLogRecord], timeout: float = 2.0) -> int:
        """Hand records to the streaming queue with backpressure.

        Returns the number accepted. Raises ``RuntimeError`` when the
        streaming queue is not running so callers can fall back to
        synchronous processing.
        """
        if self._queue is None or not self._running:
            raise RuntimeError("pipeline streaming queue is not running")
        accepted = 0
        for record in records:
            if self._queue.put_blocking(record, timeout=timeout):
                accepted += 1
            else:
                break  # queue saturated: stop early, caller retries the rest
        return accepted

    # -- streaming mode ---------------------------------------------------
    def run(self, block: bool = True) -> None:
        """Start ingestors and consume the queue on a background worker."""
        if self._running:
            return
        self._queue = LogQueue()
        self._ingestors = build_ingestors(self.config, self._queue)
        self._stop.clear()
        self._running = True
        self._streaming = True

        self._worker = threading.Thread(
            target=self._consume_loop, name="pipeline-worker", daemon=True
        )
        self._worker.start()
        self._maybe_start_retention()

        for ingestor in self._ingestors:
            try:
                ingestor.start()
            except Exception:
                log.exception("Failed to start ingestor %s", ingestor.name)

        try:
            self.rule_loader.watch(on_change=self._on_rules_changed)
        except Exception:  # watching is best-effort
            log.exception("Failed to start rule hot-reload watcher")

        log.info("Pipeline running with %d ingestor(s)", len(self._ingestors))
        if not block:
            return
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            log.info("Shutdown requested")
        finally:
            self.stop()

    def _consume_loop(self) -> None:
        assert self._queue is not None
        while not self._stop.is_set():
            item = self._queue.get(timeout=0.5)
            if item is None:
                # Queue idle: flush buffered events so data is never held
                # back longer than EVENT_BATCH_SECONDS + this idle window.
                self._flush_event_buffer()
                continue
            if item is SHUTDOWN_SENTINEL:
                self._flush_event_buffer()
                break
            try:
                self.process_record(item)
            except Exception:
                self.stats.errors += 1
                log.exception("Pipeline failed to process record")
            finally:
                self._queue.task_done()

    # -- retention --------------------------------------------------------
    def _maybe_start_retention(self) -> None:
        """Start the periodic retention/pruning thread when configured."""
        if not self.persist or self.storage is None:
            return
        interval_hours = float(self.config.get("retention.interval_hours", 0) or 0)
        if interval_hours <= 0:
            log.info("Retention scheduler disabled (retention.interval_hours=0)")
            return
        self._retention_thread = threading.Thread(
            target=self._retention_loop,
            args=(interval_hours,),
            name="pipeline-retention",
            daemon=True,
        )
        self._retention_thread.start()
        log.info("Retention scheduler started (every %.1fh)", interval_hours)

    def _retention_loop(self, interval_hours: float) -> None:
        interval = interval_hours * 3600.0
        # Wait first so we don't prune immediately at startup.
        while not self._stop.wait(interval):
            try:
                result = self.storage.run_retention()
                self._last_retention = result
                log.info("Retention cleanup finished: %s", result)
            except Exception:  # retention must never kill the pipeline
                log.exception("Retention cleanup failed")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop ingestors, drain the worker and stop the rule watcher."""
        if not self._running:
            return
        self._stop.set()
        if self._retention_thread is not None:
            self._retention_thread.join(timeout=timeout)
            self._retention_thread = None
        for ingestor in self._ingestors:
            try:
                ingestor.stop(timeout=timeout)
            except Exception:
                log.exception("Error stopping ingestor %s", ingestor.name)
        if self._queue is not None:
            self._queue.shutdown()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
        self._flush_event_buffer()
        self._streaming = False
        try:
            self.rule_loader.stop_watch()
        except Exception:
            log.exception("Error stopping rule watcher")
        self._running = False
        log.info("Pipeline stopped (stats=%s)", self.stats.as_dict())

    @property
    def is_running(self) -> bool:
        return self._running

    # -- helpers ----------------------------------------------------------
    def _on_rules_changed(self, rules: list[Rule]) -> None:
        self.rules = list(rules)
        self.engine.set_rules(self.rules)
        if self.persist:
            self.storage.sync_rules(self.rules)
        log.info("Pipeline hot-reloaded %d rule(s)", len(self.rules))

    def summary(self) -> dict:
        data = self.stats.as_dict()
        if self._queue is not None:
            data["queue"] = self._queue.stats
        data["correlator"] = dict(self.correlator.stats)
        data["engine"] = dict(self.engine.stats)
        if self.playbook_engine is not None:
            data["soar"] = self.playbook_engine.summary()
        if self._last_retention is not None:
            data["retention"] = self._last_retention
        return data
