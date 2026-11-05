"""Agent runner: wires config -> spool -> collectors -> shipper."""
from __future__ import annotations

import logging
import threading

from siem_agent.collector.base import BaseCollector
from siem_agent.collector.file_tail import FileTailCollector
from siem_agent.collector.windows_events import WindowsEventCollector
from siem_agent.config import AgentConfig
from siem_agent.shipper import Shipper
from siem_agent.spool import Spool

log = logging.getLogger("siem_agent.runner")

STATS_INTERVAL_SECONDS = 300.0


class AgentRunner:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.spool = Spool(config.spool_dir, max_mb=config.spool_max_mb)
        self.shipper = Shipper(
            self.spool,
            ingest_url=config.ingest_url,
            token=config.token,
            batch_size=config.batch_size,
            flush_interval=config.flush_interval,
            timeout=config.request_timeout,
        )
        self.collectors: list[BaseCollector] = self._build_collectors()
        self._stop_event = threading.Event()
        self._stats_thread: threading.Thread | None = None

    def _build_collectors(self) -> list[BaseCollector]:
        collectors: list[BaseCollector] = []
        if self.config.files:
            collectors.append(
                FileTailCollector(
                    emit=self.spool.append,
                    sources=self.config.files,
                    offsets_path=self.config.spool_dir / "file_offsets.json",
                    read_from_beginning=self.config.read_from_beginning,
                    tail_interval=self.config.tail_interval,
                )
            )
        if self.config.windows_enabled:
            collectors.append(
                WindowsEventCollector(
                    emit=self.spool.append,
                    channels=self.config.windows_channels,
                    cursor_path=self.config.spool_dir / "winlog_cursor.json",
                    poll_interval=self.config.windows_poll_interval,
                    max_events_per_poll=self.config.windows_max_events,
                )
            )
        return collectors

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        log.info(
            "Starting siem-agent -> %s (spool=%s, collectors=%d)",
            self.config.ingest_url,
            self.config.spool_dir,
            len(self.collectors),
        )
        self.shipper.start()
        for collector in self.collectors:
            collector.start()
        self._stats_thread = threading.Thread(
            target=self._stats_loop, name="agent-stats", daemon=True
        )
        self._stats_thread.start()

    def wait(self, timeout: float | None = None) -> None:
        """Block until stopped (SIGINT/SIGTERM) or ``timeout`` elapses."""
        self._stop_event.wait(timeout)

    def stop(self) -> None:
        log.info("Stopping siem-agent ...")
        self._stop_event.set()
        for collector in self.collectors:
            try:
                collector.stop()
            except Exception as e:
                log.warning("Collector %s failed to stop cleanly: %s", collector.name, e)
        self.shipper.stop()
        self.spool.close()
        log.info("siem-agent stopped (spool stats=%s)", self.spool.stats())

    # -- stats ------------------------------------------------------------
    def _stats_loop(self) -> None:
        while not self._stop_event.wait(STATS_INTERVAL_SECONDS):
            stats = self.spool.stats()
            collector_stats = {c.name: c.stats for c in self.collectors}
            log.info("agent stats: spool=%s collectors=%s", stats, collector_stats)

    def status(self) -> dict:
        return {
            "spool": self.spool.stats(),
            "collectors": [{"name": c.name, "stats": c.stats} for c in self.collectors],
            "shipper_alive": self.shipper.is_alive(),
            "auth_failed": self.shipper.is_auth_failed,
        }
