"""Interactive local-log Monitor (Phase 10).

``SystemMonitor`` is a controllable background service that collects log data
from the local machine (Windows Event Log and/or configured files), feeds each
record through the normal processing pipeline, and exposes live status and a
bounded recent-event buffer for the admin dashboard "Monitor" tab.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from siem.core.config import Config
from siem.core.logger import get_logger
from siem.monitoring.collectors import (
    BaseCollector,
    FileSourceCollector,
    MonitorRecord,
    WindowsEventLogCollector,
)
from siem.storage.service import StorageService

log = get_logger("monitoring.system_monitor")

AlertCallback = Callable[[object, Optional[object]], None]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class SystemMonitor:
    """Collect local logs and run them through the detection pipeline."""

    def __init__(
        self,
        config: Config,
        storage: StorageService,
        on_alert: Optional[AlertCallback] = None,
        recent_size: int = 200,
    ) -> None:
        self.config = config
        self.storage = storage
        self.on_alert = on_alert
        self._recent: deque[dict] = deque(maxlen=max(10, recent_size))

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._pipeline = None

        self._running = False
        self._started_at: Optional[str] = None
        self._stopped_at: Optional[str] = None
        self._last_poll: Optional[str] = None
        self._processed = 0
        self._alerts = 0
        self._errors = 0

        self.collectors: list[BaseCollector] = self._build_collectors()

    # -- configuration ----------------------------------------------------

    def _mon_config(self) -> dict:
        return self.config.get("monitoring", {}) or {}

    def _build_collectors(self) -> list[BaseCollector]:
        mon = self._mon_config()
        collectors: list[BaseCollector] = []

        channels = mon.get("windows_event_logs") or []
        if channels:
            collectors.append(WindowsEventLogCollector(
                channels,
                max_per_poll=int(mon.get("max_events_per_poll", 50)),
            ))

        files = mon.get("files") or []
        if files:
            root = self.config.project_root
            collectors.append(FileSourceCollector(
                files,
                read_from_beginning=bool(mon.get("read_from_beginning", False)),
                project_root=root,
            ))
        return collectors

    @property
    def interval_seconds(self) -> int:
        return max(1, int(self._mon_config().get("interval_seconds", 5)))

    # -- lifecycle --------------------------------------------------------

    def start(self) -> dict:
        with self._lock:
            if self._running and self._thread and self._thread.is_alive():
                return self.status()
            if not self.collectors:
                log.warning("Monitor: no collectors configured")
            self._stop.clear()
            self._running = True
            self._started_at = _utcnow()
            self._stopped_at = None
            self._thread = threading.Thread(
                target=self._loop, name="siem-monitor", daemon=True
            )
            self._thread.start()
            log.info("Monitor started (interval=%ss, sources=%d)",
                     self.interval_seconds, len(self.collectors))
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=self.interval_seconds + 5)
        with self._lock:
            self._running = False
            self._stopped_at = _utcnow()
        log.info("Monitor stopped")
        return self.status()

    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    # -- main loop --------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.poll_once()
            except Exception:  # pragma: no cover - defensive
                with self._lock:
                    self._errors += 1
                log.exception("Monitor poll failed")

    def poll_once(self) -> int:
        """Run a single collection + processing cycle. Returns events processed."""
        pipeline = self._ensure_pipeline()
        total = 0
        for collector in self.collectors:
            for record in collector.poll():
                self._process_record(pipeline, record)
                total += 1
        with self._lock:
            self._last_poll = _utcnow()
            self._processed += total
        return total

    def _process_record(self, pipeline, record: MonitorRecord) -> None:
        try:
            results = pipeline.process_raw(
                record.raw,
                source_id=record.source_id,
                source_type=record.source_type,
            )
        except Exception as e:
            with self._lock:
                self._errors += 1
            log.warning("Monitor: failed to process record: %s", e)
            self._push_recent({**record.as_recent(), "alerts": 0, "error": str(e)})
            return

        new_alerts = 0
        for result in results or []:
            alert = getattr(result, "alert", None)
            if alert is None:
                continue
            new_alerts += 1
            if self.on_alert is not None:
                try:
                    self.on_alert(alert, getattr(result, "incident", None))
                except Exception:  # pragma: no cover
                    log.exception("Monitor alert callback failed")
        with self._lock:
            self._alerts += new_alerts
        self._push_recent({**record.as_recent(), "alerts": new_alerts})

    def _push_recent(self, item: dict) -> None:
        item = dict(item)
        item.setdefault("collected_at", _utcnow())
        self._recent.appendleft(item)

    def _ensure_pipeline(self):
        if self._pipeline is None:
            from siem.pipeline import Pipeline

            self._pipeline = Pipeline(self.config, self.storage)
        return self._pipeline

    # -- inspection -------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            return {
                "running": self.is_running(),
                "started_at": self._started_at,
                "stopped_at": self._stopped_at,
                "last_poll": self._last_poll,
                "interval_seconds": self.interval_seconds,
                "processed": self._processed,
                "alerts": self._alerts,
                "errors": self._errors,
                "recent_count": len(self._recent),
                "sources": [c.status() for c in self.collectors],
                "supported": self._platform_supported(),
            }

    def recent_events(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), self._recent.maxlen or 50))
        return list(self._recent)[:limit]

    def clear_recent(self) -> None:
        self._recent.clear()

    @staticmethod
    def _platform_supported() -> bool:
        import platform

        return platform.system().lower() == "windows"


__all__ = ["SystemMonitor"]
