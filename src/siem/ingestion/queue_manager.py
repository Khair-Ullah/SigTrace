"""Thread-safe in-memory queue connecting ingestion to parsing (FR-08)."""
from __future__ import annotations

import queue
import time
from typing import Optional

from siem.core.constants import DEFAULT_QUEUE_MAX_SIZE
from siem.core.logger import get_logger
from siem.ingestion.base import RawLogRecord

log = get_logger("ingestion.queue")

# Sentinel placed on the queue to wake consumers on shutdown
SHUTDOWN_SENTINEL = object()


class LogQueue:
    """Bounded, thread-safe FIFO queue of RawLogRecord.

    Two put flavours:

    * ``put`` (non-blocking) drops the record when full - used by producers
      that cannot be backpressured (UDP syslog).
    * ``put_blocking`` waits up to ``timeout`` seconds for space - used by
      file tailing, TCP syslog and the HTTP ingest API so nothing is lost
      under burst load (the producer retries from its own checkpoint).
    """

    def __init__(self, max_size: int = DEFAULT_QUEUE_MAX_SIZE):
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._dropped = 0
        self._accepted = 0
        self._blocked_timeouts = 0

    def put(self, record: RawLogRecord | object) -> bool:
        """Enqueue a record. Returns True if accepted, False if dropped."""
        try:
            self._queue.put_nowait(record)
            self._accepted += 1
            return True
        except queue.Full:
            self._dropped += 1
            # Rate-limited warning: only log every 1000 drops
            if self._dropped % 1000 == 1:
                log.warning("Ingestion queue full; dropped %d records so far", self._dropped)
            return False

    def put_blocking(
        self, record: RawLogRecord | object, timeout: float = 2.0
    ) -> bool:
        """Enqueue, waiting up to ``timeout`` seconds for queue space.

        Returns True if accepted; False on timeout (caller decides whether
        to drop or retry). Shutdown sentinels are handled by ``shutdown``.
        """
        if timeout <= 0:
            return self.put(record)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._blocked_timeouts += 1
                log.warning(
                    "Ingestion queue still full after %.1fs; producer will retry",
                    timeout,
                )
                return False
            try:
                self._queue.put(record, block=True, timeout=min(remaining, 0.25))
                self._accepted += 1
                return True
            except queue.Full:
                continue

    def get(self, timeout: float | None = None) -> Optional[RawLogRecord | object]:
        """Blocking get with optional timeout. Returns None on timeout."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_nowait(self) -> Optional[RawLogRecord | object]:
        """Non-blocking get. Returns None if empty."""
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def task_done(self) -> None:
        self._queue.task_done()

    def shutdown(self) -> None:
        """Signal consumers to stop by enqueuing the sentinel."""
        try:
            self._queue.put_nowait(SHUTDOWN_SENTINEL)
        except queue.Full:
            # Force space for the sentinel
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            self._queue.put_nowait(SHUTDOWN_SENTINEL)

    @property
    def size(self) -> int:
        return self._queue.qsize()

    @property
    def is_empty(self) -> bool:
        return self._queue.empty()

    @property
    def stats(self) -> dict:
        return {
            "size": self._queue.qsize(),
            "max_size": self._queue.maxsize,
            "accepted": self._accepted,
            "dropped": self._dropped,
            "blocked_timeouts": self._blocked_timeouts,
        }
