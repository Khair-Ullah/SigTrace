"""Sliding-window state for stateful/threshold rules (FR-22, FR-23)."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

from siem.core.logger import get_logger

log = get_logger("engine.state")


class StateManager:
    """In-memory sliding-window counters keyed by (rule_id, group_key).

    Each bucket holds a list of (timestamp, event_id) tuples within the active
    window. Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], list[tuple[datetime, str]]] = {}

    def increment(
        self,
        rule_id: str,
        group_key: str,
        timestamp: datetime,
        window_seconds: int,
        event_id: str = "",
    ) -> tuple[int, list[str]]:
        """Add an occurrence and return (count in window, event_ids in window)."""
        key = (rule_id, group_key)
        cutoff = timestamp - timedelta(seconds=window_seconds)
        with self._lock:
            bucket = self._buckets.setdefault(key, [])
            bucket.append((timestamp, event_id))
            bucket[:] = [(t, eid) for (t, eid) in bucket if t >= cutoff]
            ids = [eid for (_t, eid) in bucket if eid]
            return len(bucket), ids

    def reset(self, rule_id: str, group_key: str) -> None:
        with self._lock:
            self._buckets.pop((rule_id, group_key), None)

    def count(self, rule_id: str, group_key: str) -> int:
        with self._lock:
            return len(self._buckets.get((rule_id, group_key), []))

    def prune(self, now: datetime, max_window_seconds: int) -> int:
        """Drop buckets with no entries in the last max_window. Returns removed count."""
        cutoff = now - timedelta(seconds=max_window_seconds)
        removed = 0
        with self._lock:
            for key in list(self._buckets):
                bucket = self._buckets[key]
                bucket[:] = [(t, eid) for (t, eid) in bucket if t >= cutoff]
                if not bucket:
                    del self._buckets[key]
                    removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)
