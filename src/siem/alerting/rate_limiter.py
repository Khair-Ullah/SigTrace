"""Thread-safe sliding-window rate limiter (FR-51)."""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Optional

from siem.core.utils import utcnow


class SlidingWindowRateLimiter:
    """Allow at most ``max_events`` events per ``window_seconds``."""

    def __init__(self, max_events: int, window_seconds: float = 60.0):
        self.max_events = max(0, int(max_events))
        self.window = timedelta(seconds=window_seconds)
        self._events: deque[datetime] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: datetime) -> None:
        cutoff = now - self.window
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()

    def allow(self, now: Optional[datetime] = None) -> bool:
        """Record an attempt and return True if within the limit."""
        now = now or utcnow()
        with self._lock:
            self._prune(now)
            if len(self._events) >= self.max_events:
                return False
            self._events.append(now)
            return True

    def remaining(self, now: Optional[datetime] = None) -> int:
        now = now or utcnow()
        with self._lock:
            self._prune(now)
            return max(0, self.max_events - len(self._events))

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
