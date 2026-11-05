"""Collector interface: sources push dicts into the spool via ``emit``."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Callable

# emit(record: dict) -> bool (False when the spool rejected the write)
EmitFn = Callable[[dict], bool]


class BaseCollector(ABC):
    def __init__(self, emit: EmitFn, name: str):
        self.emit = emit
        self.name = name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.stats: dict = {}

    @abstractmethod
    def start(self) -> None:
        """Start collecting (non-blocking; use a background thread)."""

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
