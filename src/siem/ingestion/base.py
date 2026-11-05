"""Base types and abstract ingestor for the log ingestion layer."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from siem.core.utils import utcnow

if TYPE_CHECKING:
    from siem.ingestion.queue_manager import LogQueue


@dataclass
class RawLogRecord:
    """A raw log line captured from a syslog or file source.

    This is the unit of data handed from ingestion to parsing.
    """

    raw: str
    source_id: str
    source_type: str
    received_at: datetime = field(default_factory=utcnow)
    transport: str = "unknown"  # "udp", "tcp", "file", "http"
    peer: Optional[str] = None  # "ip:port" for syslog
    file_path: Optional[str] = None
    format_hint: Optional[str] = None  # force a parser: json/syslog/csv/plaintext

    def __post_init__(self) -> None:
        if isinstance(self.raw, bytes):  # defensive
            self.raw = self.raw.decode("utf-8", errors="replace")
        self.raw = self.raw.rstrip("\r\n")


class BaseIngestor(ABC):
    """Abstract base class for all log ingestors."""

    def __init__(self, queue: "LogQueue", name: str | None = None):
        self.queue = queue
        self.name = name or self.__class__.__name__
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @abstractmethod
    def start(self) -> None:
        """Begin ingesting logs (non-blocking; use threads internally)."""

    @abstractmethod
    def stop(self, timeout: float = 5.0) -> None:
        """Stop ingesting and release resources."""

    def emit(self, record: RawLogRecord) -> bool:
        """Enqueue a record. Returns False if the queue is full."""
        return self.queue.put(record)
