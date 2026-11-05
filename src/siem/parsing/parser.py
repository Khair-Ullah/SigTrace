"""Main parsing orchestrator: RawLogRecord -> NormalizedEvent (FR-10..FR-16)."""
from __future__ import annotations

from typing import Optional

from siem.core.config import Config, get_config
from siem.core.constants import SEVERITY_ORDER
from siem.core.logger import get_logger
from siem.ingestion.base import RawLogRecord
from siem.parsing import detectors
from siem.parsing.models import NormalizedEvent
from siem.parsing.normalizer import normalize
from siem.parsing.parsers import csv_parser as csv_parser_mod
from siem.parsing.parsers import json_parser, pfsense_parser, plaintext_parser, syslog_parser

log = get_logger("parsing.parser")


class LogParser:
    """Detects log format and produces normalized events."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._csv = csv_parser_mod.CSVParser()
        self.stats = {"parsed": 0, "failed": 0, "headers": 0, "by_format": {}}

    # -- public API -------------------------------------------------------
    def parse(
        self, record: RawLogRecord, format_hint: Optional[str] = None
    ) -> Optional[NormalizedEvent]:
        """Parse one raw record. Returns None if unparseable / consumed."""
        fmt = detectors.detect_format(record.raw, format_hint)
        try:
            fields, consumed = self._dispatch(fmt, record)
        except Exception as e:  # never crash the pipeline on a bad line
            self.stats["failed"] += 1
            log.warning("Parse error (%s) for source %s: %s | raw=%r",
                        fmt, record.source_id, e, record.raw[:200])
            return None

        if consumed:
            self.stats["headers"] += 1
            return None

        if fields is None:
            self.stats["failed"] += 1
            log.debug("Unparseable %s line from %s (quarantined): %r",
                      fmt, record.source_id, record.raw[:200])
            return None

        event = normalize(fields, record)
        self.stats["parsed"] += 1
        self.stats["by_format"][fmt] = self.stats["by_format"].get(fmt, 0) + 1
        return event

    # -- internals --------------------------------------------------------
    def _dispatch(self, fmt: str, record: RawLogRecord) -> tuple[Optional[dict], bool]:
        if fmt == detectors.FORMAT_JSON:
            return json_parser.parse(record.raw), False

        if fmt == detectors.FORMAT_SYSLOG:
            return self._dispatch_syslog(record), False

        if fmt == detectors.FORMAT_CSV:
            fields, is_header = self._csv.parse(record.raw, record.source_id)
            return fields, is_header

        return self._parse_body(record.raw), False

    def _parse_body(self, text: str) -> dict:
        """Parse a text log body: vendor-specific parsers first, then heuristics."""
        return pfsense_parser.parse(text) or plaintext_parser.parse(text)

    def _dispatch_syslog(self, record: RawLogRecord) -> dict:
        fields = syslog_parser.parse(record.raw)
        if fields is None:
            # Fall back to plaintext extraction if the syslog frame is malformed
            return self._parse_body(record.raw)

        # Enrich the syslog message body with content-based fields (IPs, event
        # type, user, ports) while keeping the syslog frame metadata.
        inner = self._parse_body(fields.get("message", ""))
        merged = {**inner, **fields}
        if inner.get("event_type") and inner["event_type"] != "generic":
            merged["severity"] = self._higher_severity(
                fields.get("severity"), inner.get("severity")
            )
        return merged

    @staticmethod
    def _higher_severity(a: str | None, b: str | None) -> str:
        a = a or "low"
        b = b or "low"
        return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b
