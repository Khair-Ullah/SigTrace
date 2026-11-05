"""Factory to build all configured ingestors from the SIEM config."""
from __future__ import annotations

from siem.core.config import Config
from siem.core.logger import get_logger
from siem.ingestion.base import BaseIngestor
from siem.ingestion.file_tailer import FileTailer
from siem.ingestion.queue_manager import LogQueue
from siem.ingestion.syslog_server import SyslogServer

log = get_logger("ingestion.factory")


def build_ingestors(config: Config, queue: LogQueue) -> list[BaseIngestor]:
    """Instantiate ingestors for every enabled source in config."""
    ingestors: list[BaseIngestor] = []

    syslog_cfg = config.get("ingestion.syslog", {}) or {}
    if syslog_cfg.get("enabled", False):
        ingestors.append(SyslogServer(
            queue=queue,
            host=syslog_cfg.get("host", "0.0.0.0"),
            udp_port=int(syslog_cfg.get("udp_port", 514)),
            tcp_port=int(syslog_cfg.get("tcp_port", 514)),
            source_id=syslog_cfg.get("source_id", "syslog"),
            source_type=syslog_cfg.get("source_type", "syslog"),
        ))

    files_cfg = config.get("ingestion.files", {}) or {}
    sources = files_cfg.get("sources", []) or []
    if sources:
        ingestors.append(FileTailer(
            queue=queue,
            sources=sources,
            read_from_beginning=bool(files_cfg.get("read_from_beginning", False)),
            tail_interval=float(files_cfg.get("tail_interval_seconds", 0.5)),
            checkpoint_file=files_cfg.get("checkpoint_file"),
            queue_timeout=float(files_cfg.get("queue_timeout_seconds", 2.0)),
        ))

    log.info("Configured %d ingestor(s)", len(ingestors))
    return ingestors
