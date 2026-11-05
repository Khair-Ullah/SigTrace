"""Log ingestion layer: syslog and file sources feeding the processing queue."""
from siem.ingestion.base import BaseIngestor, RawLogRecord
from siem.ingestion.file_tailer import FileTailer, FileSource
from siem.ingestion.factory import build_ingestors
from siem.ingestion.queue_manager import LogQueue, SHUTDOWN_SENTINEL
from siem.ingestion.syslog_server import SyslogServer

__all__ = [
    "BaseIngestor",
    "RawLogRecord",
    "FileTailer",
    "FileSource",
    "SyslogServer",
    "LogQueue",
    "SHUTDOWN_SENTINEL",
    "build_ingestors",
]
