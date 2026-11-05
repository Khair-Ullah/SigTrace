"""Log collectors for the siem-agent."""
from __future__ import annotations

from siem_agent.collector.base import BaseCollector
from siem_agent.collector.file_tail import FileTailCollector
from siem_agent.collector.windows_events import WindowsEventCollector

__all__ = ["BaseCollector", "FileTailCollector", "WindowsEventCollector"]
