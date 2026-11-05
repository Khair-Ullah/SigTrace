"""Unit tests for the ingestion queue manager."""
from siem.ingestion.base import RawLogRecord
from siem.ingestion.queue_manager import SHUTDOWN_SENTINEL, LogQueue


def _rec(text: str = "line") -> RawLogRecord:
    return RawLogRecord(raw=text, source_id="s", source_type="file")


def test_put_and_get():
    q = LogQueue(max_size=10)
    assert q.put(_rec("a")) is True
    assert q.put(_rec("b")) is True
    assert q.size == 2
    assert q.get(timeout=1).raw == "a"
    assert q.get(timeout=1).raw == "b"
    assert q.is_empty


def test_drops_when_full():
    q = LogQueue(max_size=2)
    assert q.put(_rec()) is True
    assert q.put(_rec()) is True
    assert q.put(_rec()) is False  # dropped
    assert q.stats["dropped"] == 1
    assert q.stats["accepted"] == 2


def test_get_timeout_returns_none():
    q = LogQueue(max_size=1)
    assert q.get(timeout=0.1) is None


def test_shutdown_sentinel():
    q = LogQueue(max_size=1)
    q.shutdown()
    assert q.get(timeout=1) is SHUTDOWN_SENTINEL
