"""Tests for the agent disk spool (at-least-once queue)."""
from __future__ import annotations

import json

from siem_agent.spool import Spool


def _rec(n: int) -> dict:
    return {"raw": f"line-{n}", "source_id": "t", "source_type": "custom"}


def test_append_read_ack_roundtrip(tmp_path):
    spool = Spool(tmp_path / "spool", max_mb=10)
    for i in range(5):
        assert spool.append(_rec(i)) is True

    batch = spool.read_batch(3)
    assert [r["raw"] for r in batch] == ["line-0", "line-1", "line-2"]
    spool.ack()

    batch2 = spool.read_batch(10)
    assert [r["raw"] for r in batch2] == ["line-3", "line-4"]
    spool.ack()

    assert spool.read_batch(10) == []
    # fully drained: active segment removed once consumed
    assert spool.pending_bytes() == 0


def test_nack_rereads_same_batch(tmp_path):
    spool = Spool(tmp_path / "spool", max_mb=10)
    for i in range(3):
        spool.append(_rec(i))

    batch = spool.read_batch(2)
    assert len(batch) == 2
    spool.nack()
    again = spool.read_batch(2)
    assert [r["raw"] for r in again] == ["line-0", "line-1"]


def test_restart_resumes_from_state(tmp_path):
    spool_dir = tmp_path / "spool"
    spool = Spool(spool_dir, max_mb=10)
    for i in range(5):
        spool.append(_rec(i))
    batch = spool.read_batch(2)
    assert len(batch) == 2
    spool.ack()
    spool.close()

    # Simulate restart: a fresh Spool over the same directory.
    spool2 = Spool(spool_dir, max_mb=10)
    remaining = spool2.read_batch(10)
    assert [r["raw"] for r in remaining] == ["line-2", "line-3", "line-4"]


def test_corrupt_line_skipped(tmp_path):
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir()
    with open(spool_dir / "queue-000001.ndjson", "wb") as f:
        f.write(b'{"raw": "ok-1"}\n')
        f.write(b"not-json-at-all\n")
        f.write(b'{"raw": "ok-2"}\n')

    spool = Spool(spool_dir, max_mb=10)
    batch = spool.read_batch(10)
    assert [r["raw"] for r in batch] == ["ok-1", "ok-2"]


def test_cap_drops_oldest_segments(tmp_path, monkeypatch):
    # Tiny segments + zero cap: appending forces rotation and drops.
    monkeypatch.setattr("siem_agent.spool._SEGMENT_MAX_BYTES", 80)
    spool = Spool(tmp_path / "spool", max_mb=0)
    for i in range(30):
        assert spool.append(_rec(i)) is True
    assert spool.dropped > 0

    # Whatever survived is still internally consistent.
    batch = spool.read_batch(100)
    assert batch  # newest data retained
    assert all("raw" in r for r in batch)


def test_state_file_written_after_ack(tmp_path):
    spool_dir = tmp_path / "spool"
    spool = Spool(spool_dir, max_mb=10)
    spool.append(_rec(0))
    spool.append(_rec(1))
    spool.read_batch(1)
    spool.ack()

    state = json.loads((spool_dir / "state.json").read_text(encoding="utf-8"))
    assert set(state.keys()) == {"segment", "offset"}


def test_unicode_survives(tmp_path):
    spool = Spool(tmp_path / "spool", max_mb=10)
    spool.append({"raw": "مرحبا", "source_id": "t", "source_type": "custom"})
    batch = spool.read_batch(1)
    assert batch[0]["raw"] == "مرحبا"
