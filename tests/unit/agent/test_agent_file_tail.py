"""Tests for the agent file tail collector."""
from __future__ import annotations

import json
import os
import time

from siem_agent.collector.file_tail import FileTailCollector


def _make(tmp_path, records, **kw):
    """Build a collector whose emit appends into ``records`` (list of dicts)."""

    def emit(record: dict) -> bool:
        records.append(record)
        return True

    return FileTailCollector(
        emit=emit,
        sources=kw.pop(
            "sources",
            [
                {"path": str(tmp_path / "app.log"), "source_id": "app", "source_type": "custom"},
            ],
        ),
        offsets_path=tmp_path / "offsets.json",
        **kw,
    )


def _read_once(collector):
    for state in collector._states:
        collector._read_new(state)


def test_reads_appended_lines_from_beginning(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("first\nsecond\n", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=True)
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)

    assert [r["raw"] for r in records] == ["first", "second"]
    assert records[0]["source_id"] == "app"
    assert records[0]["source_type"] == "custom"


def test_partial_line_buffered_until_newline(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("complete\nno-newline-yet", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=True)
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)
    assert [r["raw"] for r in records] == ["complete"]

    with open(log, "a", encoding="utf-8") as f:
        f.write("-done\n")
    _read_once(collector)
    assert records[-1]["raw"] == "no-newline-yet-done"


def test_checkpoint_resume_only_new_lines(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("old-1\nold-2\n", encoding="utf-8")

    records: list[dict] = []
    c1 = _make(tmp_path, records, read_from_beginning=True)
    for state in c1._states:
        c1._open_with_checkpoint(state)
    _read_once(c1)
    for state in c1._states:
        c1._save(state, force=True)
    c1.stop(timeout=0.1)  # closes handles + saves
    assert len(records) == 2

    with open(log, "a", encoding="utf-8") as f:
        f.write("new-1\n")

    records2: list[dict] = []
    c2 = _make(tmp_path, records2, read_from_beginning=False)
    for state in c2._states:
        c2._open_with_checkpoint(state)
    _read_once(c2)
    assert [r["raw"] for r in records2] == ["new-1"]


def test_first_run_without_checkpoint_starts_at_eof(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("history\n", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=False)
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)
    assert records == []

    with open(log, "a", encoding="utf-8") as f:
        f.write("fresh\n")
    _read_once(collector)
    assert [r["raw"] for r in records] == ["fresh"]


def test_rotation_detected_and_new_file_read(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("before-rot\n", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=True)
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)

    os.rename(log, tmp_path / "app.log.1")
    with open(log, "w", encoding="utf-8") as f:
        f.write("after-rot\n")
    _read_once(collector)

    assert [r["raw"] for r in records] == ["before-rot", "after-rot"]
    assert collector.stats["rotations"] == 1


def test_emit_failure_rolls_back_position(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("keep-me\nalso-keep\n", encoding="utf-8")

    records: list[dict] = []
    attempt = {"n": 0, "fail_on": 2}

    def emit(record: dict) -> bool:
        attempt["n"] += 1
        if attempt["n"] == attempt["fail_on"]:
            return False
        records.append(record)
        return True

    collector = FileTailCollector(
        emit=emit,
        sources=[{"path": str(log), "source_id": "app", "source_type": "custom"}],
        offsets_path=tmp_path / "offsets.json",
        read_from_beginning=True,
    )
    for state in collector._states:
        collector._open_with_checkpoint(state)

    # First line succeeds, second line fails -> rollback to the failed line.
    collector._read_new(collector._states[0])
    assert [r["raw"] for r in records] == ["keep-me"]
    assert collector.stats["write_failures"] == 1

    # Retry emits the failed line exactly once (no duplicate of line one).
    attempt["fail_on"] = -1
    collector._read_new(collector._states[0])
    assert [r["raw"] for r in records] == ["keep-me", "also-keep"]


def test_format_hint_passthrough(tmp_path):
    log = tmp_path / "access.log"
    log.write_text('{"msg": "json line"}\n', encoding="utf-8")

    records: list[dict] = []
    collector = _make(
        tmp_path,
        records,
        read_from_beginning=True,
        sources=[
            {"path": str(log), "source_id": "web", "source_type": "web", "format_hint": "json"}
        ],
    )
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)
    assert records[0]["format_hint"] == "json"


def test_missing_file_is_tolerated(tmp_path):
    records: list[dict] = []
    collector = _make(
        tmp_path,
        records,
        read_from_beginning=True,
        sources=[
            {"path": str(tmp_path / "absent.log"), "source_id": "absent", "source_type": "custom"}
        ],
    )
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)  # must not raise
    assert records == []


def test_start_stop_thread_lifecycle(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("t1\n", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=True, tail_interval=0.05)
    collector.start()
    deadline = time.time() + 5
    while not records and time.time() < deadline:
        time.sleep(0.02)
    collector.stop()
    assert [r["raw"] for r in records] == ["t1"]


def test_offsets_json_shape(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("a\nb\n", encoding="utf-8")

    records: list[dict] = []
    collector = _make(tmp_path, records, read_from_beginning=True)
    for state in collector._states:
        collector._open_with_checkpoint(state)
    _read_once(collector)
    for state in collector._states:
        collector._save(state, force=True)

    data = json.loads((tmp_path / "offsets.json").read_text(encoding="utf-8"))
    entry = data[str(log)]
    assert set(entry.keys()) == {"position", "inode", "device"}
    # both lines consumed (size accounts for any CRLF translation on Windows)
    assert entry["position"] == log.stat().st_size
