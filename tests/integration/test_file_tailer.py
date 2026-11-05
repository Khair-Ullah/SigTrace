"""Integration tests for the file tailer (append + rotation)."""
from helpers import wait_for

from siem.ingestion.file_tailer import FileTailer
from siem.ingestion.queue_manager import LogQueue


def _drain(q):
    out = []
    while not q.is_empty:
        out.append(q.get_nowait().raw)
    return out


def test_tails_appended_lines(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("existing-1\nexisting-2\n", encoding="utf-8")

    q = LogQueue()
    tailer = FileTailer(
        q,
        sources=[{"path": str(log_file), "source_id": "app", "source_type": "web"}],
        read_from_beginning=True,
        tail_interval=0.1,
    )
    tailer.start()
    try:
        assert wait_for(lambda: q.size >= 2, timeout=5)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("new-line-1\nnew-line-2\n")
        assert wait_for(lambda: q.size >= 4, timeout=5)
        lines = _drain(q)
        assert lines == ["existing-1", "existing-2", "new-line-1", "new-line-2"]
    finally:
        tailer.stop()


def test_handles_rotation(tmp_path):
    log_file = tmp_path / "rot.log"
    log_file.write_text("before-rotation\n", encoding="utf-8")

    q = LogQueue()
    tailer = FileTailer(
        q,
        sources=[{"path": str(log_file), "source_id": "rot", "source_type": "firewall"}],
        read_from_beginning=True,
        tail_interval=0.1,
    )
    tailer.start()
    try:
        assert wait_for(lambda: q.size >= 1, timeout=5)

        # Rotate: move current file aside, create a fresh one
        rotated = tmp_path / "rot.log.1"
        log_file.rename(rotated)
        log_file.write_text("after-rotation-1\nafter-rotation-2\n", encoding="utf-8")

        assert wait_for(lambda: q.size >= 3, timeout=5)
        lines = _drain(q)
        assert "before-rotation" in lines
        assert "after-rotation-1" in lines
        assert "after-rotation-2" in lines
        assert tailer.stats["rotations"] >= 1
    finally:
        tailer.stop()
