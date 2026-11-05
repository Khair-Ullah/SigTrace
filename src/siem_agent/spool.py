"""Disk-backed spool: buffers records until the server acknowledges them.

Segments are append-only NDJSON files (``queue-000001.ndjson``). The read
pointer is persisted to ``state.json`` only after a successful ship, giving
at-least-once delivery: a crash can re-send the last un-acked batch, but
never lose data. When the spool exceeds ``max_mb``, the oldest complete
segments are dropped (counted, never the active segment).
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import IO, Optional

log = logging.getLogger("siem_agent.spool")

_SEGMENT_RE = re.compile(r"^queue-(\d{6})\.ndjson$")
_SEGMENT_MAX_BYTES = 10 * 1024 * 1024  # rotate the active segment at 10 MB


class Spool:
    def __init__(self, directory: Path, max_mb: int = 500):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_bytes = int(max_mb) * 1024 * 1024
        self._lock = threading.RLock()

        self._state_path = self._dir / "state.json"
        self._active_path: Optional[Path] = None
        self._active_file: Optional[IO[bytes]] = None
        self._active_size = 0

        # Read pointer (in-flight batch start + current position)
        self._read_segment: Optional[str] = None
        self._read_offset = 0
        self._batch_start: Optional[tuple[str, int]] = None

        self.appended = 0
        self.shipped = 0
        self.dropped = 0
        self.rejected = 0

        self._load_state()
        self._open_active()

    # -- segments ---------------------------------------------------------
    def _segments(self) -> list[str]:
        names = []
        for p in self._dir.iterdir():
            if p.is_file() and _SEGMENT_RE.match(p.name):
                names.append(p.name)
        return sorted(names)

    def _next_segment_path(self) -> Path:
        segments = self._segments()
        seq = 1
        if segments:
            match = _SEGMENT_RE.match(segments[-1])
            if match:
                seq = int(match.group(1)) + 1
        return self._dir / f"queue-{seq:06d}.ndjson"

    def _open_active(self) -> None:
        segments = self._segments()
        if segments:
            self._active_path = self._dir / segments[-1]
        else:
            self._active_path = self._next_segment_path()
        self._active_size = self._active_path.stat().st_size if self._active_path.exists() else 0
        self._active_file = open(self._active_path, "ab")

    def _rotate(self) -> None:
        if self._active_file:
            self._active_file.close()
        self._active_path = self._next_segment_path()
        self._active_size = 0
        self._active_file = open(self._active_path, "ab")

    def _total_bytes(self) -> int:
        total = 0
        for name in self._segments():
            try:
                total += (self._dir / name).stat().st_size
            except OSError:
                pass
        return total

    def _enforce_cap(self) -> None:
        """Drop oldest complete segments while over the size cap."""
        if self._total_bytes() <= self._max_bytes:
            return
        active_name = self._active_path.name if self._active_path else None
        for name in self._segments():
            if self._total_bytes() <= self._max_bytes:
                break
            if name == active_name:
                break  # never drop the segment being written
            try:
                size = (self._dir / name).stat().st_size
                (self._dir / name).unlink()
            except OSError:
                continue
            self.dropped += 1
            log.warning("Spool over cap: dropped segment %s (%d bytes)", name, size)
            if self._read_segment == name:
                # The reader was consuming this segment: skip to the next one.
                remaining = [s for s in self._segments() if s > name]
                self._read_segment = remaining[0] if remaining else None
                self._read_offset = 0
                self._save_state_locked()

    # -- write side -------------------------------------------------------
    def append(self, record: dict) -> bool:
        """Append one record. Returns False only on write failure."""
        data = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            try:
                if self._active_file is None:
                    self._open_active()
                if self._active_size + len(data) > _SEGMENT_MAX_BYTES:
                    self._rotate()
                af = self._active_file
                if af is None:
                    return False
                af.write(data)
                af.flush()
                self._active_size += len(data)
                self.appended += 1
            except (OSError, ValueError) as e:
                log.error("Spool append failed: %s", e)
                return False
            self._enforce_cap()
            return True

    # -- read side --------------------------------------------------------
    def _resolve_read_segment(self) -> Optional[str]:
        segments = self._segments()
        if not segments:
            return None
        if self._read_segment and self._read_segment in segments:
            return self._read_segment
        if self._read_segment:
            newer = [s for s in segments if s > self._read_segment]
            if newer:
                skipped = segments.index(newer[0])
                if skipped:
                    self.dropped += skipped
                self._read_segment = newer[0]
                self._read_offset = 0
                return self._read_segment
            # recorded segment is newer than everything present (state from
            # another spool) -> start at the oldest available
        self._read_segment = segments[0]
        self._read_offset = 0
        return self._read_segment

    def read_batch(self, max_records: int) -> list[dict]:
        """Read up to ``max_records`` from the current pointer (no ack yet)."""
        with self._lock:
            seg = self._resolve_read_segment()
            if seg is None:
                return []
            path = self._dir / seg
            try:
                size = path.stat().st_size
            except OSError:
                return []
            if self._read_offset >= size:
                # Current segment fully consumed: advance to a newer one if
                # the writer has rotated, otherwise wait for more data.
                newer = [s for s in self._segments() if s > seg]
                if not newer:
                    return []
                self._delete_segment(seg)
                self._read_segment = newer[0]
                self._read_offset = 0
                self._save_state_locked()
                seg = self._read_segment
                path = self._dir / seg
                try:
                    size = path.stat().st_size
                except OSError:
                    return []
                if self._read_offset >= size:
                    return []

            self._batch_start = (seg, self._read_offset)
            batch: list[dict] = []
            with open(path, "rb") as f:
                f.seek(self._read_offset)
                while len(batch) < max_records:
                    line = f.readline()
                    if not line:
                        break
                    self._read_offset += len(line)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        batch.append(json.loads(line.decode("utf-8", errors="replace")))
                    except ValueError:
                        log.warning("Skipping corrupt spool line in %s", seg)
            return batch

    def _delete_segment(self, name: str) -> None:
        """Best-effort segment delete (closes our handle when it is active)."""
        if (
            self._active_path is not None
            and name == self._active_path.name
            and self._active_file is not None
        ):
            # Windows cannot unlink an open file; close, delete, reopen fresh.
            try:
                self._active_file.close()
            except OSError:
                pass
            self._active_file = None
        try:
            (self._dir / name).unlink()
        except OSError:
            pass

    def ack(self) -> None:
        """Persist the read pointer after a successful (or rejected) ship."""
        with self._lock:
            if self._batch_start is None:
                return
            seg, _ = self._batch_start
            self._batch_start = None
            if self._read_segment == seg:
                try:
                    size = (self._dir / seg).stat().st_size
                except OSError:
                    size = self._read_offset
                if self._read_offset >= size:
                    active_name = self._active_path.name if self._active_path else None
                    if seg != active_name:
                        # Fully consumed and rotated away: drop it and move on.
                        self._delete_segment(seg)
                        newer = [s for s in self._segments() if s > seg]
                        self._read_segment = newer[0] if newer else None
                        self._read_offset = 0
                    else:
                        # Still the active segment: keep the pointer at EOF
                        # (read_batch never re-reads past it) and reopen after
                        # the close+delete attempt above left no handle.
                        if self._active_file is None and self._active_path is not None:
                            self._active_file = open(self._active_path, "ab")
                            self._active_size = self._active_path.stat().st_size
            self._save_state_locked()

    def nack(self) -> None:
        """Return to the batch start so it is re-read (server unreachable)."""
        with self._lock:
            if self._batch_start is not None:
                self._read_segment, self._read_offset = self._batch_start

    # -- state ------------------------------------------------------------
    def _load_state(self) -> None:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            self._read_segment = state.get("segment")
            self._read_offset = int(state.get("offset") or 0)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("Ignoring unreadable spool state: %s", e)

    def _save_state_locked(self) -> None:
        tmp = self._state_path.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"segment": self._read_segment, "offset": self._read_offset}, f)
            os.replace(tmp, self._state_path)
        except OSError as e:
            log.warning("Failed to persist spool state: %s", e)

    def commit_state(self) -> None:
        """Public flush of the read pointer (used after successful ships)."""
        with self._lock:
            self._save_state_locked()

    # -- lifecycle / stats ------------------------------------------------
    def pending_bytes(self) -> int:
        with self._lock:
            if self._read_segment is None:
                return 0
            total = 0
            for name in self._segments():
                if name < self._read_segment:
                    continue
                try:
                    size = (self._dir / name).stat().st_size
                except OSError:
                    continue
                if name == self._read_segment:
                    size -= self._read_offset
                total += max(0, size)
            return total

    def close(self) -> None:
        with self._lock:
            if self._active_file is not None:
                try:
                    self._active_file.flush()
                    self._active_file.close()
                finally:
                    self._active_file = None

    def stats(self) -> dict:
        with self._lock:
            return {
                "appended": self.appended,
                "shipped": self.shipped,
                "dropped": self.dropped,
                "rejected": self.rejected,
                "pending_bytes": self.pending_bytes(),
                "active_segment": self._active_path.name if self._active_path else None,
                "updated": time.time(),
            }
