"""Poll-based file tailer with rotation handling and offset checkpoints.

Same durability rules as the server-side tailer: offsets are checkpointed to
``<spool>/file_offsets.json`` (atomic writes) and a failed spool write rolls
the position back to the offending line so nothing is skipped.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

from siem_agent.collector.base import BaseCollector, EmitFn

log = logging.getLogger("siem_agent.file_tail")

CHECKPOINT_INTERVAL_SECONDS = 2.0


def _open_shared_read(path: Path):
    """Open a file for reading, allowing other processes to rename/delete it.

    On Windows, plain ``open`` lacks FILE_SHARE_DELETE, which blocks rotation
    by rename; CreateFileW with full sharing lets producers rotate the file
    while we hold the handle.
    """
    if os.name != "nt":
        return open(path, "rb")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    ERROR_FILE_NOT_FOUND = 2
    ERROR_PATH_NOT_FOUND = 3

    CreateFileW = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]

    handle = CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, 0, invalid):
        err = ctypes.get_last_error()
        if err in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
            raise FileNotFoundError(path)
        raise OSError(f"CreateFileW failed for {path}: error {err}")

    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb")


class OffsetStore:
    """JSON-backed per-file offsets with debounced atomic saves."""

    def __init__(self, path: Path):
        self._path = path
        self._data: dict[str, dict] = {}
        self._dirty = False
        self._last_save = 0.0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self._data = {k: v for k, v in loaded.items() if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("Ignoring unreadable offset file %s: %s", self._path, e)

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._data.get(key)
            return dict(entry) if entry else None

    def set(self, key: str, position: int, inode: int, device: int) -> None:
        with self._lock:
            self._data[key] = {
                "position": int(position),
                "inode": int(inode),
                "device": int(device),
            }
            self._dirty = True

    def save(self, force: bool = False) -> bool:
        with self._lock:
            if not self._dirty:
                return False
            now = time.monotonic()
            if not force and now - self._last_save < CHECKPOINT_INTERVAL_SECONDS:
                return False
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._data, f)
                os.replace(tmp, self._path)
            except OSError as e:
                log.warning("Failed to save offsets %s: %s", self._path, e)
                return False
            self._dirty = False
            self._last_save = now
            return True


@dataclass
class _SourceState:
    path: Path
    source_id: str
    source_type: str
    format_hint: Optional[str] = None
    handle: Optional[IO[bytes]] = None
    position: int = 0
    inode: int = -1
    device: int = -1
    buffer: bytes = field(default_factory=bytes)


class FileTailCollector(BaseCollector):
    def __init__(
        self,
        emit: EmitFn,
        sources: list[dict],
        offsets_path: Path,
        read_from_beginning: bool = False,
        tail_interval: float = 0.5,
    ):
        super().__init__(emit, name="file-tail")
        self.read_from_beginning = read_from_beginning
        self.tail_interval = max(0.1, float(tail_interval))
        self._offsets = OffsetStore(offsets_path)
        self._states = [self._make_state(s) for s in (sources or [])]
        self.stats = {"lines": 0, "rotations": 0, "errors": 0, "write_failures": 0}

    def _make_state(self, spec: dict) -> _SourceState:
        path = Path(str(spec["path"])).expanduser()
        return _SourceState(
            path=path,
            source_id=str(spec.get("source_id") or path.stem),
            source_type=str(spec.get("source_type") or "custom"),
            format_hint=spec.get("format_hint"),
        )

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        for state in self._states:
            self._open_with_checkpoint(state)
        self._thread = threading.Thread(target=self._loop, name="agent-file-tail", daemon=True)
        self._thread.start()
        log.info("File tailer watching %d file(s)", len(self._states))

    def stop(self, timeout: float = 5.0) -> None:
        super().stop(timeout=timeout)
        for state in self._states:
            self._close(state)
            self._save(state, force=True)
        log.info("File tailer stopped (stats=%s)", self.stats)

    # -- reading ----------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop_event.is_set():
            for state in self._states:
                try:
                    self._read_new(state)
                except OSError as e:
                    self.stats["errors"] += 1
                    log.debug("Read error for %s: %s", state.path, e)
            self._stop_event.wait(self.tail_interval)

    def _open(self, state: _SourceState, at_start: bool) -> None:
        try:
            f = _open_shared_read(state.path)
        except (FileNotFoundError, OSError):
            state.handle = None
            return
        stat = os.stat(state.path)
        state.handle = f
        state.inode = getattr(stat, "st_ino", -1)
        state.device = getattr(stat, "st_dev", -1)
        if at_start:
            f.seek(0)
            state.position = 0
        else:
            f.seek(0, os.SEEK_END)
            state.position = f.tell()

    def _open_with_checkpoint(self, state: _SourceState) -> None:
        if self.read_from_beginning:
            self._open(state, at_start=True)
            return
        entry = self._offsets.get(str(state.path))
        if not entry:
            self._open(state, at_start=False)  # first run: start at EOF
            return
        try:
            f = _open_shared_read(state.path)
        except (FileNotFoundError, OSError):
            state.handle = None
            return
        stat = os.stat(state.path)
        cur_inode = getattr(stat, "st_ino", -1)
        saved_inode = int(entry.get("inode", -1))
        if saved_inode not in (-1, 0) and cur_inode not in (-1, 0) and cur_inode != saved_inode:
            f.close()
            log.info("Offset inode mismatch for %s; reading new file from start", state.path)
            self._open(state, at_start=True)
            return
        position = int(entry.get("position", 0))
        if position > stat.st_size:
            position = 0
        f.seek(position)
        state.handle = f
        state.inode = cur_inode
        state.device = getattr(stat, "st_dev", -1)
        state.position = position
        state.buffer = b""
        log.info("Resumed %s at offset %d", state.path, position)

    def _save(self, state: _SourceState, force: bool = False) -> None:
        if state.inode == -1:
            return
        self._offsets.set(
            str(state.path), state.position - len(state.buffer), state.inode, state.device
        )
        self._offsets.save(force=force)

    def _close(self, state: _SourceState) -> None:
        if state.handle is not None:
            try:
                state.handle.close()
            except OSError:
                pass
            state.handle = None

    def _read_new(self, state: _SourceState) -> None:
        if state.handle is None:
            if not state.path.exists():
                return
            self._open(state, at_start=True)
            if state.handle is None:
                return

        stat = os.stat(state.path)
        cur_inode = getattr(stat, "st_ino", -1)
        cur_device = getattr(stat, "st_dev", -1)
        rotated = (
            (state.inode != -1 and cur_inode != state.inode)
            or (state.device != -1 and cur_device != state.device)
            or stat.st_size < state.position
        )
        if rotated:
            log.info("Log rotation detected for %s", state.path)
            self.stats["rotations"] += 1
            self._close(state)
            state.buffer = b""
            state.position = 0
            state.inode = -1
            state.device = -1
            self._open(state, at_start=True)
            self._save(state, force=True)

        if state.handle is None:
            return

        read_start = state.position
        old_len = len(state.buffer)
        state.handle.seek(read_start)
        data = state.handle.read()
        if not data:
            return
        state.position = state.handle.tell()

        state.buffer += data
        *line_parts, tail = state.buffer.split(b"\n")
        state.buffer = tail
        offset = read_start - old_len

        for line_bytes in line_parts:
            text = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
            if text.strip():
                record: dict = {
                    "raw": text,
                    "source_id": state.source_id,
                    "source_type": state.source_type,
                }
                if state.format_hint:
                    record["format_hint"] = state.format_hint
                if not self.emit(record):
                    # Spool write failed: roll back so the line is retried.
                    self.stats["write_failures"] += 1
                    state.position = offset
                    state.buffer = b""
                    self._save(state, force=True)
                    return
                self.stats["lines"] += 1
            offset += len(line_bytes) + 1

        self._save(state)
