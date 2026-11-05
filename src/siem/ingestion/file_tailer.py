"""File-based log ingestion with rotation handling (FR-04..FR-06).

Watches configured log files and enqueues each new line. Uses watchdog for
low-latency notification plus a periodic poll as a safety net.

Durability guarantees:
* read offsets are checkpointed to a JSON file (default
  ``data/checkpoints/file_offsets.json``) so a restart resumes exactly where
  the previous run stopped - lines written while the SIEM was down are read;
* a record that cannot be enqueued (queue full) rolls the file position back
  to that line, so bursts are retried instead of silently dropped.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from siem.core.config import get_config
from siem.core.logger import get_logger
from siem.ingestion.base import BaseIngestor, RawLogRecord
from siem.ingestion.queue_manager import LogQueue

log = get_logger("ingestion.file")

CHECKPOINT_INTERVAL_SECONDS = 2.0


def _open_shared_read(path: Path):
    """Open a file for reading, allowing other processes to rename/delete it.

    On Windows, the default ``open`` does not grant FILE_SHARE_DELETE, which
    blocks log rotation by rename. We use CreateFileW with full sharing so the
    producer can rotate the file while we hold a handle.
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
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
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


@dataclass
class FileSource:
    path: Path
    source_id: str
    source_type: str
    format_hint: Optional[str] = None


@dataclass
class _TailState:
    source: FileSource
    handle: Optional[object] = None  # binary file object
    position: int = 0
    inode: int = -1
    device: int = -1
    buffer: bytes = field(default_factory=bytes)


class _WakeHandler(FileSystemEventHandler):
    """Sets a threading.Event whenever a relevant file changes."""

    def __init__(self, wake: threading.Event, watched_names: set[str]):
        self._wake = wake
        self._names = {n.lower() for n in watched_names}

    def _touch(self, raw_path: str) -> None:
        name = Path(raw_path).name.lower()
        if name in self._names:
            self._wake.set()

    def on_modified(self, event):  # noqa: D401
        if not event.is_directory:
            self._touch(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._touch(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._touch(event.dest_path)


class OffsetCheckpoint:
    """JSON-backed store of per-file read positions (atomic, debounced saves)."""

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
                log.info("Loaded %d file offset checkpoint(s) from %s",
                         len(self._data), self._path)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning("Ignoring unreadable checkpoint file %s: %s", self._path, e)

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
                "updated": time.time(),
            }
            self._dirty = True

    def remove(self, key: str) -> None:
        with self._lock:
            if self._data.pop(key, None) is not None:
                self._dirty = True

    def maybe_save(self, force: bool = False,
                   interval: float = CHECKPOINT_INTERVAL_SECONDS) -> bool:
        """Atomically persist when dirty and due. Returns True if written."""
        with self._lock:
            if not self._dirty:
                return False
            now = time.monotonic()
            if not force and now - self._last_save < interval:
                return False
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._data, f)
                os.replace(tmp, self._path)
            except OSError as e:
                log.warning("Failed to save checkpoint file %s: %s", self._path, e)
                return False
            self._dirty = False
            self._last_save = now
            return True


class FileTailer(BaseIngestor):
    """Tail one or more log files, following rotations."""

    def __init__(
        self,
        queue: LogQueue,
        sources: list[dict],
        read_from_beginning: bool = False,
        tail_interval: float = 0.5,
        checkpoint_file: Optional[str | Path] = None,
        queue_timeout: float = 2.0,
    ):
        super().__init__(queue, name="FileTailer")
        self.read_from_beginning = read_from_beginning
        self.tail_interval = tail_interval
        self.queue_timeout = float(queue_timeout)
        self._stop_event = threading.Event()
        self._wake = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None
        self._observer: Optional[Observer] = None
        self._states: list[_TailState] = [self._make_state(s) for s in sources]
        self.stats = {"lines": 0, "rotations": 0, "errors": 0, "queue_full": 0}
        self._checkpoint: Optional[OffsetCheckpoint] = None
        if checkpoint_file:
            cp_path = Path(checkpoint_file)
            if not cp_path.is_absolute():
                cp_path = get_config().project_root / cp_path
            self._checkpoint = OffsetCheckpoint(cp_path)

    # -- setup ------------------------------------------------------------
    def _make_state(self, spec: dict) -> _TailState:
        raw_path = spec["path"]
        path = Path(raw_path)
        if not path.is_absolute():
            path = get_config().project_root / path
        source = FileSource(
            path=path,
            source_id=spec.get("source_id", path.stem),
            source_type=spec.get("source_type", "custom"),
            format_hint=spec.get("format_hint"),
        )
        return _TailState(source=source)

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        # Open existing files and seed positions (checkpoint-aware)
        for state in self._states:
            self._open_with_checkpoint(state)

        # watchdog observer on parent dirs
        dirs = {str(s.source.path.parent) for s in self._states}
        if dirs:
            names = {s.source.path.name for s in self._states}
            handler = _WakeHandler(self._wake, names)
            self._observer = Observer()
            for d in dirs:
                try:
                    Path(d).mkdir(parents=True, exist_ok=True)
                    self._observer.schedule(handler, d, recursive=False)
                except OSError as e:
                    log.warning("Cannot watch directory %s: %s", d, e)
            self._observer.start()

        self._reader_thread = threading.Thread(
            target=self._reader_loop, name="file-tailer", daemon=True
        )
        self._reader_thread.start()
        log.info("File tailer started, watching %d file(s)", len(self._states))

    def stop(self, timeout: float = 5.0) -> None:
        if not self._running:
            return
        self._stop_event.set()
        self._wake.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=timeout)
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=timeout)
        for state in self._states:
            self._close(state)
            self._save_checkpoint(state, force=True)
        self._running = False
        log.info("File tailer stopped (stats=%s)", self.stats)

    # -- reading ----------------------------------------------------------
    def _reader_loop(self) -> None:
        while not self._stop_event.is_set():
            for state in self._states:
                try:
                    self._read_new(state)
                except OSError as e:
                    self.stats["errors"] += 1
                    log.debug("Read error for %s: %s", state.source.path, e)
            # Wait for a filesystem event or the poll interval
            self._wake.wait(timeout=self.tail_interval)
            self._wake.clear()

    def _open(self, state: _TailState, at_start: bool) -> None:
        path = state.source.path
        try:
            f = _open_shared_read(path)
        except (FileNotFoundError, OSError):
            state.handle = None
            return
        stat = os.stat(path)
        state.handle = f
        state.inode = getattr(stat, "st_ino", -1)
        state.device = getattr(stat, "st_dev", -1)
        if at_start:
            f.seek(0)
            state.position = 0
        else:
            f.seek(0, os.SEEK_END)
            state.position = f.tell()

    def _open_with_checkpoint(self, state: _TailState) -> None:
        """Open a source, resuming from its checkpoint when one exists."""
        if self.read_from_beginning or self._checkpoint is None:
            self._open(state, at_start=self.read_from_beginning)
            return

        entry = self._checkpoint.get(str(state.source.path))
        if not entry:
            self._open(state, at_start=False)  # first run: start at EOF
            return

        path = state.source.path
        try:
            f = _open_shared_read(path)
        except (FileNotFoundError, OSError):
            state.handle = None  # temporarily gone; _read_new retries later
            return
        stat = os.stat(path)
        cur_inode = getattr(stat, "st_ino", -1)
        cur_device = getattr(stat, "st_dev", -1)
        saved_inode = int(entry.get("inode", -1))

        # Rotated/replaced while stopped -> new file: read it from the start.
        if saved_inode not in (-1, 0) and cur_inode not in (-1, 0) and cur_inode != saved_inode:
            f.close()
            log.info("Checkpoint inode mismatch for %s; reading new file from start", path)
            self._open(state, at_start=True)
            return

        position = int(entry.get("position", 0))
        if position > stat.st_size:
            position = 0  # truncated/replaced in place
        f.seek(position)
        state.handle = f
        state.inode = cur_inode
        state.device = cur_device
        state.position = position
        state.buffer = b""
        log.info("Resumed tail of %s at offset %d", path, position)

    def _save_checkpoint(self, state: _TailState, force: bool = False) -> None:
        """Record the committed read position for a source (best effort)."""
        if self._checkpoint is None:
            return
        if state.inode == -1:
            return  # never opened (or file absent): keep any existing entry
        key = str(state.source.path)
        # Bytes already read but not yet fully emitted live in ``buffer``;
        # only everything before them is safe to resume from.
        commit = state.position - len(state.buffer)
        self._checkpoint.set(key, commit, state.inode, state.device)
        self._checkpoint.maybe_save(force=force)

    def _close(self, state: _TailState) -> None:
        if state.handle is not None:
            try:
                state.handle.close()
            except OSError:
                pass
            state.handle = None

    def _read_new(self, state: _TailState) -> None:
        path = state.source.path

        if state.handle is None:
            if not path.exists():
                return
            # Newly-appeared file: read it from the beginning
            self._open(state, at_start=True)
            if state.handle is None:
                return

        stat = os.stat(path)
        cur_inode = getattr(stat, "st_ino", -1)
        cur_device = getattr(stat, "st_dev", -1)

        # Rotation / truncation detection
        rotated = (
            (state.inode != -1 and cur_inode != state.inode)
            or (state.device != -1 and cur_device != state.device)
            or stat.st_size < state.position
        )
        if rotated:
            log.info("Log rotation detected for %s", path)
            self.stats["rotations"] += 1
            self._close(state)
            state.buffer = b""
            state.position = 0
            state.inode = -1
            state.device = -1
            self._open(state, at_start=True)
            self._save_checkpoint(state, force=True)

        if state.handle is None:
            return

        read_start = state.position
        old_len = len(state.buffer)  # partial line carried from the last pass
        state.handle.seek(read_start)
        data = state.handle.read()
        if not data:
            return
        state.position = state.handle.tell()

        state.buffer += data
        *line_parts, tail = state.buffer.split(b"\n")
        state.buffer = tail
        # The first complete line begins where the carried partial line began.
        offset = read_start - old_len

        for line_bytes in line_parts:
            text = line_bytes.decode("utf-8", errors="replace").rstrip("\r")
            if text.strip():
                record = RawLogRecord(
                    raw=text,
                    source_id=state.source.source_id,
                    source_type=state.source.source_type,
                    transport="file",
                    file_path=str(path),
                    format_hint=state.source.format_hint,
                )
                if not self.queue.put_blocking(record, timeout=self.queue_timeout):
                    # Queue saturated: roll back to this line so it (and the
                    # rest) are re-read on the next pass instead of lost.
                    self.stats["queue_full"] += 1
                    state.position = offset
                    state.buffer = b""
                    self._save_checkpoint(state, force=True)
                    return
                self.stats["lines"] += 1
            offset += len(line_bytes) + 1  # +1 for the split newline

        self._save_checkpoint(state)
