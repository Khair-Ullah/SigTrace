"""Background HTTP/SocketIO server used by the desktop shell."""
from __future__ import annotations

import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("siem.desktop.server")


@dataclass
class DesktopServer:
    """Handle for a waitress server running on a daemon thread."""

    host: str
    port: int
    server: Any
    thread: threading.Thread

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def stop(self, timeout: float = 5.0) -> None:
        try:
            self.server.close()
        except Exception:  # pragma: no cover - best-effort shutdown
            log.exception("Error closing desktop server")
        self.thread.join(timeout=timeout)


def start(app, host: str = "127.0.0.1", port: int | None = None,
          threads: int = 8) -> DesktopServer:
    """Start the dashboard server and return a stoppable handle."""
    from siem.web.app import start_server_thread

    last_error: OSError | None = None
    for _ in range(5):
        try:
            server, thread, bound_port = start_server_thread(
                app, host=host, port=port, threads=threads
            )
            return DesktopServer(
                host=host, port=bound_port, server=server, thread=thread
            )
        except OSError as exc:
            # The ephemeral port was claimed between probe and bind; retry.
            last_error = exc
            if port is not None:
                raise
            time.sleep(0.1)
    assert last_error is not None
    raise last_error


def wait_until_ready(url: str, timeout: float = 20.0, interval: float = 0.2) -> bool:
    """Poll the dashboard until it answers, or return False on timeout."""
    deadline = time.monotonic() + timeout
    target = url.rstrip("/") + "/login"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(target, timeout=1.0) as response:
                if response.status < 500:
                    return True
        except urllib.error.HTTPError as exc:
            # A redirect to /login or a 401 still means the server is alive.
            if exc.code < 500:
                return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(interval)
    return False
