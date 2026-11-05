"""Background shipper: drains the spool to POST /api/ingest.

Retry policy:
* 2xx -> ack (records are durably accepted)
* 400/413 -> ack + count as rejected (poison batch; dropping prevents
  head-of-line blocking - the server logged the payload error)
* 429/503 -> nack and honour ``Retry-After`` when present
* 401 -> nack + 60s backoff (fix the token in agent config and restart)
* network errors/timeouts -> nack + exponential backoff (1s..60s)
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request

from siem_agent.spool import Spool

log = logging.getLogger("siem_agent.shipper")

_MAX_BACKOFF = 60.0


class Shipper(threading.Thread):
    def __init__(
        self,
        spool: Spool,
        ingest_url: str,
        token: str,
        batch_size: int = 200,
        flush_interval: float = 3.0,
        timeout: float = 10.0,
    ):
        super().__init__(name="siem-agent-shipper", daemon=True)
        self._spool = spool
        self._ingest_url = ingest_url
        self._token = token
        self._batch_size = max(1, int(batch_size))
        self._flush_interval = max(0.2, float(flush_interval))
        self._timeout = max(1.0, float(timeout))
        self._stop_event = threading.Event()
        self._failures = 0
        self._auth_failed = False

    # -- lifecycle --------------------------------------------------------
    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=timeout)

    # -- main loop --------------------------------------------------------
    def run(self) -> None:
        log.info(
            "Shipper started (url=%s, batch=%d, flush=%.1fs)",
            self._ingest_url,
            self._batch_size,
            self._flush_interval,
        )
        while not self._stop_event.is_set():
            batch = self._spool.read_batch(self._batch_size)
            if not batch:
                self._stop_event.wait(self._flush_interval)
                continue

            outcome, retry_after = self._post(batch)
            if outcome == "ok":
                self._spool.ack()
                self._spool.shipped += len(batch)
                self._failures = 0
                if self._auth_failed:
                    self._auth_failed = False
                    log.info("Server authentication recovered")
            elif outcome == "rejected":
                # Server rejected the payload itself (4xx): drop it so the
                # queue keeps moving, but record the loss.
                self._spool.ack()
                self._spool.rejected += len(batch)
                self._failures = 0
                log.error(
                    "Server rejected a batch of %d record(s) (see server "
                    "logs); dropped to avoid blocking the queue",
                    len(batch),
                )
            else:
                self._spool.nack()
                self._failures += 1
                delay = (
                    retry_after if retry_after else min(2.0 ** min(self._failures, 6), _MAX_BACKOFF)
                )
                log.warning(
                    "Ship failed (%d consecutive); retrying in %.0fs " "(%d record(s) spooled)",
                    self._failures,
                    delay,
                    len(batch),
                )
                self._stop_event.wait(delay)
        log.info("Shipper stopped (stats=%s)", self._spool.stats())

    # -- HTTP -------------------------------------------------------------
    def _post(self, batch: list[dict]) -> tuple[str, float | None]:
        """Send one batch. Returns (outcome, retry_after_seconds)."""
        body = json.dumps({"records": batch}).encode("utf-8")
        req = urllib.request.Request(
            self._ingest_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "siem-agent/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
                return "ok", None
        except urllib.error.HTTPError as e:
            retry_after = _parse_retry_after(e.headers.get("Retry-After"))
            if e.code in (429, 503):
                return "retry", retry_after
            if e.code == 401:
                if not self._auth_failed:
                    self._auth_failed = True
                    log.error(
                        "Server rejected the agent token (401). Fix "
                        "server.token in your agent config and restart the agent."
                    )
                return "retry", max(retry_after or 0.0, 60.0)
            if e.code in (400, 413, 415, 422):
                try:
                    detail = e.read().decode("utf-8", errors="replace")[:500]
                except Exception:
                    detail = ""
                log.error("Server returned %d for a batch: %s", e.code, detail)
                return "rejected", None
            log.warning("Server returned %d; will retry", e.code)
            return "retry", retry_after
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.debug("Ship request failed: %s", e)
            return "retry", None

    @property
    def is_auth_failed(self) -> bool:
        return self._auth_failed


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, min(float(value), _MAX_BACKOFF))
    except ValueError:
        return None
