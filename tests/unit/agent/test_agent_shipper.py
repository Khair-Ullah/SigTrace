"""Tests for the agent shipper retry/ack decision logic."""
from __future__ import annotations

import io
import time
import urllib.error
from email.message import Message

import pytest

from siem_agent.shipper import Shipper, _parse_retry_after


class FakeSpool:
    def __init__(self, batches=None):
        self.batches = list(batches or [])
        self.acked = 0
        self.nacked = 0
        self.shipped = 0
        self.rejected = 0

    def read_batch(self, n):
        return self.batches.pop(0) if self.batches else []

    def ack(self):
        self.acked += 1

    def nack(self):
        self.nacked += 1

    def stats(self):
        return {}


def _http_error(code: int, body: bytes = b"", retry_after: str | None = None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("http://x/api/ingest", code, "err", headers, io.BytesIO(body))


def _make_shipper(monkeypatch, spool, fake_urlopen, **kw):
    monkeypatch.setattr("siem_agent.shipper.urllib.request.urlopen", fake_urlopen)
    return Shipper(spool, "http://x/api/ingest", "tok", flush_interval=0.01, timeout=1.0, **kw)


def _run_until(monkeypatch, spool, fake_urlopen, done, **kw):
    """Start the shipper thread, wait until ``done()`` or timeout, stop it."""
    shipper = _make_shipper(monkeypatch, spool, fake_urlopen, **kw)
    shipper.start()
    deadline = time.time() + 5
    try:
        while time.time() < deadline:
            if done():
                break
            time.sleep(0.01)
    finally:
        shipper.stop(timeout=2)
    return shipper


BATCH = [{"raw": "a", "source_id": "t", "source_type": "custom"}]


def _ok_response(code=200):
    class Resp:
        status = code

        def read(self):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return Resp()


def test_success_acks_and_ships(monkeypatch):
    spool = FakeSpool(batches=[BATCH])

    def fake_urlopen(req, timeout=None):
        assert req.get_header("Authorization") == "Bearer tok"
        return _ok_response()

    _run_until(monkeypatch, spool, fake_urlopen, done=lambda: spool.acked == 1)
    assert spool.acked == 1
    assert spool.shipped == len(BATCH)
    assert spool.nacked == 0


def test_server_error_nacks(monkeypatch):
    spool = FakeSpool(batches=[BATCH])

    def fake_urlopen(req, timeout=None):
        raise _http_error(503, retry_after="1")

    _run_until(monkeypatch, spool, fake_urlopen, done=lambda: spool.nacked == 1)
    assert spool.nacked == 1
    assert spool.acked == 0


def test_poison_batch_dropped_on_400(monkeypatch):
    spool = FakeSpool(batches=[BATCH])

    def fake_urlopen(req, timeout=None):
        raise _http_error(400, body=b'{"error": "bad_payload"}')

    _run_until(monkeypatch, spool, fake_urlopen, done=lambda: spool.rejected > 0)
    assert spool.acked == 1  # dropped (acked past), not nacked
    assert spool.rejected == len(BATCH)


def test_401_flags_auth_failure(monkeypatch):
    spool = FakeSpool(batches=[BATCH])

    def fake_urlopen(req, timeout=None):
        raise _http_error(401)

    shipper = _run_until(monkeypatch, spool, fake_urlopen, done=lambda: spool.nacked == 1)
    assert shipper.is_auth_failed is True
    assert spool.nacked == 1


def test_network_error_nacks(monkeypatch):
    spool = FakeSpool(batches=[BATCH])

    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    _run_until(monkeypatch, spool, fake_urlopen, done=lambda: spool.nacked == 1)
    assert spool.nacked == 1


@pytest.mark.parametrize(
    "value,expected",
    [("5", 5.0), ("0", 0.0), ("9999", 60.0), ("abc", None), (None, None)],
)
def test_parse_retry_after(value, expected):
    assert _parse_retry_after(value) == expected
