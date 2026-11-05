"""End-to-end agent flow: file tail -> spool -> shipper -> HTTP ingest -> DB."""
from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message

import pytest

from conftest import make_web_config
from siem_agent.collector.file_tail import FileTailCollector
from siem_agent.shipper import Shipper
from siem_agent.spool import Spool

TOKEN = "e2e-ingest-token"

LOG_LINES = [
    "Oct 18 10:00:00 host sshd[1]: Failed password for invalid user root "
    "from 10.0.0.9 port 22 ssh2",
    "Oct 18 10:00:01 host sshd[1]: Failed password for invalid user admin "
    "from 10.0.0.9 port 22 ssh2",
    "Oct 18 10:00:02 host sshd[1]: Failed password for invalid user test "
    "from 10.0.0.9 port 22 ssh2",
]


@pytest.fixture
def e2e_env(tmp_path, session_factory, monkeypatch):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    monkeypatch.setenv("SIEM_INGEST_TOKENS", f"agent-01:{TOKEN}")
    config = make_web_config(tmp_path, csrf=False)
    config._data["ingestion"] = {"http": {"enabled": True}}  # noqa: SLF001
    storage = StorageService(session_factory=session_factory, config=config)
    app = create_app(config, storage=storage)
    app.config.update(TESTING=True)
    client = app.test_client()
    return {"client": client, "storage": storage, "tmp": tmp_path}


def _urlopen_via(client):
    """Fake urllib urlopen that forwards to the Flask test client."""

    class _Resp:
        def __init__(self, status: int, data: bytes):
            self.status = status
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        headers = {k: v for k, v in req.header_items()}
        resp = client.post(
            "/api/ingest",
            data=req.data,
            headers=headers,
            content_type="application/json",
        )
        if resp.status_code >= 400:
            msg = Message()
            retry = resp.get_json()
            if isinstance(retry, dict) and "retry_after" in retry:
                msg["Retry-After"] = str(retry["retry_after"])
            raise urllib.error.HTTPError(
                req.full_url, resp.status_code, "error", msg, io.BytesIO(resp.data)
            )
        return _Resp(resp.status_code, resp.data)

    return fake_urlopen


def _drain(spool: Spool, shipper: Shipper) -> str:
    """Manually run shipper passes until the spool is empty or blocked."""
    last_outcome = "empty"
    for _ in range(20):
        batch = spool.read_batch(200)
        if not batch:
            break
        outcome, _retry_after = shipper._post(batch)
        last_outcome = outcome
        if outcome == "ok":
            spool.ack()
            spool.shipped += len(batch)
        elif outcome == "rejected":
            spool.ack()
            spool.rejected += len(batch)
        else:
            spool.nack()
            break
    return last_outcome


def test_file_to_storage_end_to_end(e2e_env, monkeypatch):
    tmp_path = e2e_env["tmp"]
    log = tmp_path / "app.log"
    log.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8")

    spool = Spool(tmp_path / "spool", max_mb=10)
    tailer = FileTailCollector(
        emit=spool.append,
        sources=[{"path": str(log), "source_id": "syslog", "source_type": "syslog"}],
        offsets_path=tmp_path / "file_offsets.json",
        read_from_beginning=True,
    )
    for state in tailer._states:
        tailer._open_with_checkpoint(state)
    tailer._read_new(tailer._states[0])
    tailer.stop(timeout=0.1)

    shipper = Shipper(
        spool, "http://testserver/api/ingest", TOKEN, batch_size=2, flush_interval=0.05, timeout=5.0
    )
    monkeypatch.setattr(
        "siem_agent.shipper.urllib.request.urlopen", _urlopen_via(e2e_env["client"])
    )

    outcome = _drain(spool, shipper)
    assert outcome == "ok"
    assert spool.shipped == len(LOG_LINES)

    storage = e2e_env["storage"]
    assert storage.events.count() == len(LOG_LINES)
    assert storage.events.count(source_id="syslog") == len(LOG_LINES)


def test_server_outage_then_recovery_no_loss(e2e_env, monkeypatch):
    tmp_path = e2e_env["tmp"]
    log = tmp_path / "app.log"
    log.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8")

    spool = Spool(tmp_path / "spool", max_mb=10)
    tailer = FileTailCollector(
        emit=spool.append,
        sources=[{"path": str(log), "source_id": "syslog", "source_type": "syslog"}],
        offsets_path=tmp_path / "file_offsets.json",
        read_from_beginning=True,
    )
    for state in tailer._states:
        tailer._open_with_checkpoint(state)
    tailer._read_new(tailer._states[0])
    tailer.stop(timeout=0.1)

    fake_urlopen = _urlopen_via(e2e_env["client"])
    monkeypatch.setattr("siem_agent.shipper.urllib.request.urlopen", fake_urlopen)

    # Phase 1: wrong token -> 401 -> data stays spooled.
    bad_shipper = Shipper(
        spool, "http://testserver/api/ingest", "WRONG-TOKEN", batch_size=200, timeout=5.0
    )
    outcome = _drain(spool, bad_shipper)
    assert outcome == "retry"
    assert bad_shipper.is_auth_failed is True
    assert spool.shipped == 0
    assert e2e_env["storage"].events.count() == 0

    # Phase 2: fixed token -> everything ships exactly once.
    good_shipper = Shipper(
        spool, "http://testserver/api/ingest", TOKEN, batch_size=200, timeout=5.0
    )
    outcome = _drain(spool, good_shipper)
    assert outcome == "ok"
    assert e2e_env["storage"].events.count() == len(LOG_LINES)


def test_ingest_roundtrip_with_json_hint(e2e_env, monkeypatch):
    """Windows-style JSON payloads (format_hint=json) survive the roundtrip."""
    tmp_path = e2e_env["tmp"]
    log = tmp_path / "winlog.jsonl"
    payload = {
        "timestamp": "2026-10-18T10:00:00Z",
        "event_type": "failed_login",
        "severity": "high",
        "message": "An account failed to log on.",
        "windows_event_id": "4625",
        "channel": "Security",
    }
    log.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    spool = Spool(tmp_path / "spool", max_mb=10)
    tailer = FileTailCollector(
        emit=spool.append,
        sources=[
            {
                "path": str(log),
                "source_id": "winlog-security",
                "source_type": "windows_event",
                "format_hint": "json",
            }
        ],
        offsets_path=tmp_path / "file_offsets.json",
        read_from_beginning=True,
    )
    for state in tailer._states:
        tailer._open_with_checkpoint(state)
    tailer._read_new(tailer._states[0])
    tailer.stop(timeout=0.1)

    shipper = Shipper(spool, "http://testserver/api/ingest", TOKEN, batch_size=200, timeout=5.0)
    monkeypatch.setattr(
        "siem_agent.shipper.urllib.request.urlopen", _urlopen_via(e2e_env["client"])
    )

    assert _drain(spool, shipper) == "ok"
    storage = e2e_env["storage"]
    items = storage.events.query(message_contains="failed to log on")
    assert len(items) == 1
    assert items[0].source_id == "winlog-security"
