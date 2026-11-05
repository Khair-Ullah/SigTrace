"""Integration tests for the HTTP ingestion API (POST /api/ingest)."""
from __future__ import annotations

import json

import pytest

from conftest import make_web_config

TOKEN = "ingest-int-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def ingest_config(tmp_path):
    config = make_web_config(tmp_path, csrf=False)
    config._data["ingestion"] = {  # noqa: SLF001 - test setup
        "http": {
            "enabled": True,
            "rate_limit_per_minute": 0,  # disabled unless a test enables it
            "max_batch": 5,
            "max_body_bytes": 4096,
        }
    }
    return config


@pytest.fixture
def ingest_app(ingest_config, session_factory, monkeypatch):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    monkeypatch.setenv("SIEM_INGEST_TOKENS", f"agent-01:{TOKEN}")
    storage = StorageService(session_factory=session_factory, config=ingest_config)
    app = create_app(ingest_config, storage=storage)
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def ingest_client(ingest_app):
    return ingest_app.test_client()


def _payload(*raws, **kw):
    body = {"records": [{"raw": r, **kw} for r in raws]}
    return json.dumps(body)


def test_ingest_requires_token(ingest_client):
    resp = ingest_client.post("/api/ingest", json={"records": [{"raw": "x"}]})
    assert resp.status_code == 401


def test_ingest_rejects_wrong_token(ingest_client):
    resp = ingest_client.post(
        "/api/ingest",
        json={"records": [{"raw": "x"}]},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_ingest_accepts_batch_and_stores_events(ingest_client, ingest_app):
    resp = ingest_client.post(
        "/api/ingest",
        data=_payload(
            "Oct 18 10:00:00 host sshd[1]: Failed password for invalid user "
            "root from 10.0.0.9 port 22 ssh2",
            "Oct 18 10:00:01 host sshd[1]: Failed password for invalid user "
            "admin from 10.0.0.9 port 22 ssh2",
        ),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["accepted"] == 2

    storage = ingest_app.extensions["siem_storage"]
    assert storage.events.count() == 2


def test_ingest_json_records_with_format_hint(ingest_client, ingest_app):
    body = {
        "records": [
            {
                "raw": json.dumps({"message": "hello", "severity": "low"}),
                "format_hint": "json",
                "source_id": "w1",
                "source_type": "web",
            },
        ]
    }
    resp = ingest_client.post("/api/ingest", json=body, headers=AUTH)
    assert resp.status_code == 200
    storage = ingest_app.extensions["siem_storage"]
    items = storage.events.query(message_contains="hello")
    assert len(items) == 1
    assert items[0].source_id == "w1"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"records": []},
        {"records": "not-a-list"},
        {"records": [{"raw": ""}]},
        {"records": [42]},
        {"records": [{"no_raw": True}]},
    ],
)
def test_ingest_bad_payloads_400(ingest_client, body):
    resp = ingest_client.post("/api/ingest", json=body, headers=AUTH)
    assert resp.status_code == 400


def test_ingest_batch_too_large_400(ingest_client):
    raws = [f"line {i}" for i in range(10)]  # max_batch=5 in fixture
    resp = ingest_client.post(
        "/api/ingest",
        data=_payload(*raws),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "max_batch" in resp.get_json()["message"]


def test_ingest_body_too_large_413(ingest_client):
    big = "x" * 5000
    resp = ingest_client.post(
        "/api/ingest",
        data=_payload(big),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert resp.status_code == 413


def test_ingest_rate_limit_429(ingest_app, ingest_client):
    # Rate buckets are module-level state shared across tests: isolate.
    from siem.web.routes import ingest as ingest_module

    ingest_module._rate_hits.clear()
    ingest_app.extensions["siem_config"]._data["ingestion"]["http"][
        "rate_limit_per_minute"
    ] = 2  # noqa: SLF001

    codes = []
    for _ in range(4):
        resp = ingest_client.post(
            "/api/ingest",
            data=_payload("r"),
            headers={**AUTH, "Content-Type": "application/json"},
        )
        codes.append(resp.status_code)
    assert codes[:2] == [200, 200]
    assert codes[2:] == [429, 429]


def test_ingest_disabled_returns_404(ingest_app, ingest_client):
    ingest_app.extensions["siem_config"]._data["ingestion"]["http"][
        "enabled"
    ] = False  # noqa: SLF001
    resp = ingest_client.post("/api/ingest", json={"records": [{"raw": "x"}]}, headers=AUTH)
    assert resp.status_code == 404


def test_ingest_exempt_from_csrf(tmp_path, session_factory, monkeypatch):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    monkeypatch.setenv("SIEM_INGEST_TOKENS", f"agent-01:{TOKEN}")
    config = make_web_config(tmp_path, csrf=True)
    config._data["ingestion"] = {"http": {"enabled": True}}  # noqa: SLF001
    storage = StorageService(session_factory=session_factory, config=config)
    app = create_app(config, storage=storage)
    app.config.update(TESTING=True)
    client = app.test_client()

    # A session-cookie POST would be blocked without a CSRF token ...
    resp = client.post("/api/ingest", json={"records": [{"raw": "x"}]}, headers=AUTH)
    # ... but /api/ingest uses bearer auth and must succeed.
    assert resp.status_code == 200, resp.get_json()


def test_ingest_non_json_body_400(ingest_client):
    resp = ingest_client.post(
        "/api/ingest",
        data="not json",
        headers={**AUTH, "Content-Type": "text/plain"},
    )
    assert resp.status_code == 400
