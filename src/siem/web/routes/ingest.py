"""Token-authenticated HTTP ingestion API for the siem-agent (POST /api/ingest).

Agents ship batches of raw log lines here. The endpoint is exempt from CSRF
(it uses ``Authorization: Bearer`` tokens, not session cookies) and applies
per-token rate limiting plus a queue backpressure signal (503 + Retry-After)
so agents spool and retry instead of losing data.
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from typing import Optional

from flask import Blueprint, current_app, jsonify, request

from siem.core.config import Config
from siem.core.logger import get_logger
from siem.core.utils import utcnow
from siem.ingestion.base import RawLogRecord
from siem.parsing.detectors import normalize_format_hint

bp = Blueprint("ingest", __name__, url_prefix="/api")
log = get_logger("web.ingest")

_MAX_SOURCE_LEN = 128
_RATE_WINDOW_SECONDS = 60.0

_rate_hits: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def load_tokens(config: Config) -> dict[str, str]:
    """Return {token: token_id} from config and the SIEM_INGEST_TOKENS env.

    Config format::

        ingestion.http.tokens:
          - id: agent-01
            token: <secret>

    Env format (comma separated): ``SIEM_INGEST_TOKENS=agent-01:secret,...``
    """
    tokens: dict[str, str] = {}
    for entry in config.get("ingestion.http.tokens", []) or []:
        if not isinstance(entry, dict):
            continue
        token = str(entry.get("token") or "").strip()
        token_id = str(entry.get("id") or "agent").strip() or "agent"
        if token:
            tokens[token] = token_id

    raw_env = os.environ.get("SIEM_INGEST_TOKENS", "")
    for pair in raw_env.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        token_id, token = pair.split(":", 1)
        token_id, token = token_id.strip(), token.strip()
        if token:
            tokens[token] = token_id or "agent"
    return tokens


def _authenticate(config: Config) -> Optional[tuple[str, None]]:
    """Return (token_id, None) when valid, else None (caller sends 401)."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    presented = header[7:].strip().encode("utf-8")
    if not presented:
        return None
    for token, token_id in load_tokens(config).items():
        if hmac.compare_digest(presented, token.encode("utf-8")):
            return (token_id, None)
    return None


def _rate_limit_ok(token_id: str, limit_per_minute: int) -> bool:
    if limit_per_minute <= 0:
        return True
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS
    with _rate_lock:
        hits = _rate_hits.setdefault(token_id, [])
        hits[:] = [t for t in hits if t >= cutoff]
        if len(hits) >= limit_per_minute:
            return False
        hits.append(now)
        return True


def _error(message: str, code: int, **extra):
    return jsonify(error=message.lower().replace(" ", "_"), message=message, **extra), code


def _build_records(payload: dict, max_batch: int) -> tuple[Optional[list], Optional[tuple]]:
    """Validate the payload and build RawLogRecord objects."""
    default_source_id = str(payload.get("source_id") or "agent")[:_MAX_SOURCE_LEN]
    default_source_type = str(payload.get("source_type") or "custom")[:_MAX_SOURCE_LEN]
    default_hint = normalize_format_hint(payload.get("format_hint"))

    raw_records = payload.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        return None, _error("Payload must include a non-empty 'records' list", 400)
    if len(raw_records) > max_batch:
        return None, _error(f"Batch of {len(raw_records)} exceeds max_batch={max_batch}", 400)

    records: list[RawLogRecord] = []
    for i, item in enumerate(raw_records):
        if not isinstance(item, dict):
            return None, _error(f"records[{i}] must be an object", 400)
        raw = item.get("raw")
        if not isinstance(raw, str) or not raw.strip():
            return None, _error(f"records[{i}].raw must be a non-empty string", 400)

        received_at = utcnow()
        ts = item.get("timestamp")
        if ts is not None:
            from siem.parsing.normalizer import parse_timestamp

            received_at = parse_timestamp(ts, default=received_at)

        records.append(
            RawLogRecord(
                raw=raw,
                source_id=str(item.get("source_id") or default_source_id)[:_MAX_SOURCE_LEN],
                source_type=str(item.get("source_type") or default_source_type)[:_MAX_SOURCE_LEN],
                transport="http",
                peer=request.remote_addr,
                format_hint=normalize_format_hint(item.get("format_hint")) or default_hint,
                received_at=received_at,
            )
        )
    return records, None


@bp.route("/ingest", methods=["POST"])
def ingest():
    config: Config = current_app.extensions["siem_config"]

    if not config.get("ingestion.http.enabled", True):
        return _error("Ingestion API disabled", 404)

    auth = _authenticate(config)
    if auth is None:
        return _error("Missing or invalid bearer token", 401)
    token_id = auth[0]

    limit = int(config.get("ingestion.http.rate_limit_per_minute", 10000) or 0)
    if not _rate_limit_ok(token_id, limit):
        return _error("Rate limit exceeded", 429, retry_after=60)

    max_body = int(config.get("ingestion.http.max_body_bytes", 2 * 1024 * 1024))
    if request.content_length and request.content_length > max_body:
        return _error(f"Request body exceeds {max_body} bytes", 413)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Body must be a JSON object", 400)

    max_batch = int(config.get("ingestion.http.max_batch", 1000))
    records, error = _build_records(payload, max_batch)
    if error is not None:
        return error
    assert records is not None

    # Preferred path: hand the batch to the running streaming pipeline.
    pipeline = current_app.extensions.get("siem_pipeline")
    accepted: Optional[int] = None
    if pipeline is not None:
        timeout = float(config.get("ingestion.http.queue_timeout_seconds", 2.0) or 0)
        try:
            accepted = pipeline.enqueue_records(records, timeout=timeout)
        except RuntimeError:
            accepted = None  # pipeline not running; fall back to sync below

    if accepted is None:
        # Dashboard-only mode (siem serve): process inline. Lazy-built once.
        sync_pipeline = current_app.extensions.get("siem_ingest_pipeline")
        if sync_pipeline is None:
            from siem.pipeline import Pipeline

            sync_pipeline = Pipeline(config, current_app.extensions["siem_storage"])
            current_app.extensions["siem_ingest_pipeline"] = sync_pipeline
            log.info("Ingest API using synchronous fallback pipeline")
        accepted = 0
        for record in records:
            sync_pipeline.process_record(record)
            accepted += 1

    rejected = len(records) - accepted
    if rejected:
        # Queue saturated: tell the agent to spool and retry the remainder.
        return jsonify(ok=False, accepted=accepted, rejected=rejected, retry_after=1), 503
    log.debug("Ingest accepted %d record(s) from token=%s", accepted, token_id)
    return jsonify(ok=True, accepted=accepted), 200
