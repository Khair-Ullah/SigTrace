# REST API

The dashboard is backed by a JSON API under `/api`. All endpoints except
`/api/health` require an authenticated session (browser cookie) or
`login_required`.

## Authentication

The API uses the same **session cookie** as the dashboard. Sign in first:

```powershell
# Establish a session (cookie jar) and grab the CSRF token
curl -c cookies.txt http://localhost:5000/login
```

> **CSRF:** state-changing requests (`POST`) must include the CSRF token that
> Flask-WTF issues for the session. When `web.csrf_enabled` is `true`, a
> missing/invalid token returns **400**.

## Pagination & filtering conventions

List endpoints accept `page` (default `1`) and `per_page` (default `25`, max
`200`) and return:

```json
{
  "items": [ ... ],
  "meta": { "total": 42, "page": 1, "per_page": 25, "pages": 2,
            "has_prev": false, "has_next": true }
}
```

Date filters (`start`, `end`) accept ISO-8601 (`2026-10-17T00:00:00`, a
trailing `Z` is tolerated).

## Reference

### `GET /api/health` — public

```json
{ "status": "ok", "service": "siem-web" }
```

### `GET /api/stats`

Dashboard summary counts (`events`, `alerts`, `incidents`, severities, etc.),
see `DashboardStats.summary()`.

### `GET /api/stats/timeline?hours=24`

Hour-bucketed event/alert counts. `hours` is clamped to `1..168`.

### `GET /api/alerts`

Query params: `severity`, `src_ip`, `incident_id`, `acknowledged`
(`true`/`false`), `start`, `end`, `page`, `per_page`.

Item shape:

```json
{
  "alert_id": "ALT-...", "rule_id": "...", "rule_name": "SSH Brute Force ...",
  "timestamp": "2026-10-17T12:00:00", "severity": "high",
  "src_ip": "203.0.113.9", "dst_ip": "10.0.0.5", "user_name": "root",
  "event_ids": ["..."], "count": 6, "incident_id": "INC-...",
  "description": "", "acknowledged": false, "rule_tags": ["attack.credential_access"]
}
```

### `GET /api/alerts/<alert_id>`

Returns a single alert; **404** if not found.

### `POST /api/alerts/<alert_id>/ack` — analyst+

Body (JSON or form): `{ "acknowledged": true }` (default `true`). Returns
`{ "ok": true, "alert_id": "...", "acknowledged": true }`. Writes an
`alert_ack`/`alert_unack` audit entry. **404** if missing.

### `GET /api/incidents`

Query params: `status` (`open`/`investigating`/`closed`), `severity`,
`src_ip`, `user_name`, `start`, `end`, `page`, `per_page`.

### `GET /api/incidents/<incident_id>`

Incident plus its `alerts` array.

### `POST /api/incidents/<incident_id>/status` — analyst+

Body: `{ "status": "investigating" }` (must be a valid status). **400** on an
invalid status, **404** if not found. Writes an `incident_status` audit entry.

### `GET /api/events`

Query params: `severity`, `src_ip`, `dst_ip`, `event_type`, `source_id`,
`user_name`, `q` (message substring), `start`, `end`, `page`, `per_page`.

### `GET /api/rules`

```json
{ "items": [ { "rule_id": "...", "title": "...", "level": "high",
               "enabled": true, "tags": [ ... ], "file_path": "..." } ] }
```

### `POST /api/rules/<rule_id>/toggle` — admin only

Body: `{ "is_enabled": false }`. Omit to flip the current state. Returns
`{ "ok": true, "rule_id": "...", "is_enabled": false }`. Writes a
`rule_toggle` audit entry.

### `GET /api/notifications`

Query params: `channel`, `status`, `alert_id`, `incident_id`, `page`,
`per_page`. Notification `status` is one of `sent`, `skipped`, `failed`,
`rate_limited`, `duplicate`.

## Monitor (local-log collection)

The interactive **Monitor** tab uses these endpoints (mounted under
`/monitor/api`). `status`, `start` and `stop` return the current monitor
status object; unsafe requests require the `X-CSRFToken` header.

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `/monitor/api/status` | GET | viewer+ | Current state: `running`, counters, per-source status |
| `/monitor/api/events?limit=N` | GET | viewer+ | Most recently collected events (bounded buffer) |
| `/monitor/api/start` | POST | admin | Begin monitoring (starts a background collector) |
| `/monitor/api/stop` | POST | admin | Stop monitoring |
| `/monitor/api/clear` | POST | admin | Clear the recent-events buffer |

## Roles

| Action | viewer | analyst | admin |
| --- | --- | :---: | :---: |
| Read endpoints (`GET`) | ✅ | ✅ | ✅ |
| Acknowledge alerts / set incident status | — | ✅ | ✅ |
| Toggle rules | — | — | ✅ |
| Start/stop the local Monitor | — | — | ✅ |

## Realtime (WebSocket)

Alert and incident updates are pushed over **Socket.IO** on namespace
`/realtime`. Connect with the session cookie; events include new alerts and
incident status changes. Origins are controlled by `web.socketio_cors`.

## Error responses

| Status | Meaning |
| --- | --- |
| `400` | Bad request (invalid filter/status or missing CSRF token) |
| `401` | Not authenticated (API) / redirect to login (pages) |
| `403` | Authenticated but insufficient role |
| `404` | Resource not found |
