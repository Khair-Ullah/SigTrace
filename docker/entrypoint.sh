#!/usr/bin/env bash
#
# Container entrypoint for the SIEM engine.
#
#   1. initialises/upgrades the SQLite schema (idempotent),
#   2. optionally bootstraps an admin user from the environment,
#   3. execs the CLI (default: "run --web").
#
set -euo pipefail

cd /app

echo "[entrypoint] Initialising database..."
python scripts/setup_db.py || echo "[entrypoint] WARNING: database setup reported an error"

if [[ -n "${SIEM_ADMIN_USER:-}" && -n "${SIEM_ADMIN_PASSWORD:-}" ]]; then
    role="${SIEM_ADMIN_ROLE:-admin}"
    echo "[entrypoint] Ensuring admin user '${SIEM_ADMIN_USER}' exists..."
    python scripts/create_user.py create \
        --username "${SIEM_ADMIN_USER}" \
        --password "${SIEM_ADMIN_PASSWORD}" \
        --role "${role}" \
        || echo "[entrypoint] NOTE: user '${SIEM_ADMIN_USER}' already exists (skipped)"
fi

echo "[entrypoint] Starting: siem $*"
exec python -m siem "$@"
