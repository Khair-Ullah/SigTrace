"""Tests for the SQL migration runner."""
import sqlite3

from siem.storage.migrations import current_version, run_migrations


def _tables(db_path) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return {r[0] for r in rows}
    finally:
        conn.close()


def _columns(db_path, table) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {r[1] for r in rows}
    finally:
        conn.close()


def test_fresh_migration_creates_all_tables(tmp_path):
    db = tmp_path / "fresh.db"
    applied = run_migrations(db)

    assert applied == [
        "001_initial.sql",
        "002_alert_incident_columns.sql",
        "003_notifications.sql",
        "004_event_extra_columns.sql",
        "005_alert_incident_network_columns.sql",
    ]
    assert current_version(db) == 5

    tables = _tables(db)
    for expected in ("events", "alerts", "incidents", "rules", "users",
                     "audit_log", "config", "correlation_state",
                     "notifications", "schema_migrations"):
        assert expected in tables


def test_migration_adds_columns(tmp_path):
    db = tmp_path / "cols.db"
    run_migrations(db)

    assert {"count", "description", "rule_tags"} <= _columns(db, "alerts")
    assert {"categories", "correlation_rule_id"} <= _columns(db, "incidents")
    assert {"protocol", "direction", "in_interface", "out_interface",
            "extra"} <= _columns(db, "events")
    net = {"protocol", "direction", "in_interface", "out_interface"}
    assert net <= _columns(db, "alerts")
    assert net <= _columns(db, "incidents")


def test_migration_is_idempotent(tmp_path):
    db = tmp_path / "idem.db"
    run_migrations(db)
    second = run_migrations(db)
    assert second == []
    assert current_version(db) == 5


def test_config_seeded(tmp_path):
    db = tmp_path / "seed.db"
    run_migrations(db)
    conn = sqlite3.connect(str(db))
    try:
        row = conn.execute(
            "SELECT value FROM config WHERE key='retention_days'"
        ).fetchone()
    finally:
        conn.close()
    assert row == ("30",)


def test_legacy_db_adopts_001(tmp_path):
    """A DB created before migration tracking should adopt 001 and apply 002."""
    from siem.storage.migrations import MIGRATIONS_DIR

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.executescript((MIGRATIONS_DIR / "001_initial.sql").read_text("utf-8"))
        conn.commit()
    finally:
        conn.close()

    applied = run_migrations(db)
    assert "001_initial.sql" in applied          # adopted
    assert "002_alert_incident_columns.sql" in applied
    assert {"count", "description", "rule_tags"} <= _columns(db, "alerts")
