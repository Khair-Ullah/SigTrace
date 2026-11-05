-- ============================================================
-- SIEM Log Correlation Engine - Migration 003
-- Notification delivery log (email / logfile / websocket).
-- ============================================================

CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT,
    incident_id     TEXT,
    channel         TEXT NOT NULL,
    recipients      TEXT,
    status          TEXT NOT NULL,
    detail          TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_alert ON notifications(alert_id);
CREATE INDEX IF NOT EXISTS idx_notifications_incident ON notifications(incident_id);
CREATE INDEX IF NOT EXISTS idx_notifications_channel ON notifications(channel);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
