-- ============================================================
-- SIEM Log Correlation Engine - Initial Schema (Migration 001)
-- SQLite dialect
-- ============================================================

-- RULES TABLE: Loaded Sigma/YAML rules
CREATE TABLE IF NOT EXISTS rules (
    rule_id         TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT,
    level           TEXT,
    logsource       TEXT,
    yaml_content    TEXT NOT NULL,
    file_path       TEXT,
    is_enabled      INTEGER DEFAULT 1,
    loaded_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- INCIDENTS TABLE: Correlated alerts ka group
-- (alerts table references this, so create first)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL,
    status          TEXT DEFAULT 'open',
    src_ip          TEXT,
    user_name       TEXT,
    first_seen      DATETIME NOT NULL,
    last_seen       DATETIME NOT NULL,
    alert_count     INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip);

-- EVENTS TABLE: Har normalized log yahan store hoga
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       DATETIME NOT NULL,
    source_id       TEXT NOT NULL,
    source_type     TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    user_name       TEXT,
    action          TEXT,
    event_type      TEXT,
    severity        TEXT,
    message         TEXT,
    raw_log         TEXT,
    ingested_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_id ON events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

-- ALERTS TABLE: Rule match hone par yahan alert aayega
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT,
    timestamp       DATETIME NOT NULL,
    severity        TEXT NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    user_name       TEXT,
    event_ids       TEXT,
    incident_id     TEXT,
    acknowledged    INTEGER DEFAULT 0,
    FOREIGN KEY (rule_id) REFERENCES rules(rule_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

-- STATE TABLE: Stateful correlation ke liye (brute force counter)
CREATE TABLE IF NOT EXISTS correlation_state (
    state_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT NOT NULL,
    group_key       TEXT NOT NULL,
    window_start    DATETIME NOT NULL,
    event_count     INTEGER DEFAULT 0,
    last_updated    DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(rule_id, group_key)
);

CREATE INDEX IF NOT EXISTS idx_state_rule_group ON correlation_state(rule_id, group_key);
CREATE INDEX IF NOT EXISTS idx_state_window ON correlation_state(window_start);

-- USERS TABLE: Dashboard login ke liye
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT DEFAULT 'analyst',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME
);

-- AUDIT LOG TABLE: Kisne kya kiya
CREATE TABLE IF NOT EXISTS audit_log (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id         INTEGER,
    action          TEXT NOT NULL,
    details         TEXT,
    ip_address      TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);

-- CONFIG TABLE: System settings
CREATE TABLE IF NOT EXISTS config (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    description     TEXT,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Default config values
INSERT OR IGNORE INTO config (key, value, description) VALUES
('retention_days', '30', 'Number of days to keep events'),
('correlation_window', '300', 'Correlation window in seconds'),
('alert_email_threshold', 'high', 'Minimum severity for email alerts'),
('syslog_udp_port', '514', 'Syslog UDP listening port'),
('syslog_tcp_port', '514', 'Syslog TCP listening port'),
('dashboard_port', '5000', 'Dashboard HTTP port');
