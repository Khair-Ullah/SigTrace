-- ============================================================
-- SIEM Log Correlation Engine - Migration 004
-- Persist extended event fields produced by the firewall/Windows parsers:
-- network protocol, traffic direction, interface names, plus a generic
-- JSON blob for any other detected fields (never lose parsed data).
-- SQLite dialect (ALTER TABLE ... ADD COLUMN).
-- ============================================================

ALTER TABLE events ADD COLUMN protocol TEXT;
ALTER TABLE events ADD COLUMN direction TEXT;
ALTER TABLE events ADD COLUMN in_interface TEXT;
ALTER TABLE events ADD COLUMN out_interface TEXT;
ALTER TABLE events ADD COLUMN extra TEXT;

CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
