-- ============================================================
-- SIEM Log Correlation Engine - Migration 005
-- Surface the network context (protocol/direction/interfaces)
-- on alerts and incidents so the dashboard can display it.
-- SQLite dialect (ALTER TABLE ... ADD COLUMN).
-- ============================================================

ALTER TABLE alerts ADD COLUMN protocol TEXT;
ALTER TABLE alerts ADD COLUMN direction TEXT;
ALTER TABLE alerts ADD COLUMN in_interface TEXT;
ALTER TABLE alerts ADD COLUMN out_interface TEXT;

ALTER TABLE incidents ADD COLUMN protocol TEXT;
ALTER TABLE incidents ADD COLUMN direction TEXT;
ALTER TABLE incidents ADD COLUMN in_interface TEXT;
ALTER TABLE incidents ADD COLUMN out_interface TEXT;
