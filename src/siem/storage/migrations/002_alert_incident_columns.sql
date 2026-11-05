-- ============================================================
-- SIEM Log Correlation Engine - Migration 002
-- Extra columns to persist the full engine Alert/Incident model.
-- SQLite dialect (ALTER TABLE ... ADD COLUMN).
-- ============================================================

-- Alerts: capture threshold count, description and MITRE tags
ALTER TABLE alerts ADD COLUMN count INTEGER DEFAULT 1;
ALTER TABLE alerts ADD COLUMN description TEXT;
ALTER TABLE alerts ADD COLUMN rule_tags TEXT;

-- Incidents: capture derived attack categories and matched chain rule
ALTER TABLE incidents ADD COLUMN categories TEXT;
ALTER TABLE incidents ADD COLUMN correlation_rule_id TEXT;
