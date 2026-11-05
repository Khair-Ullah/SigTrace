"""SQLAlchemy ORM models for the SIEM database (mirrors 001_initial.sql)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Return current UTC time (naive, consistent with SQLite storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Rule(Base):
    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    level: Mapped[str | None] = mapped_column(String)
    logsource: Mapped[str | None] = mapped_column(Text)
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str | None] = mapped_column(Text)
    is_enabled: Mapped[int] = mapped_column(Integer, default=1)
    loaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="open")
    src_ip: Mapped[str | None] = mapped_column(String)
    user_name: Mapped[str | None] = mapped_column(String)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    categories: Mapped[str | None] = mapped_column(Text)
    correlation_rule_id: Mapped[str | None] = mapped_column(String)
    protocol: Mapped[str | None] = mapped_column(String)
    direction: Mapped[str | None] = mapped_column(String)
    in_interface: Mapped[str | None] = mapped_column(String)
    out_interface: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("idx_incidents_severity", "severity"),
        Index("idx_incidents_status", "status"),
        Index("idx_incidents_first_seen", "first_seen"),
        Index("idx_incidents_src_ip", "src_ip"),
    )


class Event(Base):
    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_id: Mapped[str] = mapped_column(String, nullable=False)
    source_type: Mapped[str | None] = mapped_column(String)
    src_ip: Mapped[str | None] = mapped_column(String)
    dst_ip: Mapped[str | None] = mapped_column(String)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    user_name: Mapped[str | None] = mapped_column(String)
    action: Mapped[str | None] = mapped_column(String)
    event_type: Mapped[str | None] = mapped_column(String)
    severity: Mapped[str | None] = mapped_column(String)
    protocol: Mapped[str | None] = mapped_column(String)
    direction: Mapped[str | None] = mapped_column(String)
    in_interface: Mapped[str | None] = mapped_column(String)
    out_interface: Mapped[str | None] = mapped_column(String)
    extra: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    raw_log: Mapped[str | None] = mapped_column(Text)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_src_ip", "src_ip"),
        Index("idx_events_event_type", "event_type"),
        Index("idx_events_source_id", "source_id"),
        Index("idx_events_severity", "severity"),
        Index("idx_events_protocol", "protocol"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, ForeignKey("rules.rule_id"), nullable=False)
    rule_name: Mapped[str | None] = mapped_column(String)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String)
    dst_ip: Mapped[str | None] = mapped_column(String)
    user_name: Mapped[str | None] = mapped_column(String)
    event_ids: Mapped[str | None] = mapped_column(Text)
    incident_id: Mapped[str | None] = mapped_column(String, ForeignKey("incidents.incident_id"))
    acknowledged: Mapped[int] = mapped_column(Integer, default=0)
    count: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str | None] = mapped_column(Text)
    rule_tags: Mapped[str | None] = mapped_column(Text)
    protocol: Mapped[str | None] = mapped_column(String)
    direction: Mapped[str | None] = mapped_column(String)
    in_interface: Mapped[str | None] = mapped_column(String)
    out_interface: Mapped[str | None] = mapped_column(String)

    __table_args__ = (
        Index("idx_alerts_timestamp", "timestamp"),
        Index("idx_alerts_severity", "severity"),
        Index("idx_alerts_src_ip", "src_ip"),
        Index("idx_alerts_incident", "incident_id"),
        Index("idx_alerts_rule", "rule_id"),
    )


class CorrelationState(Base):
    __tablename__ = "correlation_state"

    state_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    group_key: Mapped[str] = mapped_column(String, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("idx_state_rule_group", "rule_id", "group_key"),
        Index("idx_state_window", "window_start"),
    )


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_log"

    log_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.user_id"))
    action: Mapped[str] = mapped_column(String, nullable=False)
    details: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String)

    __table_args__ = (Index("idx_audit_timestamp", "timestamp"),)


class Config(Base):
    __tablename__ = "config"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    notification_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str | None] = mapped_column(String)
    incident_id: Mapped[str | None] = mapped_column(String)
    channel: Mapped[str] = mapped_column(String, nullable=False)
    recipients: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("idx_notifications_alert", "alert_id"),
        Index("idx_notifications_incident", "incident_id"),
        Index("idx_notifications_channel", "channel"),
        Index("idx_notifications_created", "created_at"),
    )


DEFAULT_CONFIG = [
    ("retention_days", "30", "Number of days to keep events"),
    ("correlation_window", "300", "Correlation window in seconds"),
    ("alert_email_threshold", "high", "Minimum severity for email alerts"),
    ("syslog_udp_port", "514", "Syslog UDP listening port"),
    ("syslog_tcp_port", "514", "Syslog TCP listening port"),
    ("dashboard_port", "5000", "Dashboard HTTP port"),
]
