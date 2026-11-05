"""Syslog parsers for RFC 3164 and RFC 5424 (FR-03)."""
from __future__ import annotations

from typing import Optional

from siem.parsing import regex_patterns as rp

# Map syslog severity number (0-7) to (severity, event_type_hint)
_SYSLOG_SEVERITY = {
    0: "critical",  # Emergency
    1: "critical",  # Alert
    2: "critical",  # Critical
    3: "high",      # Error
    4: "medium",    # Warning
    5: "low",       # Notice
    6: "low",       # Info
    7: "low",       # Debug
}


def _facility_severity(pri: int) -> tuple[int, int, str]:
    facility = pri // 8
    severity_num = pri % 8
    return facility, severity_num, _SYSLOG_SEVERITY.get(severity_num, "low")


def parse_rfc5424(raw: str) -> Optional[dict]:
    m = rp.RFC5424.match(raw)
    if not m:
        return None
    pri = int(m.group("pri"))
    facility, sev_num, severity = _facility_severity(pri)
    return {
        "timestamp_str": m.group("timestamp"),
        "host": m.group("host"),
        "app": m.group("app"),
        "procid": m.group("procid"),
        "msgid": m.group("msgid"),
        "message": m.group("message") or "",
        "syslog_facility": facility,
        "syslog_severity": sev_num,
        "severity": severity,
        "logsource": m.group("app"),
    }


def parse_rfc3164(raw: str) -> Optional[dict]:
    m = rp.RFC3164.match(raw) or rp.RFC3164_NOTAG.match(raw)
    if not m:
        return None
    pri = int(m.group("pri"))
    facility, sev_num, severity = _facility_severity(pri)
    fields = {
        "timestamp_str": m.group("timestamp"),
        "host": m.group("host"),
        "message": m.group("message") or "",
        "syslog_facility": facility,
        "syslog_severity": sev_num,
        "severity": severity,
    }
    if "tag" in m.groupdict() and m.group("tag"):
        fields["logsource"] = m.group("tag")
        fields["app"] = m.group("tag")
    if m.groupdict().get("pid"):
        fields["procid"] = m.group("pid")
    return fields


def parse(raw: str) -> Optional[dict]:
    """Parse a syslog line, trying RFC 5424 then RFC 3164."""
    return parse_rfc5424(raw) or parse_rfc3164(raw)
