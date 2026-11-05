"""pfSense / OPNsense ``filterlog`` parser (FR-14).

pfSense and OPNsense emit firewall events as a comma-separated ``filterlog``
payload, delivered either inside a syslog frame::

    <134>Oct 19 10:15:02 firewall filterlog: 5,,,1000000103,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.168.1.50,1.2.3.4,54321,80,47781,S

or as the same payload without a frame (on-disk ``filter.log`` / CSV export)::

    5,,,1000000103,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.168.1.50,1.2.3.4,54321,80,47781,S

Both forms are recognised here and mapped onto the canonical field names used
by :mod:`siem.parsing.normalizer`. The field layout follows the pfSense
filterlog documentation; the action column is located dynamically so the
metadata prefix can vary between releases.
"""
from __future__ import annotations

from typing import Optional

from siem.parsing import regex_patterns as rp

# action -> (event_type, canonical action)
_ACTIONS = {
    "block": ("firewall_deny", "denied"),
    "reject": ("firewall_deny", "denied"),
    "pass": ("firewall_allow", "allowed"),
}

# numeric protocol id -> name (IPv4 + IPv6 variants)
_PROTO_NAMES = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "58": "icmpv6",
    "132": "sctp",
}

# protocols whose trailing columns are <src>,<dst>,<sport>,<dport>
_PORT_PROTOCOLS = {"tcp", "udp", "sctp"}


def is_filterlog(raw: str) -> bool:
    """Return True when ``raw`` looks like a pfSense/OPNsense filterlog line."""
    if not raw:
        return False
    if rp.FILTERLOG_TAG.search(raw):
        return True
    if rp.FILTERLOG_ACTION.search(raw):
        # Bare CSV: the action keyword must sit within the leading columns.
        head = raw.split(",", 12)
        return any(c.strip().lower() in _ACTIONS for c in head)
    return False


def parse(raw: str) -> Optional[dict]:
    """Parse a filterlog line into canonical fields (None if not one)."""
    text = raw or ""
    if not is_filterlog(text):
        return None

    ts = rp.RFC3164_TS.match(text.strip())
    tag = rp.FILTERLOG_TAG.search(text)
    payload = text[tag.end():] if tag else text.strip()

    cols = [c.strip() for c in payload.split(",")]
    if len(cols) < 12:
        return None

    ai = _action_index(cols)
    if ai is None:
        return None

    event_type, action = _ACTIONS[cols[ai].lower()]

    direction = _at(cols, ai + 1)
    ip_version = _at(cols, ai + 2)
    proto_id = _at(cols, ai + 9)
    proto_name = (_at(cols, ai + 10) or _PROTO_NAMES.get(proto_id or "", "")).lower()
    src_ip = _at(cols, ai + 12)
    dst_ip = _at(cols, ai + 13)

    src_port = dst_port = None
    if proto_name in _PORT_PROTOCOLS:
        src_port = _to_int(_at(cols, ai + 14))
        dst_port = _to_int(_at(cols, ai + 15))

    fields: dict = {
        "message": text,
        "event_type": event_type,
        "action": action,
        "severity": "low",
    }
    if ts is not None:
        fields["timestamp_str"] = ts.group("ts")
    if src_ip:
        fields["src_ip"] = src_ip
    if dst_ip:
        fields["dst_ip"] = dst_ip
    if src_port is not None:
        fields["src_port"] = src_port
    if dst_port is not None:
        fields["dst_port"] = dst_port
    if proto_name:
        fields["protocol"] = proto_name
    if direction:
        fields["direction"] = direction
    if ip_version:
        fields["ip_version"] = ip_version
    return fields


def _action_index(cols: list[str]) -> Optional[int]:
    for i, col in enumerate(cols[:12]):
        if col.lower() in _ACTIONS:
            return i
    return None


def _at(cols: list[str], index: int) -> Optional[str]:
    if 0 <= index < len(cols):
        value = cols[index]
        return value or None
    return None


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
