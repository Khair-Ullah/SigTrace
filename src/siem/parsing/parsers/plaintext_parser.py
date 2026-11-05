"""Plaintext log parser using heuristic regex extraction (FR-14 fallback)."""
from __future__ import annotations

from typing import Optional

from siem.parsing import regex_patterns as rp


def _first_ip(text: str) -> Optional[str]:
    m = rp.IPV4.search(text)
    return m.group(0) if m else None


def parse(raw: str) -> dict:
    """Extract as many fields as possible from an arbitrary text log line."""
    fields: dict = {"message": raw}
    text = raw

    # --- Leading RFC3164 timestamp (on-disk syslog files have no <PRI>) --
    ts_match = rp.RFC3164_TS.match(text)
    if ts_match:
        fields["timestamp_str"] = ts_match.group("ts")

    # --- Web access log (combined/common log format) --------------------
    access = rp.ACCESS_LOG.match(text)
    if access:
        g = access.groupdict()
        fields["src_ip"] = g["src_ip"]
        fields["event_type"] = "web_access"
        fields["timestamp_str"] = g["timestamp"]
        status = int(g["status"])
        fields["action"] = g["request"]
        fields["http_status"] = status
        fields["severity"] = "medium" if status >= 400 else "low"
        return fields

    # --- IP addresses ---------------------------------------------------
    src = rp.SRC_HINT.search(text)
    if src:
        fields["src_ip"] = src.group("ip")
    dst = rp.DST_HINT.search(text)
    if dst:
        fields["dst_ip"] = dst.group("ip")

    # Fallback: first IP is source, second distinct IP is destination
    ips = rp.IPV4.findall(text)
    if "src_ip" not in fields and ips:
        fields["src_ip"] = ips[0]
    if "dst_ip" not in fields and len(ips) >= 2:
        fields["dst_ip"] = ips[1]

    # --- Ports ----------------------------------------------------------
    host_port = rp.HOST_PORT.search(text)
    if host_port:
        fields["dst_port"] = int(host_port.group("port"))
    port_kv = rp.PORT_KV.search(text)
    if port_kv and "dst_port" not in fields:
        fields["dst_port"] = int(port_kv.group("port"))
    sport_kv = rp.SPORT_KV.search(text)
    if sport_kv:
        fields["src_port"] = int(sport_kv.group("port"))

    # --- Protocol / interfaces (iptables / UFW key=value style) ----------
    proto = rp.PROTO_KV.search(text)
    if proto:
        fields["protocol"] = proto.group("proto").lower()
    iface_in = rp.IFACE_IN.search(text)
    if iface_in:
        fields["in_interface"] = iface_in.group("iface")
    iface_out = rp.IFACE_OUT.search(text)
    if iface_out:
        fields["out_interface"] = iface_out.group("iface")

    # --- User -----------------------------------------------------------
    um = rp.USER.search(text)
    if um:
        candidate = um.group("user")
        if candidate.lower() not in {"invalid", "from", "to"}:
            fields["user"] = candidate

    # --- Event type / action / severity heuristics ----------------------
    if rp.SSH_FAILED.search(text):
        fields["event_type"] = "failed_login"
        fields.setdefault("action", "login_failed")
        fields["severity"] = "medium"
    elif rp.SSH_SUCCESS.search(text):
        fields["event_type"] = "successful_login"
        fields.setdefault("action", "login_success")
        fields["severity"] = "low"
    elif rp.DENY.search(text):
        fields["event_type"] = "firewall_deny"
        fields.setdefault("action", "denied")
        fields["severity"] = "low"
    elif rp.ALLOW.search(text):
        fields["event_type"] = "firewall_allow"
        fields.setdefault("action", "allowed")
        fields["severity"] = "low"
    else:
        fields.setdefault("event_type", "generic")

    return fields
