"""Compiled regex patterns used by the plaintext and syslog parsers."""
from __future__ import annotations

import re

# --- Generic ---------------------------------------------------------------
IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# --- Syslog ----------------------------------------------------------------
SYSLOG_PRI = re.compile(r"^<(?P<pri>\d{1,3})>")

# RFC 3164 timestamp without a <PRI> frame (common in on-disk syslog files)
RFC3164_TS = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\S"
)

# RFC 3164: <PRI>MMM dd HH:MM:SS HOST TAG[PID]: MSG
RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

# RFC 3164 variant without a tag (message follows host directly)
RFC3164_NOTAG = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.*)$"
)

# RFC 5424: <PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG
RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[[^\]]*\])(?:\s(?P<message>.*))?$"
)

# --- Plaintext heuristics --------------------------------------------------
# "from 1.2.3.4" / "src=1.2.3.4" / "client 1.2.3.4"
SRC_HINT = re.compile(
    r"(?:from|src|source|client|ip)\s*[=:]?\s*"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.I,
)
DST_HINT = re.compile(
    r"(?:to|dst|dest|destination|server)\s*[=:]?\s*"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.I,
)
HOST_PORT = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})"
)
PORT_KV = re.compile(r"\b(?:port|dport|dst_port|dpt)\s*[=:]?\s*(?P<port>\d{1,5})", re.I)
SPORT_KV = re.compile(
    r"\b(?:sport|spt|src_port|source_port)\s*[=:]?\s*(?P<port>\d{1,5})", re.I
)
PROTO_KV = re.compile(r"\b(?:proto|protocol)\s*[=:]?\s*(?P<proto>[A-Za-z0-9]+)", re.I)
IFACE_IN = re.compile(r"\bIN=(?P<iface>\S+)", re.I)
IFACE_OUT = re.compile(r"\bOUT=(?P<iface>\S+)", re.I)
USER = re.compile(
    r"\b(?:user|username|for(?:\s+invalid\s+user)?)\s*[=:]?\s*"
    r"(?P<user>[A-Za-z0-9_.\-@]{1,64})",
    re.I,
)

SSH_FAILED = re.compile(r"(failed password|failed publickey|invalid user|authentication failure)", re.I)
SSH_SUCCESS = re.compile(r"(accepted password|accepted publickey|session opened)", re.I)
DENY = re.compile(r"\b(deny|denied|block|blocked|drop|dropped|reject|rejected)\b", re.I)
ALLOW = re.compile(r"\b(allow|allowed|accept|accepted|permit|permitted)\b", re.I)

# --- pfSense / OPNsense firewall (filterlog) --------------------------------
# Syslog tag that precedes the comma-separated filterlog payload.
FILTERLOG_TAG = re.compile(r"\bfilterlog:\s*", re.I)
# filterlog action token: one of the leading CSV columns is an action keyword.
FILTERLOG_ACTION = re.compile(r",(?:block|pass|reject)\s*,", re.I)

# Common web access log (combined common log format)
ACCESS_LOG = re.compile(
    r"^(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})\s+\S+\s+\S+\s+"
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)(?:\s+\"(?P<referer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)
