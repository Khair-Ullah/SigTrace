"""Tests for the plaintext heuristic parser."""
from siem.parsing.parsers import plaintext_parser


def test_firewall_deny():
    fields = plaintext_parser.parse("Denied TCP connection from 192.168.1.45 to 10.0.0.5:22")
    assert fields["src_ip"] == "192.168.1.45"
    assert fields["dst_ip"] == "10.0.0.5"
    assert fields["dst_port"] == 22
    assert fields["event_type"] == "firewall_deny"
    assert fields["action"] == "denied"


def test_ssh_failed_login():
    fields = plaintext_parser.parse("Failed password for invalid user admin from 10.0.0.8")
    assert fields["event_type"] == "failed_login"
    assert fields["src_ip"] == "10.0.0.8"
    assert fields["severity"] == "medium"


def test_web_access_log():
    raw = '192.168.1.5 - - [16/Oct/2026:14:32:11 +0000] "GET /admin HTTP/1.1" 403 512'
    fields = plaintext_parser.parse(raw)
    assert fields["src_ip"] == "192.168.1.5"
    assert fields["event_type"] == "web_access"
    assert fields["http_status"] == 403
    assert fields["severity"] == "medium"


def test_generic_line():
    fields = plaintext_parser.parse("some completely unstructured message")
    assert fields["event_type"] == "generic"
    assert fields["message"] == "some completely unstructured message"


def test_ufw_block_is_deny():
    fields = plaintext_parser.parse(
        "Oct 17 10:20:04 fw-01 kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.5 "
        "PROTO=TCP DPT=22"
    )
    assert fields["event_type"] == "firewall_deny"
    assert fields["src_ip"] == "1.2.3.4"
    assert fields["dst_ip"] == "10.0.0.5"
    assert fields["dst_port"] == 22


def test_ufw_block_extracts_src_port_protocol_and_interface():
    fields = plaintext_parser.parse(
        "Oct 17 10:20:04 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.163 "
        "DST=10.0.0.5 PROTO=TCP SPT=44365 DPT=3389 WINDOW=1024 SYN"
    )
    assert fields["event_type"] == "firewall_deny"
    assert fields["src_port"] == 44365
    assert fields["dst_port"] == 3389
    assert fields["protocol"] == "tcp"
    assert fields["in_interface"] == "eth0"


def test_iptables_drop_extracts_fields():
    fields = plaintext_parser.parse(
        "Oct 17 10:20:04 fw-01 kernel: DROP IN=eth0 SRC=203.0.113.50 DST=10.0.0.5 "
        "PROTO=TCP SPT=51100 DPT=22 WINDOW=1024 SYN"
    )
    assert fields["event_type"] == "firewall_deny"
    assert fields["src_ip"] == "203.0.113.50"
    assert fields["src_port"] == 51100
    assert fields["dst_port"] == 22
    assert fields["protocol"] == "tcp"
    assert fields["in_interface"] == "eth0"


def test_leading_rfc3164_timestamp_extracted():
    fields = plaintext_parser.parse(
        "Oct 17 10:20:04 srv-01 kernel: [UFW BLOCK] SRC=1.2.3.4 DST=10.0.0.5"
    )
    assert fields["timestamp_str"] == "Oct 17 10:20:04"


def test_no_timestamp_when_absent():
    fields = plaintext_parser.parse("Denied TCP connection from 192.168.1.45")
    assert "timestamp_str" not in fields
