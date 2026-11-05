"""Tests for the pfSense/OPNsense filterlog parser."""
from siem.parsing import detectors
from siem.parsing.parsers import pfsense_parser

FRAMED_TCP_BLOCK = (
    "<134>Oct 19 10:15:02 fw01 filterlog: 5,,,1000000103,vtnet0,match,block,in,"
    "4,0x0,,64,12345,0,DF,6,tcp,60,192.168.1.50,1.2.3.4,54321,80,0,S"
)
BARE_TCP_BLOCK = FRAMED_TCP_BLOCK.split("filterlog: ", 1)[1]
PLAINTEXT_FRAME = (
    "Oct 19 10:15:02 fw01 filterlog: " + BARE_TCP_BLOCK
)
UDP_PASS = (
    "5,,,1000000103,vtnet0,match,pass,in,4,0x0,,64,12345,0,,17,udp,60,"
    "192.168.1.5,8.8.8.8,5353,53,0"
)
ICMP_BLOCK = (
    "5,,,1000000103,vtnet0,match,block,in,4,0x0,,64,12345,0,,1,icmp,84,"
    "192.168.1.5,8.8.8.8,0,0,request"
)


def test_is_filterlog_accepts_syslog_framed():
    assert pfsense_parser.is_filterlog(FRAMED_TCP_BLOCK)


def test_is_filterlog_accepts_bare_csv():
    assert pfsense_parser.is_filterlog(BARE_TCP_BLOCK)


def test_is_filterlog_rejects_other_text():
    assert not pfsense_parser.is_filterlog("Failed password for root from 10.0.0.1")


def test_is_filterlog_rejects_plain_csv():
    assert not pfsense_parser.is_filterlog("name,iface,action\nwan0,block")


def test_parse_bare_csv_tcp_block():
    fields = pfsense_parser.parse(BARE_TCP_BLOCK)
    assert fields["event_type"] == "firewall_deny"
    assert fields["action"] == "denied"
    assert fields["src_ip"] == "192.168.1.50"
    assert fields["dst_ip"] == "1.2.3.4"
    assert fields["src_port"] == 54321
    assert fields["dst_port"] == 80
    assert fields["protocol"] == "tcp"
    assert fields["direction"] == "in"
    assert fields["severity"] == "low"


def test_parse_syslog_framed_tcp_block():
    fields = pfsense_parser.parse(FRAMED_TCP_BLOCK)
    assert fields["event_type"] == "firewall_deny"
    assert fields["src_ip"] == "192.168.1.50"
    assert fields["dst_port"] == 80


def test_parse_plaintext_frame_extracts_timestamp():
    fields = pfsense_parser.parse(PLAINTEXT_FRAME)
    assert fields["timestamp_str"] == "Oct 19 10:15:02"
    assert fields["src_ip"] == "192.168.1.50"


def test_parse_udp_pass():
    fields = pfsense_parser.parse(UDP_PASS)
    assert fields["event_type"] == "firewall_allow"
    assert fields["action"] == "allowed"
    assert fields["src_port"] == 5353
    assert fields["dst_port"] == 53
    assert fields["protocol"] == "udp"


def test_parse_icmp_has_no_ports():
    fields = pfsense_parser.parse(ICMP_BLOCK)
    assert fields["event_type"] == "firewall_deny"
    assert fields["protocol"] == "icmp"
    assert "src_port" not in fields
    assert "dst_port" not in fields


def test_parse_rejects_non_filterlog():
    assert pfsense_parser.parse("random, text, line") is None


def test_detector_routes_filterlog_to_plaintext():
    assert detectors.detect_format(BARE_TCP_BLOCK) == detectors.FORMAT_PLAINTEXT
    assert detectors.detect_format(FRAMED_TCP_BLOCK) == detectors.FORMAT_SYSLOG
