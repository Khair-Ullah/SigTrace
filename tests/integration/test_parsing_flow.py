"""Integration test: RawLogRecord -> NormalizedEvent via LogParser."""
from siem.ingestion.base import RawLogRecord
from siem.parsing.parser import LogParser


def _rec(raw, **kw):
    return RawLogRecord(raw=raw, source_id=kw.get("source_id", "src"),
                        source_type=kw.get("source_type", "custom"))


def test_parse_syslog_to_normalized_event():
    parser = LogParser()
    raw = "<134>Oct 16 14:32:11 host sshd[1]: Failed password for admin from 1.2.3.4"
    event = parser.parse(_rec(raw, source_id="server-01", source_type="ssh"))
    assert event is not None
    assert event.src_ip == "1.2.3.4"
    assert event.event_type == "failed_login"
    assert event.source_id == "server-01"
    assert event.source_type == "ssh"
    assert event.raw_log == raw


def test_parse_plaintext_firewall():
    parser = LogParser()
    raw = "Denied TCP connection from 192.168.1.45 to 10.0.0.5:22"
    event = parser.parse(_rec(raw, source_type="firewall"))
    assert event is not None
    assert event.src_ip == "192.168.1.45"
    assert event.dst_ip == "10.0.0.5"
    assert event.dst_port == 22
    assert event.event_type == "firewall_deny"


def test_parse_json():
    parser = LogParser()
    raw = '{"src_ip": "1.2.3.4", "user": "admin", "level": "high", "event_type": "login"}'
    event = parser.parse(_rec(raw))
    assert event.user_name == "admin"
    assert event.severity == "high"


def test_parse_pfsense_filterlog_syslog():
    parser = LogParser()
    raw = ("<134>Oct 19 10:15:02 fw01 filterlog: 5,,,1000000103,vtnet0,match,block,in,"
           "4,0x0,,64,12345,0,DF,6,tcp,60,192.168.1.50,1.2.3.4,54321,80,0,S")
    event = parser.parse(_rec(raw, source_id="pfsense-01", source_type="firewall"))
    assert event is not None
    assert event.event_type == "firewall_deny"
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "1.2.3.4"
    assert event.src_port == 54321
    assert event.dst_port == 80
    assert event.source_type == "firewall"
    assert event.extra.get("protocol") == "tcp"


def test_parse_pfsense_filterlog_plaintext_frame():
    parser = LogParser()
    raw = ("Oct 19 10:15:22 fw01 filterlog: 5,,,1000000103,vtnet0,match,block,in,"
           "4,0x0,,64,12345,0,,1,icmp,84,192.168.1.5,8.8.8.8,0,0,request")
    event = parser.parse(_rec(raw, source_type="firewall"))
    assert event is not None
    assert event.event_type == "firewall_deny"
    assert event.src_ip == "192.168.1.5"
    assert event.dst_ip == "8.8.8.8"
    assert event.dst_port is None


def test_parser_stats():
    parser = LogParser()
    parser.parse(_rec("<134>Oct 16 14:32:11 h app[1]: hi"))
    parser.parse(_rec('{"a": 1}'))
    parser.parse(_rec("random text"))
    assert parser.stats["parsed"] == 3
    assert parser.stats["by_format"]["syslog"] == 1
    assert parser.stats["by_format"]["json"] == 1
    assert parser.stats["by_format"]["plaintext"] == 1
