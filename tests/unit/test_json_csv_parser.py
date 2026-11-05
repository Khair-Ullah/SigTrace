"""Tests for JSON and CSV parsers."""
from siem.parsing.parsers import csv_parser, json_parser


def test_json_flat():
    fields = json_parser.parse('{"src_ip": "1.2.3.4", "action": "login", "user": "admin"}')
    assert fields == {"src_ip": "1.2.3.4", "action": "login", "user": "admin"}


def test_json_nested_flatten():
    fields = json_parser.parse('{"a": {"b": 1}, "list": [1, 2]}')
    assert fields["a_b"] == 1
    assert fields["list"] == "[1, 2]"


def test_json_list_takes_first_object():
    fields = json_parser.parse('[{"x": 1}, {"y": 2}]')
    assert fields == {"x": 1}


def test_json_invalid_returns_none():
    assert json_parser.parse("{not valid json") is None


def test_csv_header_then_rows():
    p = csv_parser.CSVParser()
    fields, is_header = p.parse("src_ip,user,action", "s1")
    assert is_header and fields == {}

    fields, is_header = p.parse("1.2.3.4,admin,login", "s1")
    assert not is_header
    assert fields == {"src_ip": "1.2.3.4", "user": "admin", "action": "login"}


def test_csv_generic_without_header():
    p = csv_parser.CSVParser()
    fields, is_header = p.parse("1,2,3", "s2")
    assert not is_header
    assert fields == {"col_0": "1", "col_1": "2", "col_2": "3"}


def test_csv_explicit_columns():
    p = csv_parser.CSVParser()
    p.set_columns("s3", ["ip", "port", "status"])
    fields, _ = p.parse("1.2.3.4,22,ok", "s3")
    assert fields == {"ip": "1.2.3.4", "port": "22", "status": "ok"}
