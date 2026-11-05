"""Unit tests for the log simulator (Phase 9)."""
from datetime import datetime

import pytest

from siem.parsing.parser import LogParser
from siem.simulators import LogSimulator, SimulatedLog, generate_many
from siem.ingestion.base import RawLogRecord


def test_scenario_names():
    names = LogSimulator.scenario_names()
    assert "multi_stage" in names
    assert "port_scan" in names
    assert "normal" in names


def test_unknown_scenario_raises():
    with pytest.raises(ValueError):
        LogSimulator().generate("does-not-exist")


def test_generate_is_time_sorted():
    logs = LogSimulator(seed=1).generate("multi_stage")
    timestamps = [entry.timestamp for entry in logs]
    assert timestamps == sorted(timestamps)


def test_generate_is_deterministic_with_seed():
    a = LogSimulator(seed=99).generate("web_exploit")
    b = LogSimulator(seed=99).generate("web_exploit")
    assert [entry.raw for entry in a] == [entry.raw for entry in b]


def test_count_override():
    logs = LogSimulator(seed=1).generate("port_scan", count=5)
    assert len(logs) == 5


def test_normal_scenario_has_no_failures():
    logs = LogSimulator(seed=3).generate("normal")
    assert all(isinstance(entry, SimulatedLog) for entry in logs)
    assert logs


@pytest.mark.parametrize(
    "scenario,source_type,event_type",
    [
        ("port_scan", "firewall", "firewall_deny"),
        ("ssh_bruteforce", "ssh", "failed_login"),
        ("ssh_root_login", "ssh", "successful_login"),
    ],
)
def test_generated_lines_parse_to_expected_event(scenario, source_type, event_type):
    parser = LogParser()
    logs = LogSimulator(seed=5).generate(scenario)
    event = parser.parse(
        RawLogRecord(raw=logs[0].raw, source_id="sim", source_type=source_type)
    )
    assert event is not None
    assert event.event_type == event_type


def test_web_exploit_line_is_web_access():
    parser = LogParser()
    logs = LogSimulator(seed=5).generate("web_exploit")
    event = parser.parse(
        RawLogRecord(raw=logs[0].raw, source_id="web", source_type="web")
    )
    assert event is not None
    assert event.event_type == "web_access"


def test_generate_many_merges_and_sorts():
    base = datetime(2026, 10, 17, 12, 0, 0)
    logs = generate_many(["port_scan", "ssh_bruteforce"], seed=1, base=base)
    timestamps = [entry.timestamp for entry in logs]
    assert timestamps == sorted(timestamps)
    assert len(logs) == len(LogSimulator(seed=1).generate("port_scan", base=base)) + \
        len(LogSimulator(seed=1).generate("ssh_bruteforce", base=base))
