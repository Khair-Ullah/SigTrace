"""Extended event fields (protocol/interface/direction) persist and round-trip."""
from siem.core.utils import utcnow
from siem.parsing.models import NormalizedEvent
from siem.storage.mappers import event_to_orm, event_to_row, orm_to_event


def _event(event_id: str, **extra) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=utcnow(),
        source_id="pfsense-01",
        source_type="firewall",
        raw_log="5,,,1000000103,vtnet0,match,block,in,4,...,tcp,60,192.168.1.50,1.2.3.4,54321,80",
        src_ip="192.168.1.50",
        dst_ip="1.2.3.4",
        src_port=54321,
        dst_port=80,
        event_type="firewall_deny",
        action="denied",
        extra=extra,
    )


def test_split_promotes_columns_and_keeps_rest():
    orm = event_to_orm(_event(
        "e1", protocol="tcp", direction="in", in_interface="vtnet0",
        ip_version="4", windows_event_id="4625",
    ))
    assert orm.protocol == "tcp"
    assert orm.direction == "in"
    assert orm.in_interface == "vtnet0"
    assert orm.out_interface is None
    # Non-promoted fields stay in the JSON blob.
    assert orm.extra is not None and "windows_event_id" in orm.extra
    assert "ip_version" in orm.extra
    assert "protocol" not in orm.extra


def test_event_to_row_has_all_columns():
    row = event_to_row(_event("e2", protocol="udp", out_interface="eth1"))
    for key in ("protocol", "direction", "in_interface", "out_interface", "extra"):
        assert key in row
    assert row["protocol"] == "udp"
    assert row["out_interface"] == "eth1"


def test_persist_and_read_back(storage):
    storage.events.add(_event(
        "e3", protocol="tcp", direction="in", in_interface="vtnet0",
        ip_version="4", windows_event_id="4625",
    ))
    got = storage.events.get("e3")
    assert got is not None
    assert got.extra["protocol"] == "tcp"
    assert got.extra["direction"] == "in"
    assert got.extra["in_interface"] == "vtnet0"
    assert got.extra["ip_version"] == "4"
    assert got.extra["windows_event_id"] == "4625"
    # promoted columns are not duplicated in the raw JSON blob
    assert got.src_port == 54321 and got.dst_port == 80


def test_bulk_insert_round_trip(storage):
    events = [
        _event(f"bulk-{i}", protocol="udp", direction="out", out_interface="eth1",
               ip_version="4")
        for i in range(5)
    ]
    storage.persist_events(events)
    got = storage.events.get("bulk-3")
    assert got is not None
    assert got.extra["protocol"] == "udp"
    assert got.extra["out_interface"] == "eth1"


def test_orm_to_event_without_extra_is_empty():
    event = _event("e4")
    row = event_to_orm(event)
    restored = orm_to_event(row)
    assert restored.extra == {}


def test_alert_and_incident_network_fields_round_trip(storage):
    from siem.engine.models import Alert, Incident

    alert = Alert(
        alert_id="a-net-1", rule_id="R-1", rule_name="Test rule",
        timestamp=utcnow(), severity="high", src_ip="198.51.100.9",
        protocol="tcp", direction="in", in_interface="vtnet0",
    )
    storage.alerts.add(alert)
    got_alert = storage.alerts.get("a-net-1")
    assert got_alert.protocol == "tcp"
    assert got_alert.direction == "in"
    assert got_alert.in_interface == "vtnet0"

    incident = Incident(
        incident_id="i-net-1", title="Test incident", severity="critical",
        first_seen=utcnow(), last_seen=utcnow(), protocol="udp",
        direction="out", out_interface="eth1",
    )
    storage.incidents.upsert(incident)
    got_inc = storage.incidents.get("i-net-1")
    assert got_inc.protocol == "udp"
    assert got_inc.direction == "out"
    assert got_inc.out_interface == "eth1"

