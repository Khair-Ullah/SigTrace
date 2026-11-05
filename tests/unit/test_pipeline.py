"""Unit tests for the end-to-end pipeline (Phase 9)."""
import pytest

from siem.alerting.manager import AlertNotifier
from siem.alerting.notifiers import CallbackNotifier
from siem.core.config import load_config
from siem.pipeline import Pipeline, PipelineStats
from siem.simulators import LogSimulator


@pytest.fixture
def pipeline_config():
    cfg = load_config()
    cfg.set("alerting.email.enabled", False)
    cfg.set("alerting.logfile.enabled", False)
    return cfg


def make_pipeline(storage, cfg, sent=None, **kwargs):
    notifiers = []
    if sent is not None:
        notifiers.append(
            CallbackNotifier([lambda a, i: sent.append((a, i))], min_severity="low")
        )
    notifier = AlertNotifier(
        cfg, notifiers=notifiers, notification_repo=getattr(storage, "notifications", None)
    )
    return Pipeline(cfg, storage, notifier=notifier, **kwargs)


def test_single_event_persisted(storage, pipeline_config):
    pipeline = make_pipeline(storage, pipeline_config)
    pipeline.process_raw(
        "UFW BLOCK SRC=203.0.113.9 DST=10.0.0.5 DPT=22 PROTO=TCP",
        source_type="firewall",
    )
    assert pipeline.stats.parsed == 1
    assert pipeline.stats.records == 1
    assert storage.events.count() == 1


def test_multi_stage_creates_critical_incident(storage, pipeline_config):
    sent = []
    pipeline = make_pipeline(storage, pipeline_config, sent=sent)
    logs = LogSimulator(seed=1).generate("multi_stage")

    results = pipeline.ingest_simulated(logs)

    assert pipeline.stats.alerts == 3
    assert pipeline.stats.incidents_created == 1
    assert storage.alerts.count() == 3

    incidents = storage.incidents.query()
    assert len(incidents) == 1
    assert incidents[0].severity == "critical"
    assert len(sent) == 3  # all three alerts notified

    # The first alert is pending; once the chain completes the incident is
    # attached to the subsequent alerts and all refer to the same incident.
    incident_ids = {e.incident.incident_id for e in results if e.incident is not None}
    assert incident_ids == {incidents[0].incident_id}
    assert sum(1 for e in results if e.incident is not None) == 2


def test_on_alert_callback_invoked(storage, pipeline_config):
    seen = []
    pipeline = make_pipeline(storage, pipeline_config, sent=[])
    pipeline.on_alert = lambda alert, incident: seen.append(alert.rule_name)

    pipeline.ingest_simulated(LogSimulator(seed=2).generate("port_scan"))

    assert seen == ["Network Port Scan Detection"]


def test_on_alert_error_does_not_break_pipeline(storage, pipeline_config):
    pipeline = make_pipeline(storage, pipeline_config, sent=[])

    def boom(_alert, _incident):
        raise RuntimeError("listener failure")

    pipeline.on_alert = boom
    # Should not raise despite the failing listener
    results = pipeline.ingest_simulated(LogSimulator().generate("port_scan"))
    assert pipeline.stats.alerts == 1


def test_dedup_suppresses_repeat_notification(storage, pipeline_config):
    pipeline = make_pipeline(storage, pipeline_config, sent=[])

    first = pipeline.ingest_simulated(LogSimulator(seed=7).generate("port_scan"))
    second = pipeline.ingest_simulated(LogSimulator(seed=7).generate("port_scan"))

    assert first[0].notifications[0].status == "sent"
    assert second[0].notifications[0].status == "duplicate"


def test_persist_disabled_writes_nothing(pipeline_config):
    pipeline = Pipeline(pipeline_config, storage=None, persist=False)
    results = pipeline.ingest_simulated(LogSimulator(seed=1).generate("multi_stage"))
    assert pipeline.stats.alerts == 3
    assert results  # processing still happens


def test_ingest_lines_skips_blank(storage, pipeline_config):
    pipeline = make_pipeline(storage, pipeline_config)
    pipeline.ingest_lines(["", "   ", "UFW BLOCK SRC=1.2.3.4 DST=5.6.7.8 DPT=22"],
                          source_type="firewall")
    assert pipeline.stats.parsed == 1


def test_summary_keys(storage, pipeline_config):
    pipeline = make_pipeline(storage, pipeline_config)
    summary = pipeline.summary()
    for key in ("records", "parsed", "alerts", "incidents_created", "engine",
                "correlator"):
        assert key in summary


def test_pipeline_stats_as_dict():
    stats = PipelineStats(records=3, parsed=2, alerts=1)
    data = stats.as_dict()
    assert data["records"] == 3 and data["alerts"] == 1
    assert data["incidents_created"] == 0
