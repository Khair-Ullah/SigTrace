"""End-to-end pipeline integration test: file -> events -> alerts -> incident."""
import pytest

from siem.alerting.manager import AlertNotifier
from siem.alerting.notifiers import CallbackNotifier
from siem.core.config import load_config
from siem.pipeline import Pipeline
from siem.simulators import LogSimulator


@pytest.fixture
def pipeline_config():
    cfg = load_config()
    cfg.set("alerting.email.enabled", False)
    cfg.set("alerting.logfile.enabled", False)
    return cfg


def test_file_to_incident_flow(tmp_path, storage, pipeline_config):
    logs = LogSimulator(seed=11).generate("multi_stage")
    log_file = tmp_path / "attack.log"
    log_file.write_text("\n".join(entry.raw for entry in logs), encoding="utf-8")

    sent = []
    notifier = AlertNotifier(
        pipeline_config,
        notifiers=[CallbackNotifier([lambda a, i: sent.append((a, i))],
                                    min_severity="low")],
        notification_repo=storage.notifications,
    )
    pipeline = Pipeline(pipeline_config, storage, notifier=notifier)

    results = pipeline.ingest_file(log_file, source_id="edge-01",
                                   source_type="firewall")

    assert pipeline.stats.parsed == len(logs)
    assert storage.events.count() == len(logs)
    assert storage.alerts.count() == 3

    incidents = storage.incidents.query()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity == "critical"
    assert incident.alert_count == 3
    assert incident.correlation_rule_id is not None

    # Correlation linked all alerts to the incident in storage
    linked = storage.alerts.query(incident_id=incident.incident_id)
    assert len(linked) == 3

    assert len(sent) == 3
    assert storage.notifications.count() >= 3


def test_rule_toggle_affects_detection(storage, pipeline_config):
    pipeline = Pipeline(
        pipeline_config, storage, persist=False,
        notifier=AlertNotifier(pipeline_config, notifiers=[]),
    )
    pipeline.ingest_simulated(LogSimulator(seed=12).generate("port_scan"))
    assert pipeline.stats.alerts == 1

    # Disable the port-scan rule; the same traffic must no longer alert.
    for rule in pipeline.rules:
        if "Port Scan" in rule.title:
            rule.enabled = False
    pipeline.engine.set_rules(pipeline.rules)

    pipeline.ingest_simulated(LogSimulator(seed=12).generate("port_scan"))
    assert pipeline.stats.alerts == 1  # unchanged
