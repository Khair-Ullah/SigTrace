"""Unit tests for SOAR-Lite playbooks."""
from __future__ import annotations

from datetime import datetime, timezone

from siem.core.config import Config, load_config
from siem.engine.models import Alert, Incident
from siem.pipeline import Pipeline
from siem.simulators import LogSimulator
from siem.soar import PlaybookEngine, load_playbook_config

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_incident(severity="critical", src_ip="203.0.113.9", alert_count=2):
    return Incident(
        incident_id="inc-1",
        title="Suspicious activity",
        severity=severity,
        first_seen=NOW,
        last_seen=NOW,
        src_ip=src_ip,
        alert_count=alert_count,
        rule_names={"Network Port Scan Detection"},
        categories={"reconnaissance"},
        correlation_rule_id="corr-1",
    )


def make_alert():
    return Alert(
        alert_id="alert-1",
        rule_id="port-scan",
        rule_name="Network Port Scan Detection",
        timestamp=NOW,
        severity="critical",
        src_ip="203.0.113.9",
        dst_ip="10.0.0.10",
        user_name="alice",
    )


def make_config(tmp_path, email_enabled=False):
    return Config(
        {
            "soar": {"enabled": True},
            "alerting": {
                "email": {
                    "enabled": email_enabled,
                    "smtp_host": "localhost",
                    "smtp_port": 25,
                    "use_tls": False,
                    "username": "",
                    "password": "",
                    "from_address": "siem@example.com",
                }
            },
        },
        project_root=tmp_path,
    )


COMMAND_PLAYBOOK = """
version: 1
enabled: true
dry_run: false
max_runs_per_incident: 1
playbooks:
  - id: "block-source"
    name: "Block source"
    match:
      severities: ["critical"]
    actions:
      - name: "block"
        type: "command"
        command: ["echo", "{src_ip}"]
        require: ["src_ip"]
        timeout_seconds: 5
"""


def write_playbook(tmp_path, text=COMMAND_PLAYBOOK, name="playbooks.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_load_defaults_and_validation(tmp_path):
    path = write_playbook(
        tmp_path,
        """
version: 1
dry_run: true
playbooks:
  - id: "critical-only"
    actions:
      - type: "command"
        command: ["true"]
""",
    )

    loaded = load_playbook_config(path)

    assert loaded.enabled is True
    assert loaded.dry_run is True
    assert loaded.max_runs_per_incident == 1
    assert loaded.playbooks[0].match.severities == frozenset({"critical"})
    assert loaded.playbooks[0].actions[0].name == "command action 1"


def test_missing_file_disables_soar(tmp_path):
    engine = PlaybookEngine(make_config(tmp_path), tmp_path / "missing.yaml")

    assert engine.enabled is False
    assert engine.summary()["load_error"] == ""


def test_invalid_playbook_disables_soar_safely(tmp_path):
    path = write_playbook(
        tmp_path,
        """
playbooks:
  - id: "broken"
    actions:
      - type: "command"
""",
    )

    engine = PlaybookEngine(make_config(tmp_path), path)

    assert engine.enabled is False
    assert "requires a command" in engine.load_error


def test_matches_critical_once_and_ignores_high(tmp_path):
    calls = []
    path = write_playbook(tmp_path)

    def runner(argv, timeout, cwd, shell):
        calls.append((argv, timeout, cwd, shell))
        return 0, "blocked", ""

    engine = PlaybookEngine(make_config(tmp_path), path, command_runner=runner)
    alert = make_alert()
    incident = make_incident()

    first = engine.evaluate(incident, alert)
    second = engine.evaluate(incident, alert)
    high = engine.evaluate(make_incident(severity="high"), alert)

    assert len(first) == 1
    assert first[0].status == "completed"
    assert first[0].actions[0].status == "success"
    assert first[0].actions[0].output == "blocked"
    assert calls[0][0] == ["echo", "203.0.113.9"]
    assert second == []
    assert high == []
    assert engine.stats["runs"] == 1


def test_dry_run_does_not_execute_command(tmp_path):
    calls = []
    path = write_playbook(tmp_path)
    text = path.read_text(encoding="utf-8").replace("dry_run: false", "dry_run: true")
    path.write_text(text, encoding="utf-8")

    engine = PlaybookEngine(
        make_config(tmp_path),
        path,
        command_runner=lambda *args: calls.append(args) or (0, "", ""),
    )

    runs = engine.evaluate(make_incident(), make_alert())

    assert runs[0].status == "dry_run"
    assert "echo 203.0.113.9" in runs[0].actions[0].output
    assert calls == []
    assert engine.stats["actions_dry_run"] == 1


def test_action_requirement_skips_when_field_missing(tmp_path):
    calls = []
    engine = PlaybookEngine(
        make_config(tmp_path),
        write_playbook(tmp_path),
        command_runner=lambda *args: calls.append(args) or (0, "", ""),
    )

    runs = engine.evaluate(make_incident(src_ip=None), make_alert())

    assert runs[0].status == "skipped"
    assert runs[0].actions[0].status == "skipped"
    assert "src_ip" in runs[0].actions[0].detail
    assert calls == []


def test_command_failures_can_continue_or_stop(tmp_path):
    path = write_playbook(
        tmp_path,
        """
dry_run: false
playbooks:
  - id: "two-steps"
    actions:
      - name: "first"
        type: "command"
        command: ["fail"]
        continue_on_error: true
      - name: "second"
        type: "command"
        command: ["ok"]
""",
    )
    results = {"fail": (1, "", "boom"), "ok": (0, "fine", "")}

    engine = PlaybookEngine(
        make_config(tmp_path),
        path,
        command_runner=lambda argv, *_args: results[argv[0]],
    )
    run = engine.evaluate(make_incident(), make_alert())[0]
    assert run.status == "partial"
    assert [a.status for a in run.actions] == ["failed", "success"]

    stop_path = write_playbook(
        tmp_path,
        """
dry_run: false
playbooks:
  - id: "stop-on-failure"
    actions:
      - name: "first"
        type: "command"
        command: ["fail"]
        continue_on_error: false
      - name: "second"
        type: "command"
        command: ["ok"]
""",
        name="stop.yaml",
    )
    stop_engine = PlaybookEngine(
        make_config(tmp_path),
        stop_path,
        command_runner=lambda argv, *_args: results[argv[0]],
    )
    stopped = stop_engine.evaluate(make_incident(), make_alert())[0]
    assert stopped.status == "failed"
    assert [a.action_name for a in stopped.actions] == ["first"]
    assert "stopped" in stopped.error


def test_email_action_uses_rendered_message(tmp_path):
    path = write_playbook(
        tmp_path,
        """
dry_run: false
playbooks:
  - id: "notify"
    actions:
      - name: "notify"
        type: "email"
        to: ["soc@example.com"]
        subject: "[SOAR] {severity} {incident_id}"
        body: "Source: {src_ip}"
""",
    )
    sent = []

    engine = PlaybookEngine(
        make_config(tmp_path, email_enabled=True),
        path,
        email_sender=lambda message, config: sent.append(message),
    )
    run = engine.evaluate(make_incident(), make_alert())[0]

    assert run.status == "completed"
    assert len(sent) == 1
    assert sent[0]["Subject"] == "[SOAR] critical inc-1"
    assert sent[0]["To"] == "soc@example.com"
    assert "Source: 203.0.113.9" in sent[0].get_content()


def test_email_action_skips_when_email_disabled(tmp_path):
    path = write_playbook(
        tmp_path,
        """
dry_run: false
playbooks:
  - id: "notify"
    actions:
      - name: "notify"
        type: "email"
        to: ["soc@example.com"]
""",
    )
    engine = PlaybookEngine(
        make_config(tmp_path, email_enabled=False),
        path,
        email_sender=lambda *_: (_ for _ in ()).throw(AssertionError("sent")),
    )

    run = engine.evaluate(make_incident(), make_alert())[0]

    assert run.status == "skipped"
    assert "alerting.email.enabled" in run.actions[0].detail


def test_pipeline_triggers_soar_for_critical_incident(storage, tmp_path):
    cfg = load_config()
    cfg.set("alerting.email.enabled", False)
    cfg.set("alerting.logfile.enabled", False)

    calls = []
    engine = PlaybookEngine(
        cfg,
        write_playbook(tmp_path),
        command_runner=lambda argv, *_args: calls.append(argv) or (0, "blocked", ""),
    )
    pipeline = Pipeline(cfg, storage, playbook_engine=engine)

    results = pipeline.ingest_simulated(LogSimulator(seed=1).generate("multi_stage"))

    assert engine.stats["runs"] == 1
    assert pipeline.stats.soar_runs == 1
    assert pipeline.stats.soar_actions == 1
    assert calls == [["echo", "203.0.113.9"]]
    runs = [run for result in results for run in result.playbook_runs]
    assert len(runs) == 1
    assert runs[0].incident_id == storage.incidents.query()[0].incident_id
