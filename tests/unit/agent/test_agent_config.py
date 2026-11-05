"""Tests for agent configuration loading."""
from __future__ import annotations

import pytest

from siem_agent.config import AgentConfigError, load_agent_config

YAML = """
server:
  url: http://siem.example:5000
  token: secret-token
  batch_size: 50
spool:
  path: my-spool
sources:
  read_from_beginning: true
  files:
    - path: /var/log/syslog
      source_id: syslog
      source_type: syslog
  windows:
    enabled: false
"""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SIEM_AGENT_URL", raising=False)
    monkeypatch.delenv("SIEM_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("SIEM_AGENT_CONFIG", raising=False)


def _write(tmp_path, content=YAML, name="agent.yaml"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_load_yaml_config(tmp_path):
    path = _write(tmp_path)
    cfg = load_agent_config(str(path))
    assert cfg.server_url == "http://siem.example:5000"
    assert cfg.token == "secret-token"
    assert cfg.batch_size == 50
    assert cfg.ingest_url == "http://siem.example:5000/api/ingest"
    assert cfg.health_url == "http://siem.example:5000/api/health"
    assert cfg.read_from_beginning is True
    assert len(cfg.files) == 1
    assert cfg.files[0]["source_id"] == "syslog"
    # relative spool path resolves against the config file's directory
    assert cfg.spool_dir == (tmp_path / "my-spool").resolve()


def test_json_config(tmp_path):
    path = _write(
        tmp_path,
        content='{"server": {"url": "https://x", "token": "t"}}',
        name="agent.json",
    )
    cfg = load_agent_config(str(path))
    assert cfg.server_url == "https://x"
    assert cfg.ingest_url == "https://x/api/ingest"


def test_env_overrides(tmp_path, monkeypatch):
    path = _write(tmp_path)
    monkeypatch.setenv("SIEM_AGENT_URL", "http://override:1234")
    monkeypatch.setenv("SIEM_AGENT_TOKEN", "override-token")
    cfg = load_agent_config(str(path))
    assert cfg.server_url == "http://override:1234"
    assert cfg.token == "override-token"


def test_discovery_in_cwd(tmp_path, monkeypatch):
    _write(tmp_path)
    monkeypatch.chdir(tmp_path)
    cfg = load_agent_config(None)
    assert cfg.token == "secret-token"


def test_missing_config_raises(tmp_path):
    with pytest.raises(AgentConfigError):
        load_agent_config(str(tmp_path / "nope.yaml"))


def test_missing_token_raises(tmp_path):
    path = _write(tmp_path, content="server:\n  url: http://x\n")
    with pytest.raises(AgentConfigError, match="token"):
        load_agent_config(str(path))


def test_bad_url_scheme_raises(tmp_path):
    path = _write(tmp_path, content="server:\n  url: ftp://x\n  token: t\n")
    with pytest.raises(AgentConfigError, match="http"):
        load_agent_config(str(path))


def test_non_mapping_root_raises(tmp_path):
    path = _write(tmp_path, content="- just\n- a list\n")
    with pytest.raises(AgentConfigError, match="mapping"):
        load_agent_config(str(path))
