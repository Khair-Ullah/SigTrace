"""Agent configuration loading (agent.yaml / agent.json + environment)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_SEARCH_PATHS = (
    "agent.yaml",
    "agent.yml",
    "agent.json",
    "~/.config/siem-agent/agent.yaml",
    "~/.config/siem-agent/agent.json",
)


class AgentConfigError(Exception):
    """Raised when the agent configuration is missing or invalid."""


@dataclass
class AgentConfig:
    server_url: str
    token: str
    ingest_path: str = "/api/ingest"
    health_path: str = "/api/health"
    batch_size: int = 200
    flush_interval: float = 3.0
    request_timeout: float = 10.0
    spool_dir: Path = field(default_factory=lambda: Path("spool"))
    spool_max_mb: int = 500
    read_from_beginning: bool = False
    tail_interval: float = 0.5
    files: list[dict] = field(default_factory=list)
    windows_enabled: bool = False
    windows_channels: list[str] = field(
        default_factory=lambda: ["Security", "System", "Application"]
    )
    windows_poll_interval: float = 5.0
    windows_max_events: int = 100
    config_path: Optional[Path] = None

    @property
    def ingest_url(self) -> str:
        return self.server_url.rstrip("/") + self.ingest_path

    @property
    def health_url(self) -> str:
        return self.server_url.rstrip("/") + self.health_path


def _find_config(explicit: Optional[str] = None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_path = os.environ.get("SIEM_AGENT_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(Path(p) for p in DEFAULT_SEARCH_PATHS)

    for cand in candidates:
        expanded = cand.expanduser()
        if expanded.is_file():
            return expanded
    if explicit:
        raise AgentConfigError(f"Config file not found: {explicit}")
    raise AgentConfigError(
        "No agent config found. Create agent.yaml (see docs/deployment.md) "
        "or pass --config PATH."
    )


def _load_raw(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as e:  # pragma: no cover - yaml ships with the server
            raise AgentConfigError(
                "PyYAML is required for YAML configs: pip install PyYAML "
                "(or use an agent.json config instead)"
            ) from e
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise AgentConfigError(f"Config root must be a mapping: {path}")
    return data


def load_agent_config(explicit_path: Optional[str] = None) -> AgentConfig:
    """Load agent config from file with SIEM_AGENT_* env overrides."""
    path = _find_config(explicit_path)
    raw = _load_raw(path)

    server = raw.get("server") or {}
    spool = raw.get("spool") or {}
    sources = raw.get("sources") or {}
    windows = sources.get("windows") or {}

    url = os.environ.get("SIEM_AGENT_URL") or server.get("url") or ""
    token = os.environ.get("SIEM_AGENT_TOKEN") or server.get("token") or ""
    url = str(url).strip()
    token = str(token).strip()
    if not url:
        raise AgentConfigError("server.url is required (or set SIEM_AGENT_URL)")
    if not url.startswith(("http://", "https://")):
        raise AgentConfigError(f"server.url must start with http(s):// - got: {url}")
    if not token:
        raise AgentConfigError(
            "server.token is required (or set SIEM_AGENT_TOKEN). Create one on "
            'the server with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )

    spool_dir = Path(str(spool.get("path") or "spool")).expanduser()
    if not spool_dir.is_absolute():
        spool_dir = (path.parent / spool_dir).resolve()

    files = sources.get("files") or []
    if not isinstance(files, list):
        raise AgentConfigError("sources.files must be a list")

    cfg = AgentConfig(
        server_url=url.rstrip("/"),
        token=token,
        batch_size=max(1, int(server.get("batch_size", 200))),
        flush_interval=max(0.2, float(server.get("flush_interval_seconds", 3.0))),
        request_timeout=max(1.0, float(server.get("timeout_seconds", 10.0))),
        spool_dir=spool_dir,
        spool_max_mb=max(10, int(spool.get("max_mb", 500))),
        read_from_beginning=bool(sources.get("read_from_beginning", False)),
        tail_interval=max(0.1, float(sources.get("tail_interval_seconds", 0.5))),
        files=files,
        windows_enabled=bool(windows.get("enabled", False)),
        windows_channels=[
            str(c) for c in (windows.get("channels") or ["Security", "System", "Application"])
        ],
        windows_poll_interval=max(1.0, float(windows.get("poll_interval_seconds", 5.0))),
        windows_max_events=max(1, int(windows.get("max_events_per_poll", 100))),
        config_path=path,
    )
    return cfg
