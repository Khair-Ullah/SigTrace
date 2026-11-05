"""Service installation helpers (Windows: schtasks ONSTART, Linux: systemd).

The agent stays dependency-free; Windows uses a scheduled task that runs at
boot as SYSTEM (no pywin32 service wrapper needed).
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

_WINDOWS_TASK_NAME = "SIEM Agent"
_LINUX_UNIT_PATH = Path("/etc/systemd/system/siem-agent.service")


class ServiceError(Exception):
    """Raised when service install/uninstall fails."""


def _is_windows() -> bool:
    return os.name == "nt"


def _is_root() -> bool:
    """True when running with privileges to install system units (POSIX)."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _run(cmd: list[str]) -> None:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(cmd, capture_output=True, text=True, creationflags=creationflags)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise ServiceError(f"{' '.join(cmd[:2])} failed (rc={proc.returncode}): {detail}")


def _agent_command(config_path: Optional[str]) -> str:
    exe = sys.executable
    if _is_windows():
        parts = [f'"{exe}"', "-m", "siem_agent", "run"]
        if config_path:
            parts.append(f'--config "{config_path}"')
        return " ".join(parts)
    parts = [shlex.quote(exe), "-m", "siem_agent", "run"]
    if config_path:
        parts += ["--config", shlex.quote(config_path)]
    return " ".join(parts)


def install(config_path: Optional[str] = None) -> str:
    """Install the agent to start at boot. Returns a human status message."""
    if _is_windows():
        _run(
            [
                "schtasks",
                "/Create",
                "/TN",
                _WINDOWS_TASK_NAME,
                "/TR",
                _agent_command(config_path),
                "/SC",
                "ONSTART",
                "/RU",
                "SYSTEM",
                "/RL",
                "HIGHEST",
                "/F",
            ]
        )
        return (
            f"Scheduled task '{_WINDOWS_TASK_NAME}' created (runs at boot as "
            f"SYSTEM). Start it now with:\n"
            f'  schtasks /Run /TN "{_WINDOWS_TASK_NAME}"'
        )
    return _install_systemd(config_path)


def uninstall() -> str:
    if _is_windows():
        proc = subprocess.run(
            ["schtasks", "/Delete", "/TN", _WINDOWS_TASK_NAME, "/F"],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0 and "cannot find" not in (proc.stdout + proc.stderr).lower():
            raise ServiceError((proc.stderr or proc.stdout or "delete failed").strip())
        return f"Scheduled task '{_WINDOWS_TASK_NAME}' removed."
    return _uninstall_systemd()


def _install_systemd(config_path: Optional[str]) -> str:
    unit = (
        "[Unit]\n"
        "Description=SIEM log shipper (siem-agent)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_agent_command(config_path)}\n"
        "Restart=always\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    if _is_root():
        _LINUX_UNIT_PATH.write_text(unit, encoding="utf-8")
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "siem-agent.service"])
        return "systemd unit installed and enabled. Start it with:\n" "  systemctl start siem-agent"
    local = Path("siem-agent.service")
    local.write_text(unit, encoding="utf-8")
    return (
        f"Not root: wrote {local.resolve()} - install it with:\n"
        f"  sudo cp {local} {_LINUX_UNIT_PATH}\n"
        f"  sudo systemctl daemon-reload\n"
        f"  sudo systemctl enable --now siem-agent"
    )


def _uninstall_systemd() -> str:
    if _is_root() and _LINUX_UNIT_PATH.exists():
        _run(["systemctl", "disable", "--now", "siem-agent.service"])
        _LINUX_UNIT_PATH.unlink()
        _run(["systemctl", "daemon-reload"])
        return "systemd unit removed."
    return (
        f"Not root or unit missing - remove manually:\n"
        f"  sudo systemctl disable --now siem-agent\n"
        f"  sudo rm {_LINUX_UNIT_PATH}"
    )
