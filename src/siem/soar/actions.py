"""Action helpers for SOAR-Lite command and email responses."""
from __future__ import annotations

import os
import re
import shlex
import smtplib
import subprocess
from email.message import EmailMessage
from typing import Any, Optional

from siem.core.config import Config

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_template(value: str, context: dict[str, str]) -> str:
    """Replace known ``{placeholders}`` and leave unknown ones untouched."""

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return context.get(key, match.group(0))

    return _PLACEHOLDER_RE.sub(_replace, value)


def missing_requirements(required: tuple[str, ...], context: dict[str, str]) -> Optional[str]:
    for field in required:
        if not str(context.get(field, "")).strip():
            return field
    return None


def render_command(command: Any, context: dict[str, str]) -> str | list[str]:
    """Render a command string or list into an argv value."""
    if isinstance(command, (list, tuple)):
        return [render_template(str(item), context) for item in command]
    return render_template(str(command), context)


def command_argv(command: Any, context: dict[str, str], shell: bool) -> str | list[str]:
    rendered = render_command(command, context)
    if isinstance(rendered, list):
        return rendered
    if shell:
        return rendered
    return shlex.split(rendered, posix=os.name != "nt")


def default_command_runner(
    argv: str | list[str],
    timeout: float,
    cwd: Optional[str],
    shell: bool,
) -> tuple[int, str, str]:
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        shell=shell,
        check=False,
    )
    return result.returncode, result.stdout or "", result.stderr or ""


def build_email(
    action,
    context: dict[str, str],
    config: Config,
) -> EmailMessage:
    recipients = [render_template(item, context) for item in action.to]
    cc = [render_template(item, context) for item in action.cc]
    subject = render_template(
        action.subject or "[SIEM][SOAR] {severity} incident {incident_id}", context
    )
    body = render_template(action.body or _default_body(), context)

    from_address = (
        render_template(action.from_address, context)
        if action.from_address
        else str(
            config.get("alerting.email.from_address")
            or config.get("alerting.email.username")
            or "siem@localhost"
        )
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    if cc:
        message["Cc"] = ", ".join(cc)
    message.set_content(body)
    return message


def default_email_sender(message: EmailMessage, config: Config) -> None:
    host = str(config.get("alerting.email.smtp_host", "localhost"))
    port = int(config.get("alerting.email.smtp_port", 587))
    use_tls = bool(config.get("alerting.email.use_tls", True))
    username = str(config.get("alerting.email.username") or "")
    password = str(config.get("alerting.email.password") or "")

    with smtplib.SMTP(host, port, timeout=15) as server:
        if use_tls:
            server.starttls()
        if username:
            server.login(username, password)
        server.send_message(message)


def _default_body() -> str:
    return (
        "SIEM SOAR-Lite triggered playbook {playbook_id}.\n\n"
        "Incident  : {incident_id}\n"
        "Title     : {title}\n"
        "Severity  : {severity}\n"
        "Source IP : {src_ip}\n"
        "User      : {user_name}\n"
        "Alerts    : {alert_count}\n"
        "Rules     : {rule_names}\n"
        "Categories: {categories}\n"
        "Last seen : {last_seen}\n\n"
        "Review the incident in the SIEM dashboard.\n"
    )
