"""siem-agent command line interface (argparse, mirrors the server CLI style)."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
import urllib.error
import urllib.request

from siem_agent import __version__
from siem_agent.config import AgentConfig, AgentConfigError, load_agent_config

log = logging.getLogger("siem_agent")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _load_config_or_die(args: argparse.Namespace) -> AgentConfig:
    try:
        return load_agent_config(getattr(args, "config", None))
    except AgentConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        raise SystemExit(2) from e


# -- commands --------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    config = _load_config_or_die(args)

    from siem_agent.runner import AgentRunner

    runner = AgentRunner(config)

    def _handle_signal(signum, frame):  # noqa: ARG001
        log.info("Received signal %s; shutting down", signum)
        runner.stop()

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, _handle_signal)
            except (ValueError, OSError):
                pass

    runner.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()
    return 0


def _cmd_test_connection(args: argparse.Namespace) -> int:
    config = _load_config_or_die(args)
    ok = True

    # 1) health probe
    try:
        req = urllib.request.Request(config.health_url, method="GET")
        with urllib.request.urlopen(req, timeout=config.request_timeout) as resp:
            print(f"[OK]  {config.health_url} -> HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        print(
            f"[WARN] {config.health_url} -> HTTP {e.code} "
            f"(server reachable; health endpoint may require auth)"
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"[FAIL] {config.health_url} -> {e}")
        ok = False

    # 2) ingest probe with one test record
    body = json.dumps(
        {
            "records": [
                {
                    "raw": json.dumps({"message": "siem-agent test-connection", "severity": "low"}),
                    "source_id": "agent-test",
                    "source_type": "custom",
                    "format_hint": "json",
                }
            ]
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        config.ingest_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.token}",
            "User-Agent": f"siem-agent/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=config.request_timeout) as resp:
            print(
                f"[OK]  {config.ingest_url} -> HTTP {resp.status} "
                f"(token accepted, ingest works)"
            )
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        print(f"[FAIL] {config.ingest_url} -> HTTP {e.code} {detail}")
        if e.code == 401:
            print("      Hint: server.token does not match SIEM_INGEST_TOKENS " "on the server.")
        ok = False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"[FAIL] {config.ingest_url} -> {e}")
        ok = False

    return 0 if ok else 1


def _cmd_install(args: argparse.Namespace) -> int:
    _load_config_or_die(args)  # validate before touching the boot config
    from siem_agent import service

    try:
        message = service.install(config_path=args.config)
    except service.ServiceError as e:
        print(f"Install failed: {e}", file=sys.stderr)
        return 1
    print(message)
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    from siem_agent import service

    try:
        print(service.uninstall())
    except service.ServiceError as e:
        print(f"Uninstall failed: {e}", file=sys.stderr)
        return 1
    return 0


# -- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem-agent",
        description="Lightweight log shipper for the SIEM platform",
    )
    parser.add_argument("--version", action="version", version=f"siem-agent {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run the agent (foreground)")
    p_run.add_argument("--config", help="path to agent.yaml / agent.json")
    p_run.set_defaults(func=_cmd_run)

    p_test = sub.add_parser("test-connection", help="probe the server health + ingest endpoints")
    p_test.add_argument("--config", help="path to agent.yaml / agent.json")
    p_test.set_defaults(func=_cmd_test_connection)

    p_install = sub.add_parser(
        "install", help="install to start at boot " "(Windows task / systemd unit)"
    )
    p_install.add_argument("--config", help="path to agent.yaml / agent.json")
    p_install.set_defaults(func=_cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="remove the boot service")
    p_uninstall.set_defaults(func=_cmd_uninstall)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
