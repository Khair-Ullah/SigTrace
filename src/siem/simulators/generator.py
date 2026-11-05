"""Realistic log-traffic simulator (Phase 9, FR-57).

Generates synthetic raw log lines for demos, training and performance tests.
The output is deliberately emitted in the *raw* formats the parsers expect
(firewall, sshd, web access logs) so it can be fed through the full pipeline
exactly like real traffic.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from siem.core.utils import utcnow

# Scenario name -> method name on LogSimulator
SCENARIOS: dict[str, str] = {
    "normal": "_normal",
    "port_scan": "_port_scan",
    "ssh_bruteforce": "_ssh_bruteforce",
    "ssh_root_login": "_ssh_root_login",
    "web_exploit": "_web_exploit",
    "directory_scan": "_directory_scan",
    "admin_access": "_admin_access",
    "suspicious_outbound": "_suspicious_outbound",
    "ddos_flood": "_ddos_flood",
    "multi_stage": "_multi_stage",
}

DEFAULT_ATTACKER = "203.0.113.9"
DEFAULT_VICTIM = "10.0.0.5"


@dataclass
class SimulatedLog:
    """A single synthetic log line with its originating source metadata."""

    raw: str
    source_id: str = "simulator"
    source_type: str = "custom"
    timestamp: Optional[datetime] = None


class LogSimulator:
    """Deterministic (optionally seeded) generator of synthetic log traffic."""

    def __init__(self, seed: Optional[int] = None):
        self._rand = random.Random(seed)

    # -- public API -------------------------------------------------------
    @staticmethod
    def scenario_names() -> list[str]:
        return sorted(SCENARIOS)

    def generate(
        self,
        scenario: str = "multi_stage",
        count: Optional[int] = None,
        base: Optional[datetime] = None,
    ) -> list[SimulatedLog]:
        """Generate logs for a named scenario."""
        method_name = SCENARIOS.get(scenario)
        if method_name is None:
            raise ValueError(
                f"Unknown scenario {scenario!r}; choose from {self.scenario_names()}"
            )
        base = base or utcnow()
        method: Callable = getattr(self, method_name)
        logs = method(base=base) if count is None else method(base=base, count=count)
        return sorted(logs, key=lambda entry: entry.timestamp or base)

    # -- scenario implementations ----------------------------------------
    def _normal(self, base: datetime, count: int = 12, **_) -> list[SimulatedLog]:
        logs: list[SimulatedLog] = []
        users = ["alice", "bob", "carol", "dave"]
        for i in range(count):
            ts = base + timedelta(seconds=i * 3)
            src = f"198.51.100.{self._rand.randint(10, 40)}"
            user = self._rand.choice(users)
            if i % 4 == 0:
                logs.append(self._ssh(
                    f"Accepted password for {user} from {src} port "
                    f"{self._rand.randint(40000, 60000)} ssh2",
                    "srv-01", "ssh", ts,
                ))
            else:
                logs.append(self._firewall(
                    src, DEFAULT_VICTIM, 443, allowed=True, ts=ts, host="fw-01",
                ))
        return logs

    def _port_scan(
        self, base: datetime, count: int = 22,
        src: str = DEFAULT_ATTACKER, dst: str = DEFAULT_VICTIM, **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i * 0.2)
            logs.append(self._firewall(src, dst, 1 + i, allowed=False, ts=ts,
                                       host="fw-01"))
        return logs

    def _ssh_bruteforce(
        self, base: datetime, count: int = 6, src: str = DEFAULT_ATTACKER,
        user: str = "admin", start: float = 0.0, host: str = "srv-01", **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=start + i * 0.5)
            logs.append(self._ssh(
                f"Failed password for invalid user {user} from {src} port "
                f"{self._rand.randint(40000, 60000)} ssh2",
                host, "ssh", ts,
            ))
        return logs

    def _ssh_root_login(
        self, base: datetime, src: str = DEFAULT_ATTACKER, start: float = 0.0,
        host: str = "srv-01", count: int = 1, **_,
    ) -> list[SimulatedLog]:
        return [self._ssh(
            f"Accepted password for root from {src} port "
            f"{self._rand.randint(40000, 60000)} ssh2",
            host, "ssh", base + timedelta(seconds=start),
        )]

    def _web_exploit(
        self, base: datetime, src: str = DEFAULT_ATTACKER, web_host: str = "web-01",
        count: int = 4, **_,
    ) -> list[SimulatedLog]:
        paths = [
            "/index.php?id=1' OR '1'='1",
            "/../../etc/passwd",
            "/search?q=<script>alert(1)</script>",
            "/product?id=1 UNION SELECT username,password FROM users",
        ]
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i * 1.5)
            path = paths[i % len(paths)]
            logs.append(self._web(src, f"GET {path} HTTP/1.1",
                                  self._rand.choice([200, 403, 500]), ts, web_host))
        return logs

    def _directory_scan(
        self, base: datetime, src: str = DEFAULT_ATTACKER, web_host: str = "web-01",
        count: int = 20, **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i * 0.5)
            path = f"/{self._rand.choice(['old', 'backup', 'test', 'tmp', 'private'])}" \
                   f"{i}.php"
            logs.append(self._web(src, f"GET {path} HTTP/1.1", 404, ts, web_host))
        return logs

    def _admin_access(
        self, base: datetime, src: str = DEFAULT_ATTACKER, web_host: str = "web-01",
        status: int = 403, count: int = 1, **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i)
            path = self._rand.choice(["/admin", "/wp-admin/", "/phpmyadmin/index.php"])
            logs.append(self._web(src, f"GET {path} HTTP/1.1", status, ts, web_host))
        return logs

    def _suspicious_outbound(
        self, base: datetime, src: str = "10.0.0.42", dst: str = "198.51.100.66",
        port: int = 4444, count: int = 1, **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i * 2)
            logs.append(self._firewall(src, dst, port, allowed=True, ts=ts,
                                       host="fw-01"))
        return logs

    def _ddos_flood(
        self, base: datetime, count: int = 110, dst: str = DEFAULT_VICTIM, **_,
    ) -> list[SimulatedLog]:
        logs = []
        for i in range(count):
            ts = base + timedelta(seconds=i * 0.05)
            src = f"192.0.2.{self._rand.randint(1, 254)}"
            logs.append(self._firewall(src, dst, 80, allowed=False, ts=ts,
                                       host="fw-01"))
        return logs

    def _multi_stage(
        self, base: datetime, src: str = DEFAULT_ATTACKER, dst: str = DEFAULT_VICTIM,
        count: Optional[int] = None, **_,
    ) -> list[SimulatedLog]:
        """Recon -> brute force -> successful root login from one source."""
        logs: list[SimulatedLog] = []
        logs += self._port_scan(base, src=src, dst=dst)
        logs += self._ssh_bruteforce(base, src=src, user="admin", start=10.0)
        logs += self._ssh_root_login(base, src=src, start=20.0)
        return logs

    # -- line builders ----------------------------------------------------
    def _firewall(
        self, src: str, dst: str, dport: int, *, allowed: bool,
        ts: datetime, host: str = "fw-01",
    ) -> SimulatedLog:
        action = "ALLOW" if allowed else "BLOCK"
        raw = (
            f"UFW {action} IN=eth0 OUT= SRC={src} DST={dst} LEN=44 "
            f"PROTO=TCP SPT={self._rand.randint(1024, 65535)} DPT={dport} WINDOW=1024 SYN"
        )
        return SimulatedLog(raw, source_id=host, source_type="firewall",
                            timestamp=ts)

    def _ssh(self, message: str, host: str, source_type: str,
             ts: datetime) -> SimulatedLog:
        stamp = ts.strftime("%b %d %H:%M:%S")
        raw = f"{stamp} {host} sshd[{self._rand.randint(1000, 9999)}]: {message}"
        return SimulatedLog(raw, source_id=host, source_type=source_type,
                            timestamp=ts)

    def _web(self, src: str, request: str, status: int, ts: datetime,
             host: str) -> SimulatedLog:
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        size = self._rand.randint(100, 5000) if status < 400 else 0
        raw = (
            f'{src} - - [{stamp}] "{request}" {status} {size} "-" "Mozilla/5.0"'
        )
        return SimulatedLog(raw, source_id=host, source_type="web", timestamp=ts)


def generate_many(
    scenarios: list[str], seed: Optional[int] = None, base: Optional[datetime] = None
) -> list[SimulatedLog]:
    """Generate and merge logs from multiple scenarios (time-sorted)."""
    sim = LogSimulator(seed)
    base = base or utcnow()
    logs: list[SimulatedLog] = []
    for scenario in scenarios:
        logs.extend(sim.generate(scenario, base=base))
    return sorted(logs, key=lambda entry: entry.timestamp or base)
