"""Integration tests for the syslog server (live UDP + TCP)."""
import socket

from helpers import wait_for

from siem.ingestion.queue_manager import LogQueue
from siem.ingestion.syslog_server import SyslogServer


def _wait_for_socket(server, attr, timeout=5.0):
    assert wait_for(lambda: getattr(server, attr) is not None, timeout=timeout), \
        f"{attr} did not bind in time"
    return getattr(server, attr).getsockname()[1]


def test_udp_ingestion():
    q = LogQueue()
    server = SyslogServer(q, host="127.0.0.1", udp_port=0, tcp_port=0,
                          enable_udp=True, enable_tcp=False)
    server.start()
    try:
        port = _wait_for_socket(server, "_udp_sock")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<134>Oct 16 14:32:11 host sshd[123]: failed login", ("127.0.0.1", port))
        sock.close()

        assert wait_for(lambda: q.size >= 1)
        rec = q.get(timeout=1)
        assert rec.transport == "udp"
        assert "failed login" in rec.raw
        assert rec.peer.startswith("127.0.0.1:")
    finally:
        server.stop()


def test_tcp_ingestion_multiple_lines():
    q = LogQueue()
    server = SyslogServer(q, host="127.0.0.1", udp_port=0, tcp_port=0,
                          enable_udp=False, enable_tcp=True)
    server.start()
    try:
        port = _wait_for_socket(server, "_tcp_sock")
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(b"line-one\nline-two\n")
        assert wait_for(lambda: q.size >= 2)
        lines = {q.get(timeout=1).raw for _ in range(2)}
        assert lines == {"line-one", "line-two"}
        sock.close()
    finally:
        server.stop()
