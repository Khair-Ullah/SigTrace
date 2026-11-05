"""Syslog ingestion over UDP and TCP (RFC 3164 / RFC 5424, FR-01..FR-03).

Transport-level only: this module receives raw syslog messages and enqueues
them. Full RFC parsing happens in the parsing layer.
"""
from __future__ import annotations

import socket
import threading
from typing import Optional

from siem.core.logger import get_logger
from siem.ingestion.base import BaseIngestor, RawLogRecord
from siem.ingestion.queue_manager import LogQueue

log = get_logger("ingestion.syslog")

MAX_UDP_DATAGRAM = 65535
SOCKET_TIMEOUT = 0.5


class SyslogServer(BaseIngestor):
    """Listen for syslog messages on UDP and/or TCP."""

    def __init__(
        self,
        queue: LogQueue,
        host: str = "0.0.0.0",
        udp_port: int = 514,
        tcp_port: int = 514,
        source_id: str = "syslog",
        source_type: str = "syslog",
        enable_udp: bool = True,
        enable_tcp: bool = True,
    ):
        super().__init__(queue, name="SyslogServer")
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.source_id = source_id
        self.source_type = source_type
        self.enable_udp = enable_udp
        self.enable_tcp = enable_tcp

        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp_sock: Optional[socket.socket] = None
        self._tcp_sock: Optional[socket.socket] = None
        self._tcp_clients: list[socket.socket] = []
        self._clients_lock = threading.Lock()

        self.stats = {"udp_messages": 0, "tcp_messages": 0, "bytes": 0, "errors": 0}

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        if self.enable_udp:
            t = threading.Thread(target=self._udp_loop, name="syslog-udp", daemon=True)
            t.start()
            self._threads.append(t)

        if self.enable_tcp:
            t = threading.Thread(target=self._tcp_loop, name="syslog-tcp", daemon=True)
            t.start()
            self._threads.append(t)

        log.info("Syslog server started (udp=%s:%s, tcp=%s:%s)",
                 self.host, self.udp_port if self.enable_udp else "-",
                 self.host, self.tcp_port if self.enable_tcp else "-")

    def stop(self, timeout: float = 5.0) -> None:
        if not self._running:
            return
        self._stop_event.set()

        # Close listening sockets to unblock recv/accept
        for sock in (self._udp_sock, self._tcp_sock):
            self._close_socket(sock)
        with self._clients_lock:
            for c in list(self._tcp_clients):
                self._close_socket(c)
            self._tcp_clients.clear()

        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        self._running = False
        log.info("Syslog server stopped (stats=%s)", self.stats)

    # -- UDP --------------------------------------------------------------
    def _udp_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.bind((self.host, self.udp_port))
            self._udp_sock = sock
        except OSError as e:
            log.error("Failed to bind UDP %s:%s -> %s", self.host, self.udp_port, e)
            self.stats["errors"] += 1
            return

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(MAX_UDP_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed during shutdown

            self.stats["bytes"] += len(data)
            text = data.decode("utf-8", errors="replace")
            peer = f"{addr[0]}:{addr[1]}"
            for line in text.splitlines():
                if line.strip():
                    self._emit(line, "udp", peer)
                    self.stats["udp_messages"] += 1

    # -- TCP --------------------------------------------------------------
    def _tcp_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.bind((self.host, self.tcp_port))
            sock.listen(50)
            self._tcp_sock = sock
        except OSError as e:
            log.error("Failed to bind TCP %s:%s -> %s", self.host, self.tcp_port, e)
            self.stats["errors"] += 1
            return

        while not self._stop_event.is_set():
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed during shutdown

            with self._clients_lock:
                self._tcp_clients.append(client)
            t = threading.Thread(
                target=self._tcp_client_loop,
                args=(client, addr),
                name=f"syslog-tcp-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            t.start()

    def _tcp_client_loop(self, client: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        client.settimeout(SOCKET_TIMEOUT)
        buffer = b""
        try:
            while not self._stop_event.is_set():
                try:
                    data = client.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break  # client closed
                self.stats["bytes"] += len(data)
                buffer += data
                # Non-transparent framing: newline-delimited messages
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle_tcp_line(line, peer)
            # Flush any trailing data without newline
            if buffer.strip():
                self._handle_tcp_line(buffer, peer)
        finally:
            self._close_socket(client)
            with self._clients_lock:
                if client in self._tcp_clients:
                    self._tcp_clients.remove(client)

    def _handle_tcp_line(self, line: bytes, peer: str) -> None:
        text = line.decode("utf-8", errors="replace").rstrip("\r")
        if text.strip():
            # TCP has flow control: block briefly instead of dropping when
            # the queue is saturated (backpressure to the sender).
            self._emit(text, "tcp", peer, block=True)
            self.stats["tcp_messages"] += 1

    # -- helpers ----------------------------------------------------------
    def _emit(self, raw: str, transport: str, peer: str, block: bool = False) -> None:
        record = RawLogRecord(
            raw=raw,
            source_id=self.source_id,
            source_type=self.source_type,
            transport=transport,
            peer=peer,
        )
        if block:
            self.queue.put_blocking(record, timeout=2.0)
        else:
            self.emit(record)

    @staticmethod
    def _close_socket(sock: Optional[socket.socket]) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass
