"""Tests for the waitress background server used by the desktop shell."""
from __future__ import annotations

import socket

import pytest

from siem.web.app import find_free_port


def test_find_free_port_is_bindable():
    port = find_free_port("127.0.0.1")
    assert 0 < port < 65536
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))


def test_start_server_thread_serves_and_stops():
    pytest.importorskip("waitress")
    from flask import Flask

    from siem.desktop import server as server_mod

    app = Flask(__name__)

    @app.get("/login")
    def login():
        return "ok"

    handle = server_mod.start(app, threads=2)
    try:
        assert handle.url.startswith("http://127.0.0.1:")
        assert server_mod.wait_until_ready(handle.url, timeout=10)
    finally:
        handle.stop()

    assert not handle.thread.is_alive()
