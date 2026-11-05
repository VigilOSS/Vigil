"""A reaped pooled keep-alive socket must get one fresh-connection re-send.

Regression for the `code-index sync` broken-pipe failure: writes use
``max_retries=1``, so before this fix a server-reaped idle socket surfaced as an
unretried ``[Errno 32] Broken pipe`` and took the whole sync down.
"""
from __future__ import annotations

import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from assess.lib.client import AssessError, AssessmentClient, AssessTransportError


def _response(status: int, body: bytes = b'{"ok": true}'):
    class _Resp:
        def __init__(self) -> None:
            self.status = status

        def read(self) -> bytes:
            return body

    return _Resp()


class _Conn:
    """One scripted connection: either raise on request() or return a response."""

    sock = Mock()

    def __init__(self, outcome):
        self._outcome = outcome  # ("raise", exc) | ("respond", status)

    def request(self, *args, **kwargs):
        if self._outcome[0] == "raise":
            raise self._outcome[1]

    def getresponse(self):
        return _response(self._outcome[1])

    def close(self):
        pass


def _client(monkeypatch, outcomes, *, warm):
    """Hand out one scripted connection per send; ``warm`` pre-pools the first."""
    client = AssessmentClient("http://localhost:8000", "eng")
    made: list[_Conn] = []
    pending = list(outcomes)

    def _get_conn(_timeout: float = 2.0):
        if client._conn is None:
            client._conn = _Conn(pending.pop(0))
            made.append(client._conn)
        return client._conn

    monkeypatch.setattr(client, "_get_conn", _get_conn)
    monkeypatch.setattr("assess.lib.client.time.sleep", lambda _s: None)
    if warm:
        client._conn = _Conn(pending.pop(0))
        made.append(client._conn)
    return client, made


def test_reused_socket_broken_pipe_is_resent_on_a_fresh_connection(monkeypatch):
    client, made = _client(
        monkeypatch,
        [("raise", BrokenPipeError()), ("respond", 200)],
        warm=True,
    )
    status, _body = client._request_raw("POST", "/x", body=b"{}", max_retries=1)
    assert status == 200
    assert len(made) == 2  # one free re-send on a fresh connection


def test_reused_remote_disconnected_is_resent(monkeypatch):
    client, made = _client(
        monkeypatch,
        [("raise", http.client.RemoteDisconnected()), ("respond", 200)],
        warm=True,
    )
    status, _body = client._request_raw("POST", "/x", body=b"{}", max_retries=1)
    assert status == 200
    assert len(made) == 2


def test_free_resend_is_bounded_to_one(monkeypatch):
    client, made = _client(
        monkeypatch,
        [("raise", BrokenPipeError()), ("raise", BrokenPipeError())],
        warm=True,
    )
    with pytest.raises(AssessError, match="Failed after 1 attempts"):
        client._request_raw("POST", "/x", body=b"{}", max_retries=1)
    assert len(made) == 2  # warmed drop + one fresh re-send, then give up


def test_read_timeout_on_a_write_is_never_resent(monkeypatch):
    # TimeoutError means the server may have committed but is slow — the exact
    # case the stale-retry must exclude so a write is not double-applied.
    client, made = _client(
        monkeypatch,
        [("raise", TimeoutError())],
        warm=True,
    )
    with pytest.raises(AssessError, match="Failed after 1 attempts"):
        client._request_raw("POST", "/x", body=b"{}", max_retries=1)
    assert len(made) == 1  # no fresh re-send


def test_fresh_connect_failure_is_not_treated_as_stale(monkeypatch):
    # A drop on a connection this call opened (not reused) takes the normal
    # retry path, so with max_retries=3 a persistent BrokenPipe sends 4 times.
    client, made = _client(
        monkeypatch,
        [("raise", BrokenPipeError())] * 4,
        warm=False,
    )
    with pytest.raises(AssessError, match="Failed after 3 attempts"):
        client._request_raw("GET", "/x", max_retries=3)
    assert len(made) == 3


def test_a_sent_request_stays_sent_when_a_retry_cannot_connect(monkeypatch):
    client = AssessmentClient("http://localhost:8000", "eng")
    sent = _Conn(("respond", 200))
    monkeypatch.setattr(sent, "getresponse", Mock(side_effect=TimeoutError()))
    monkeypatch.setattr(client, "_get_conn", Mock(side_effect=[sent, ConnectionRefusedError()]))
    monkeypatch.setattr("assess.lib.client.time.sleep", lambda _s: None)

    with pytest.raises(AssessTransportError, match="Failed after 2 attempts") as raised:
        client._request_raw("POST", "/x", body=b"{}", max_retries=2)
    assert raised.value.request_sent


def test_connect_and_read_each_get_their_own_timeout(monkeypatch):
    opened: list[float] = []
    create_connection = socket.create_connection

    def record(address, timeout, *args):
        opened.append(timeout)
        return create_connection(address, timeout, *args)

    monkeypatch.setattr(socket, "create_connection", record)

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/slow":
                time.sleep(0.6)
            self.send_response(200)
            self.send_header("Content-Length", "11")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with AssessmentClient(f"http://127.0.0.1:{server.server_address[1]}", "eng") as client:
            client._request_raw("POST", "/fast", body=b"{}", read_timeout=0.3, max_retries=1)
            pooled = client._conn
            status, _body = client._request_raw(
                "POST", "/slow", body=b"{}", read_timeout=5.0, max_retries=1
            )
            assert status == 200
            assert client._conn is pooled
            assert opened == [2.0]
    finally:
        server.shutdown()
        server.server_close()
