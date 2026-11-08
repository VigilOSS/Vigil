"""A lost response cannot establish that a mutation was not committed."""
from __future__ import annotations

import http.client
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from assess.lib.client import AssessTransportError
from test_client_stale_keepalive_retry import _client


def test_closed_idle_connection_is_replaced_before_a_mutation_is_sent():
    from assess.lib.client import AssessmentClient
    writes = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            self.wfile.flush()
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
        def do_POST(self):
            writes.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", "8")
            self.end_headers()
            self.wfile.write(b'{"id":1}')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        with AssessmentClient(f"http://127.0.0.1:{server.server_port}", "acme") as client:
            client.get("warm")
            assert select.select([client._conn.sock], [], [], 2)[0]
            assert client.post("writes", {"observation": "Acme"}) == {"id": 1}
        assert len(writes) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_committed_post_with_lost_response_reaches_server_only_once():
    from assess.lib.client import AssessmentClient
    writes = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
        def do_POST(self):
            writes.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        with AssessmentClient(f"http://127.0.0.1:{server.server_port}", "acme") as client:
            client.get("warm")
            with pytest.raises(AssessTransportError) as result:
                client.post("writes", {"observation": "Acme"})
            assert result.value.request_sent
        assert len(writes) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("stage", ["send", "response"])
def test_mutation_disconnect_is_uncertain_and_never_replayed(monkeypatch, method, stage):
    client, made = _client(
        monkeypatch, [("respond", 200), ("respond", 200)], warm=True
    )
    def lost(*args, **kwargs):
        raise http.client.RemoteDisconnected("response lost after possible commit")
    monkeypatch.setattr(made[0], "request" if stage == "send" else "getresponse", lost)
    with pytest.raises(AssessTransportError) as result:
        client._request_raw(method, "/acme", body=b"{}", max_retries=3)
    assert result.value.request_sent
    assert "Failed after 1 attempts" in str(result.value)
    assert len(made) == 1
    assert "uncertain" in str(result.value).lower()


def test_mutation_retryable_status_is_not_automatically_replayed(monkeypatch):
    from assess.lib.client import AssessError
    client, made = _client(monkeypatch, [("respond", 503), ("respond", 200)], warm=True)
    with pytest.raises(AssessError, match="HTTP 503"):
        client._request_raw("POST", "/acme", body=b"{}", max_retries=3)
    assert len(made) == 1
