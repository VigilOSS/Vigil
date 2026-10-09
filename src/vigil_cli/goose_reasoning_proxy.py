#!/usr/bin/env python3
"""Reasoning-content repair proxy for Goose + direct DeepSeek thinking models.

Stopgap for aaif-goose#9397. Goose v1.38.0's ``openai``-compatible provider, when
driving a DeepSeek **thinking** model (``deepseek-v4-pro`` / ``-flash``) on the
direct API (``https://api.deepseek.com``), 400s mid-run with::

    The reasoning_content in the thinking mode must be passed back to the API.

Root cause (proven at the wire level): when the model emits **multiple tool calls
in one assistant turn**, Goose serialises that single turn back to the API as N
*separate* assistant messages — one per tool call — but attaches the turn's
``reasoning_content`` to only the FIRST of them. DeepSeek's thinking mode requires
every assistant message it produced to carry its ``reasoning_content`` verbatim,
so messages 2..N (which Goose left without it) are rejected with the 400 above.

We can NOT fix this with ``parallel_tool_calls: false`` — DeepSeek's V4 thinking
model ignores that request flag and emits parallel tool calls anyway (verified).
So this proxy fixes the message stream directly: it sits between Goose and
DeepSeek and, for every ``/chat/completions`` request, re-attaches a
``reasoning_content`` to each assistant message that has ``tool_calls`` but is
missing/blank ``reasoning_content``. Everything else (including the streaming SSE
response) is passed through byte-for-byte.

Dependency-free (stdlib only) so the engagement launcher can run it with the
system ``python3``. Streaming-aware: Goose sends ``stream: true`` and the SSE
response is relayed incrementally as it arrives.

Run::

    UPSTREAM_HOST=https://api.deepseek.com PROXY_PORT=0 \
      python3 -m vigil_cli.goose_reasoning_proxy

With ``PROXY_PORT=0`` (recommended) the kernel picks a free port; the chosen
``host:port`` is printed to stdout as ``LISTENING http://127.0.0.1:<port>`` so a
launcher can capture it. The process serves until killed (SIGTERM/SIGINT).
"""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# DeepSeek requires a NON-EMPTY reasoning_content on every thinking-mode assistant
# message. A single space is the minimal accepted placeholder for the assistant
# tool-call messages whose reasoning Goose dropped (verified: the API accepts it
# and the run continues with thinking still active on subsequent turns).
DEFAULT_REPAIR_VALUE = " "
# Cap on how long we wait for the upstream response to begin/stream. DeepSeek
# thinking responses can take a while; keep this generous.
UPSTREAM_TIMEOUT = float(os.environ.get("PROXY_UPSTREAM_TIMEOUT", "300"))


def repair_messages(body: object, repair_value: str) -> int:
    """Re-attach reasoning_content to assistant tool-call messages missing it.

    Mutates ``body`` in place. Returns the number of messages repaired so the
    caller can log/inspect. Only assistant messages that carry ``tool_calls`` and
    have a falsy ``reasoning_content`` are touched; nothing else is modified.
    """
    if not isinstance(body, dict):
        return 0
    n_fixed = 0
    for msg in body.get("messages", []) or []:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") != "assistant":
            continue
        if not msg.get("tool_calls"):
            continue
        if not msg.get("reasoning_content"):
            msg["reasoning_content"] = repair_value
            n_fixed += 1
    return n_fixed


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so we can use chunked transfer for the streamed SSE relay.
    protocol_version = "HTTP/1.1"

    # Injected by the server factory.
    upstream: str = "https://api.deepseek.com"
    repair_value: str = DEFAULT_REPAIR_VALUE
    debug: bool = False

    def log_message(self, *args):  # noqa: D401 - silence default stderr access log
        return

    def _dbg(self, msg: str) -> None:
        if self.debug:
            sys.stderr.write(f"[goose-reasoning-proxy] {msg}\n")
            sys.stderr.flush()

    def _relay(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        path = self.path
        forward_body = raw

        # Only chat/completions bodies need repair; pass everything else through.
        if path.endswith("/chat/completions") and raw:
            try:
                body = json.loads(raw)
                n_fixed = repair_messages(body, self.repair_value)
                if n_fixed:
                    forward_body = json.dumps(body).encode("utf-8")
                    self._dbg(f"repaired {n_fixed} assistant tool-call message(s)")
            except (ValueError, TypeError) as exc:
                # Malformed body — forward verbatim rather than dropping the run.
                self._dbg(f"body parse failed ({exc}); forwarding unchanged")
                forward_body = raw

        # Rebuild upstream headers: drop hop-by-hop and length/host (recomputed).
        up_headers: dict[str, str] = {}
        for key, value in self.headers.items():
            kl = key.lower()
            if kl in ("host", "content-length", "connection", "accept-encoding",
                      "transfer-encoding", "keep-alive", "proxy-connection"):
                continue
            up_headers[key] = value
        # Identity encoding so we relay the SSE stream untransformed.
        up_headers["Accept-Encoding"] = "identity"

        url = self.upstream.rstrip("/") + path
        req = urllib.request.Request(url, data=forward_body, headers=up_headers,
                                     method=self.command)
        try:
            resp = urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT)  # noqa: S310 - fixed upstream
        except urllib.error.HTTPError as exc:
            # Upstream returned a non-2xx (e.g. a 400). Relay status + body so
            # Goose sees the real error exactly as if it had spoken directly.
            err_body = exc.read()
            self.send_response(exc.code)
            for key, value in (exc.headers.items() if exc.headers else []):
                if key.lower() in ("content-length", "transfer-encoding", "connection",
                                   "content-encoding"):
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
            self._dbg(f"upstream HTTPError {exc.code} relayed")
            return
        except (urllib.error.URLError, OSError) as exc:
            self.send_error(502, f"upstream error: {exc}")
            self._dbg(f"upstream URLError: {exc}")
            return

        # Relay the (possibly streaming) response with chunked transfer so SSE
        # frames reach Goose as they arrive.
        self.send_response(resp.status)
        for key, value in resp.headers.items():
            if key.lower() in ("content-length", "transfer-encoding", "connection",
                               "content-encoding", "keep-alive"):
                continue
            self.send_header(key, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError) as exc:
            self._dbg(f"client disconnected mid-stream: {exc}")
        finally:
            resp.close()

    do_POST = _relay
    do_GET = _relay


def _watch_parent(initial_ppid: int, server: ThreadingHTTPServer, debug: bool) -> None:
    """Self-terminate when the launcher that started us goes away.

    The engagement launcher ``exec``s ``goose`` (replacing its own shell), so an
    EXIT trap there cannot reliably reap us. Instead we poll our parent PID: when
    it changes (re-parented to init/launchd because the original parent died) we
    shut the server down so the proxy never outlives the run it serves. This
    watchdog covers a clean ``goose`` exit and the interactive
    ``vigil engagement start`` path.
    """
    while True:
        time.sleep(2.0)
        try:
            if os.getppid() != initial_ppid:
                if debug:
                    sys.stderr.write("[goose-reasoning-proxy] parent exited; shutting down\n")
                    sys.stderr.flush()
                server.shutdown()
                return
        except OSError:
            server.shutdown()
            return


def make_server(upstream: str, port: int, repair_value: str, debug: bool) -> ThreadingHTTPServer:
    handler = type("_BoundHandler", (_Handler,), {
        "upstream": upstream,
        "repair_value": repair_value,
        "debug": debug,
    })
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


def main() -> int:
    upstream = os.environ.get("UPSTREAM_HOST", "https://api.deepseek.com")
    port = int(os.environ.get("PROXY_PORT", "0"))
    repair_value = os.environ.get("PROXY_REPAIR_VALUE", DEFAULT_REPAIR_VALUE)
    debug = os.environ.get("PROXY_DEBUG", "") not in ("", "0", "false", "False")

    server = make_server(upstream, port, repair_value, debug)
    actual_port = server.server_address[1]
    # Single, parse-friendly line so a launcher can capture the chosen port.
    print(f"LISTENING http://127.0.0.1:{actual_port}", flush=True)
    if debug:
        sys.stderr.write(f"[goose-reasoning-proxy] upstream={upstream} port={actual_port}\n")
        sys.stderr.flush()
    # Self-cleanup watchdog: exit when the launcher that started us goes away.
    watcher = threading.Thread(
        target=_watch_parent, args=(os.getppid(), server, debug), daemon=True
    )
    watcher.start()
    # When the launcher tells us where its capture file is (PROXY_ANNOUNCE_FILE),
    # remove it ourselves on shutdown. The launcher ``exec``s goose, so its own
    # EXIT trap is lost — having the proxy reap the file keeps temp dirs clean.
    announce_file = os.environ.get("PROXY_ANNOUNCE_FILE", "")

    def _cleanup() -> None:
        try:
            server.server_close()
        except OSError:
            pass
        if announce_file:
            try:
                os.unlink(announce_file)
            except OSError:
                pass

    # Process-group supervisors use SIGTERM on timeout/early completion; reap
    # the announce file on that path too (not just the clean exit).
    def _on_signal(_signum, _frame):
        _cleanup()
        raise SystemExit(0)

    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError):
            pass  # not on the main thread / unsupported platform — fall back to finally

    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
