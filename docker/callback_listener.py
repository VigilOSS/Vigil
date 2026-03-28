#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CallbackHandler(BaseHTTPRequestHandler):
    server_version = "security-research-callback/1.0"

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _handle(self) -> None:
        body = self._read_body()
        sys.stdout.write(
            f"\n=== callback ===\n"
            f"method={self.command}\n"
            f"path={self.path}\n"
            f"client={self.client_address[0]}:{self.client_address[1]}\n"
            f"headers={dict(self.headers)}\n"
            f"body={body.decode('utf-8', errors='replace')}\n"
        )
        sys.stdout.flush()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"callback received\n")

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple callback capture server for exploit validation")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), CallbackHandler)
    print(f"[callback] listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
