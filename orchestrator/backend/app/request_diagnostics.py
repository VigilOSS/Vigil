"""Capture long-request thread evidence without depending on the event loop."""
from __future__ import annotations

import faulthandler
import logging
import math
import os
import sys
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class _PendingRequest:
    method: str
    path: str
    started: float
    reported: bool = False


class RequestDiagnostics:
    def __init__(self) -> None:
        self._pending: dict[object, _PendingRequest] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        raw = os.environ.get("VIGIL_SLOW_REQUEST_SECONDS", "30")
        try:
            threshold = float(raw)
            if not math.isfinite(threshold) or threshold < 0:
                raise ValueError
        except ValueError:
            logger.warning("Invalid VIGIL_SLOW_REQUEST_SECONDS=%r; using 30 seconds", raw)
            threshold = 30.0
        if threshold == 0 or self._thread is not None:
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._watch, args=(self._stop, threshold),
            name="vigil-request-diagnostics", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None
        with self._lock:
            self._pending.clear()

    def begin(self, method: str, path: str) -> object:
        token = object()
        with self._lock:
            self._pending[token] = _PendingRequest(method, path, time.monotonic())
        return token

    def finish(self, token: object) -> None:
        with self._lock:
            self._pending.pop(token, None)

    def _watch(self, stop: threading.Event, threshold: float) -> None:
        while not stop.wait(min(1.0, threshold / 2)):
            now = time.monotonic()
            with self._lock:
                stalled = [request for request in self._pending.values()
                           if not request.reported and now - request.started >= threshold]
                for request in stalled:
                    request.reported = True
            if not stalled:
                continue
            # Dump before logging: a blocked logging handler must not prevent
            # the independent thread from capturing the process's wait state.
            try:
                faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
            except (OSError, ValueError, RuntimeError):
                logger.exception("Could not capture slow-request thread stacks")
            for request in stalled:
                logger.warning("HTTP request still active after %.1fs: %s %r",
                               now - request.started, request.method, request.path)


class RequestDiagnosticsMiddleware:
    def __init__(self, app, diagnostics: RequestDiagnostics) -> None:
        self.app = app
        self.diagnostics = diagnostics

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        token = self.diagnostics.begin(scope["method"], scope["path"])
        try:
            await self.app(scope, receive, send)
        finally:
            self.diagnostics.finish(token)
