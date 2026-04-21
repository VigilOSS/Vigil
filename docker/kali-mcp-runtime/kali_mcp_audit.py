"""Non-blocking audit POST pipeline for the patched Kali MCP server.

Every target-facing Kali tool call writes a command-run audit record to the
orchestrator backend. Previously those writes were **synchronous** inside
Flask's ``after_request`` hook — when the orchestrator was slow or down,
every tool response blocked for up to ``KALI_MCP_AUDIT_TIMEOUT`` seconds,
and a single request that produced multiple command runs paid the cost
serially (N × timeout). Under load with a down orchestrator, Flask worker
threads all ended up waiting on ``urlopen``; new requests queued; the
runtime appeared frozen to MCP clients.

This module moves the POST off the request path:

* ``enqueue(...)`` drops a payload onto a bounded ``queue.Queue`` and
  returns immediately. The tool response never waits on the audit.
* A single daemon worker thread drains the queue, posting one payload at
  a time with a short timeout.
* A circuit breaker opens after ``CIRCUIT_BREAKER_THRESHOLD`` consecutive
  POST failures and stays open for ``CIRCUIT_BREAKER_OPEN_SECONDS``. While
  open, incoming audits are dropped with a rate-limited log line instead
  of wasting the worker thread on a known-bad target.
* The queue is bounded at ``QUEUE_MAXSIZE``. When it fills (orchestrator
  down + sustained tool traffic), the oldest entries are dropped so
  recent commands still get through once the orchestrator recovers.
  Losing some rows is better than growing memory without bound.

The module is deliberately dependency-free (stdlib only) and does NOT
import the upstream MCP server. That lets the test suite exercise it
outside the container, which matters because the only way to reproduce
the freeze is a controlled test harness that simulates a slow/down
backend.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("KALI_MCP_AUDIT_TIMEOUT", "2"))
QUEUE_MAXSIZE = int(os.environ.get("KALI_MCP_AUDIT_QUEUE_MAX", "512"))
CIRCUIT_BREAKER_THRESHOLD = int(os.environ.get("KALI_MCP_AUDIT_BREAKER_FAILS", "5"))
CIRCUIT_BREAKER_OPEN_SECONDS = float(
    os.environ.get("KALI_MCP_AUDIT_BREAKER_OPEN_SECONDS", "30")
)
WARN_DROP_EVERY = 50  # log one drop per N suppressed items while breaker is open


logger = logging.getLogger("kali_mcp_audit")


@dataclass
class _BreakerState:
    consecutive_failures: int = 0
    opened_at: float | None = None
    suppressed_since_last_warn: int = 0


class AuditPoster:
    """Background audit poster with a bounded queue and a circuit breaker.

    One instance is created at module import. Tests construct their own
    to avoid global state.
    """

    def __init__(
        self,
        *,
        orchestrator_base_url: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        queue_maxsize: int = QUEUE_MAXSIZE,
        breaker_threshold: int = CIRCUIT_BREAKER_THRESHOLD,
        breaker_open_seconds: float = CIRCUIT_BREAKER_OPEN_SECONDS,
        url_opener=None,
    ) -> None:
        self._orchestrator = orchestrator_base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(
            maxsize=queue_maxsize
        )
        self._breaker = _BreakerState()
        self._breaker_threshold = breaker_threshold
        self._breaker_open_seconds = breaker_open_seconds
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._shutdown = threading.Event()
        # Injectable so tests can replace the HTTP backend without
        # monkey-patching the urllib module globally.
        self._urlopen = url_opener or urllib.request.urlopen

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the background worker thread (idempotent)."""
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._shutdown.clear()
            self._worker = threading.Thread(
                target=self._run,
                name="kali-mcp-audit-poster",
                daemon=True,
            )
            self._worker.start()

    def stop(self, *, drain_timeout_seconds: float = 1.0) -> None:
        """Signal the worker to stop. Best-effort drain of the queue
        within ``drain_timeout_seconds`` before the thread is let go."""
        self._shutdown.set()
        # Nudge the worker out of its .get() wait with a sentinel.
        try:
            self._queue.put_nowait(("__shutdown__", {}))
        except queue.Full:
            pass
        worker = self._worker
        if worker is not None:
            worker.join(timeout=drain_timeout_seconds)

    # ------------------------------------------------------------------
    # Public enqueue path (called from the Flask hook)
    # ------------------------------------------------------------------

    def enqueue(self, engagement_key: str, payload: dict[str, Any]) -> bool:
        """Append an audit payload to the background queue.

        Returns True when the payload was accepted, False when the queue
        was full AND we could not make room. Never raises: an audit write
        must never crash the command response.
        """
        if self._is_breaker_open():
            self._note_suppression()
            return False
        item = (engagement_key, payload)
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            # Drop the oldest entry to keep the queue moving when the
            # backend has been slow for a while. The newest command is
            # more useful than the oldest unposted one.
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(item)
                logger.warning(
                    "audit queue full (max=%d); dropped oldest entry to keep recent traffic",
                    self._queue.maxsize,
                )
                return True
            except queue.Full:
                logger.warning("audit queue full; dropping current entry")
                return False

    # Test/debug introspection
    def queue_size(self) -> int:
        return self._queue.qsize()

    def breaker_open(self) -> bool:
        return self._is_breaker_open()

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._shutdown.is_set():
            try:
                engagement_key, payload = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if engagement_key == "__shutdown__":
                return
            if self._is_breaker_open():
                self._note_suppression()
                continue
            self._post_one(engagement_key, payload)

    def _post_one(self, engagement_key: str, payload: dict[str, Any]) -> None:
        url = f"{self._orchestrator}/engagements/{engagement_key}/assessment/command-runs"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._urlopen(req, timeout=self._timeout):
                pass
            self._record_success()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning(
                "command-run audit POST failed (%s %s): %s — tool output returned unchanged",
                engagement_key,
                payload.get("tool_name"),
                exc,
            )
            self._record_failure()

    # ------------------------------------------------------------------
    # Circuit breaker
    # ------------------------------------------------------------------

    def _is_breaker_open(self) -> bool:
        with self._lock:
            if self._breaker.opened_at is None:
                return False
            if time.monotonic() - self._breaker.opened_at >= self._breaker_open_seconds:
                # Half-open: let the next POST attempt through.
                self._breaker.opened_at = None
                self._breaker.consecutive_failures = 0
                self._emit_resumption_log()
                return False
            return True

    def _record_success(self) -> None:
        with self._lock:
            if self._breaker.opened_at is not None or self._breaker.consecutive_failures > 0:
                self._breaker.consecutive_failures = 0
                self._breaker.opened_at = None
                self._emit_resumption_log()

    def _record_failure(self) -> None:
        with self._lock:
            self._breaker.consecutive_failures += 1
            if (
                self._breaker.consecutive_failures >= self._breaker_threshold
                and self._breaker.opened_at is None
            ):
                self._breaker.opened_at = time.monotonic()
                logger.warning(
                    "audit circuit breaker OPEN after %d consecutive failures; "
                    "suppressing audit POSTs for %.0fs",
                    self._breaker.consecutive_failures,
                    self._breaker_open_seconds,
                )

    def _note_suppression(self) -> None:
        with self._lock:
            self._breaker.suppressed_since_last_warn += 1
            n = self._breaker.suppressed_since_last_warn
            if n == 1 or n % WARN_DROP_EVERY == 0:
                logger.warning(
                    "audit circuit breaker open; dropping audit payload "
                    "(suppressed=%d since last warn)",
                    n,
                )

    def _emit_resumption_log(self) -> None:
        # Called with the lock held.
        suppressed = self._breaker.suppressed_since_last_warn
        if suppressed > 0:
            logger.info(
                "audit circuit breaker recovered; dropped %d audit payloads while open",
                suppressed,
            )
        self._breaker.suppressed_since_last_warn = 0


# Singleton used by patched_kali_server.py. Tests construct their own.
_default_poster: AuditPoster | None = None


def _normalize_orchestrator_url(url: str) -> str:
    """Inside the Kali MCP container, ``127.0.0.1`` points at the container's
    own loopback, not the Mac host. Rewrite loopback literals to
    ``host.docker.internal`` so a stale ``.env`` with ``127.0.0.1:18000``
    still reaches the orchestrator running on the host."""
    return (
        url.rstrip("/")
        .replace("://127.0.0.1", "://host.docker.internal")
        .replace("://localhost", "://host.docker.internal")
    )


def default_poster() -> AuditPoster:
    global _default_poster
    if _default_poster is None:
        # Empty string counts as "not set" — passing `-e ORCHESTRATOR_BASE_URL=`
        # would otherwise give us an empty base URL that every POST pastes
        # ``/engagements/...`` onto, silently sending audits to the wrong host.
        raw = (
            os.environ.get("ORCHESTRATOR_BASE_URL", "").strip()
            or "http://host.docker.internal:18000"
        )
        orchestrator_url = _normalize_orchestrator_url(raw)
        _default_poster = AuditPoster(orchestrator_base_url=orchestrator_url)
        _default_poster.start()
    return _default_poster
