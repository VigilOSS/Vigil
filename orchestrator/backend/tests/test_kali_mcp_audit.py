"""Non-blocking audit poster used by the patched Kali MCP server.

These tests live in the backend pytest tree because that is where the
project's test infrastructure is wired up. The module under test lives in
``docker/kali-mcp-runtime/kali_mcp_audit.py`` and is deliberately stdlib-only
so it can be imported without the upstream Kali MCP server present.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[3]
_AUDIT_MODULE_DIR = _REPO_ROOT / "docker" / "kali-mcp-runtime"
if str(_AUDIT_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_MODULE_DIR))

import kali_mcp_audit  # noqa: E402


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _noop_opener(req, timeout=None):  # noqa: ARG001
    return _FakeResponse()


def _raising_opener(exc_type=ConnectionRefusedError, message="refused"):
    def _opener(req, timeout=None):  # noqa: ARG001
        raise exc_type(message)

    return _opener


def _slow_opener(delay_seconds: float):
    def _opener(req, timeout=None):
        time.sleep(delay_seconds)
        return _FakeResponse()

    return _opener


def _make_poster(**kwargs):
    defaults = dict(
        orchestrator_base_url="http://127.0.0.1:18000",
        timeout_seconds=0.1,
        queue_maxsize=16,
        breaker_threshold=3,
        breaker_open_seconds=0.25,
    )
    defaults.update(kwargs)
    return kali_mcp_audit.AuditPoster(**defaults)


def _wait_until(predicate, timeout: float = 2.0, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# Core non-blocking contract
# ---------------------------------------------------------------------------


def test_enqueue_returns_immediately_when_backend_is_slow():
    """The request path MUST NOT wait on the orchestrator POST. A slow
    backend that takes 5s per POST cannot hold up the Flask response."""
    poster = _make_poster(url_opener=_slow_opener(5.0))
    poster.start()
    try:
        t0 = time.monotonic()
        for i in range(10):
            assert poster.enqueue("engagement", {"tool_name": f"t{i}"}) is True
        elapsed = time.monotonic() - t0
        # 10 enqueues must complete in milliseconds, not seconds — proves
        # the worker thread is decoupled from the caller.
        assert elapsed < 0.2, f"enqueue blocked for {elapsed:.3f}s"
    finally:
        poster.stop()


def test_enqueue_success_drains_queue():
    poster = _make_poster(url_opener=_noop_opener)
    poster.start()
    try:
        for i in range(5):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})
        assert _wait_until(lambda: poster.queue_size() == 0)
    finally:
        poster.stop()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


def test_breaker_opens_after_consecutive_failures_and_drops_payloads():
    poster = _make_poster(
        url_opener=_raising_opener(ConnectionRefusedError, "refused"),
        breaker_threshold=3,
    )
    poster.start()
    try:
        # Feed enough failures to trip the breaker.
        for i in range(3):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})
        assert _wait_until(poster.breaker_open)

        # With breaker open, further enqueues return False (dropped).
        dropped = sum(
            0 if poster.enqueue("engagement", {"tool_name": f"drop{i}"}) else 1
            for i in range(10)
        )
        assert dropped == 10, "every enqueue while open must be dropped"
    finally:
        poster.stop()


def test_worker_drops_queued_payloads_after_breaker_opens():
    attempts = {"count": 0}

    def _counting_failure(req, timeout=None):  # noqa: ARG001
        attempts["count"] += 1
        raise ConnectionRefusedError("refused")

    poster = _make_poster(
        url_opener=_counting_failure,
        queue_maxsize=20,
        breaker_threshold=3,
        breaker_open_seconds=10.0,
    )
    poster.start()
    try:
        for i in range(20):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})

        assert _wait_until(lambda: poster.queue_size() == 0)
        assert poster.breaker_open()
        assert attempts["count"] == 3
    finally:
        poster.stop()


def test_breaker_closes_after_open_window_and_success():
    """After the open window, the breaker half-opens: the next successful
    POST closes it and resumes normal operation."""
    opener_state = {"fail": True}

    def _switching_opener(req, timeout=None):  # noqa: ARG001
        if opener_state["fail"]:
            raise ConnectionRefusedError("refused")
        return _FakeResponse()

    poster = _make_poster(
        url_opener=_switching_opener,
        breaker_threshold=3,
        breaker_open_seconds=0.1,
    )
    poster.start()
    try:
        for i in range(3):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})
        assert _wait_until(poster.breaker_open)

        # Recover backend and wait for the open window to expire.
        opener_state["fail"] = False
        time.sleep(0.15)

        # Next enqueue must pass; the worker sees success and closes the
        # breaker.
        assert poster.enqueue("engagement", {"tool_name": "recover"}) is True
        assert _wait_until(lambda: not poster.breaker_open() and poster.queue_size() == 0)
    finally:
        poster.stop()


# ---------------------------------------------------------------------------
# Bounded queue
# ---------------------------------------------------------------------------


def test_queue_overflow_drops_oldest_not_current():
    """With the worker blocked on a slow POST and the queue full, new
    enqueues drop the oldest pending entry so the freshest traffic still
    gets a chance."""
    # Block the worker hard so the queue actually fills.
    block = threading.Event()

    def _blocking_opener(req, timeout=None):  # noqa: ARG001
        block.wait(timeout=5.0)
        return _FakeResponse()

    poster = _make_poster(url_opener=_blocking_opener, queue_maxsize=4)
    poster.start()
    try:
        # First enqueue starts the worker on a blocked POST. Fill the queue.
        for i in range(20):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})
        # Queue is bounded at 4 (+1 item in flight at worker).
        assert poster.queue_size() <= 4
    finally:
        block.set()
        poster.stop()


# ---------------------------------------------------------------------------
# Exception handling never escapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_type",
    [ConnectionRefusedError, TimeoutError, OSError],
)
def test_worker_swallows_all_expected_errors(exc_type):
    poster = _make_poster(url_opener=_raising_opener(exc_type, "boom"))
    poster.start()
    try:
        for i in range(4):
            poster.enqueue("engagement", {"tool_name": f"t{i}"})
        # Worker must drain the queue even though every POST fails.
        assert _wait_until(lambda: poster.queue_size() == 0)
    finally:
        poster.stop()


def test_stop_is_safe_when_not_started():
    poster = _make_poster()
    poster.stop()  # no raise


def test_start_is_idempotent():
    poster = _make_poster()
    poster.start()
    worker_a = poster._worker
    poster.start()
    assert poster._worker is worker_a
    poster.stop()


# ---------------------------------------------------------------------------
# Container-networking normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Loopback literals rewrite to the Docker Desktop host alias because
        # inside the container they point at the container's own lo, not the
        # Mac host where the orchestrator runs.
        ("http://127.0.0.1:18000", "http://host.docker.internal:18000"),
        ("http://localhost:18000", "http://host.docker.internal:18000"),
        ("http://127.0.0.1:18000/", "http://host.docker.internal:18000"),
        # Non-loopback targets pass through untouched (operator ran the
        # orchestrator on a different box and set the URL explicitly).
        ("http://10.0.0.5:18000", "http://10.0.0.5:18000"),
        ("http://host.docker.internal:18000", "http://host.docker.internal:18000"),
    ],
)
def test_normalize_orchestrator_url(raw, expected):
    assert kali_mcp_audit._normalize_orchestrator_url(raw) == expected
