"""Aggregate reads run on a small budget of their own and coalesce identical requests.

Readiness, coverage and resume-brief style reads walk a whole engagement. They
share the request worker pool with every write, so an unbounded burst of them
would take every worker and park writes behind them. These tests drive the real ASGI app
with requests genuinely in flight at once: the aggregate handler is held on an
event, so what the write sees is decided by worker availability, not timing.
"""
from __future__ import annotations

import asyncio
import itertools
import threading
import time

import anyio
import httpx

from app import aggregate_reads
from app.main import app
from app.services import code_analysis
from tests.test_event_loop_not_blocked import _command_run_payload, _write_engagement

KEY = "2026-06-13-000000-loopguard"
READINESS = f"/engagements/{KEY}/assessment/code/readiness"
POOL = 16
READERS = 16


def _held_readiness(monkeypatch):
    """Replace code readiness with a call that waits on ``release``."""
    state = {"active": 0, "peak": 0, "calls": 0}
    lock = threading.Lock()
    release = threading.Event()

    def held(engagement_id, **params):
        with lock:
            state["calls"] += 1
            flight = state["calls"]
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        try:
            assert release.wait(10), "test never released the held readiness reads"
            return {"flight": flight, "params": params}
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr(code_analysis, "code_readiness", held)
    return state, release


async def _until(predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


def _distinct_readiness_queries() -> list[str]:
    combos = itertools.product(
        ("classify-map", "hunt", "verify-variant", "fuzz", "complete"),
        ("true", "false"),
        ("true", "false"),
    )
    return [
        f"{READINESS}?target_phase={phase}&include_debt_paths={debt}&include_coverage={cov}"
        for phase, debt, cov in combos
    ][:READERS]


def test_a_write_completes_while_aggregate_readers_hold_their_budget(
    client, isolate_settings, monkeypatch
):
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{KEY}").status_code == 200
    state, release = _held_readiness(monkeypatch)

    async def scenario():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        limiter.total_tokens = POOL
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as http:
            readers = [
                asyncio.create_task(http.get(query)) for query in _distinct_readiness_queries()
            ]
            try:
                await _until(lambda: state["active"] >= 1)
                # Let every reader that can get a worker take one.
                await asyncio.sleep(0.3)
                started = time.monotonic()
                write = await asyncio.wait_for(
                    http.post(
                        f"/engagements/{KEY}/assessment/command-runs",
                        json=_command_run_payload(),
                    ),
                    5,
                )
                write_seconds = time.monotonic() - started
                held_during_write = state["active"]
            finally:
                release.set()
                replies = await asyncio.wait_for(asyncio.gather(*readers), 10)
                limiter.total_tokens = original
        return write, write_seconds, held_during_write, replies

    write, write_seconds, held_during_write, replies = asyncio.run(scenario())

    assert write.status_code == 201, write.text
    assert write_seconds < 5
    budget = aggregate_reads.aggregate_read_budget(POOL)
    assert 1 <= budget < POOL
    # Only the aggregate budget ran; the rest waited without holding a worker.
    assert held_during_write == budget
    assert state["peak"] == budget
    assert [reply.status_code for reply in replies] == [200] * READERS
    assert state["calls"] == READERS


def test_identical_aggregate_reads_share_one_fresh_flight(client, isolate_settings, monkeypatch):
    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{KEY}").status_code == 200
    state, release = _held_readiness(monkeypatch)
    query = f"{READINESS}?target_phase=complete&include_coverage=true"
    # Same parameters in another order are the same read.
    reordered = f"{READINESS}?include_coverage=true&target_phase=complete"

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as http:
            first = asyncio.create_task(http.get(query))
            await _until(lambda: state["active"] == 1)
            joiners = [
                asyncio.create_task(http.get(query if index % 2 else reordered))
                for index in range(6)
            ]
            await asyncio.sleep(0.2)
            # Joiners wait for the next flight instead of starting their own.
            assert state["calls"] == 1
            release.set()
            return await asyncio.wait_for(first, 10), await asyncio.wait_for(
                asyncio.gather(*joiners), 10
            )

    first, joined = asyncio.run(scenario())

    assert first.status_code == 200 and first.json()["flight"] == 1
    # A request that arrived while flight 1 ran never receives flight 1's
    # answer: it was computed before the request existed. All of them share
    # flight 2, byte for byte.
    assert {reply.status_code for reply in joined} == {200}
    assert {reply.content for reply in joined} == {joined[0].content}
    assert joined[0].json()["flight"] == 2
    assert state["calls"] == 2


def test_every_aggregate_route_is_a_registered_get_route():
    registered = {path for path, operations in app.openapi()["paths"].items() if "get" in operations}
    assert aggregate_reads.AGGREGATE_READ_ROUTES <= registered, (
        aggregate_reads.AGGREGATE_READ_ROUTES - registered
    )


def test_the_aggregate_budget_always_leaves_writes_a_worker(monkeypatch):
    monkeypatch.delenv("VIGIL_BACKEND_AGGREGATE_READS", raising=False)
    assert aggregate_reads.aggregate_read_budget(16) == 3
    monkeypatch.setenv("VIGIL_BACKEND_AGGREGATE_READS", "40")
    assert aggregate_reads.aggregate_read_budget(16) == 15
    monkeypatch.setenv("VIGIL_BACKEND_AGGREGATE_READS", "0")
    assert aggregate_reads.aggregate_read_budget(16) == 1
    monkeypatch.setenv("VIGIL_BACKEND_AGGREGATE_READS", "many")
    assert aggregate_reads.aggregate_read_budget(16) == 3


def test_repeated_values_keep_their_order_in_the_flight_key():
    """Keys may come in any order; one key's repeated values are a list, in order."""

    def key(query: str):
        return aggregate_reads._flight_key({"path": READINESS, "query_string": query.encode()})

    assert key("target_phase=complete&include_coverage=true") == key(
        "include_coverage=true&target_phase=complete"
    )
    assert key("family=sqli&family=xss") != key("family=xss&family=sqli")
    assert key("family=sqli&target_phase=complete&family=xss") == key(
        "target_phase=complete&family=sqli&family=xss"
    )
