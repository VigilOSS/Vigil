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
import sqlite3
import threading
import time
from contextlib import closing

import anyio
import httpx
import pytest
from starlette.responses import PlainTextResponse

from app import aggregate_reads
from app.main import app
from app.services import code_analysis
from tests.test_event_loop_not_blocked import _command_run_payload, _write_engagement

KEY = "2026-06-13-000000-loopguard"
BASE = f"/engagements/{KEY}/assessment"
READINESS = f"{BASE}/code/readiness"
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


@pytest.mark.parametrize("cancel_during_read", [False, True], ids=["queued", "running"])
def test_surviving_identical_reads_share_a_fresh_result_after_cancellation(cancel_during_read):
    async def scenario():
        first_started = asyncio.Event()
        release_first = asyncio.Event()
        second_started = asyncio.Event()
        revision = 1
        reads = []

        async def report(scope, receive, send):
            snapshot = revision
            reads.append(snapshot)
            if len(reads) == 1:
                first_started.set()
                await release_first.wait()
            elif len(reads) == 2 and cancel_during_read:
                second_started.set()
                await asyncio.Event().wait()
            await PlainTextResponse(str(snapshot))(scope, receive, send)

        transport = httpx.ASGITransport(app=aggregate_reads.AggregateReadMiddleware(report))
        async with httpx.AsyncClient(transport=transport, base_url="http://acme.example") as http:
            path = "/engagements/acme/assessment/report-readiness"
            first = asyncio.create_task(http.get(path))
            await first_started.wait()
            revision = 2
            second = asyncio.create_task(http.get(path))
            followers = [asyncio.create_task(http.get(path)) for _ in range(6)]
            await asyncio.sleep(0)  # Let all callers queue behind the first read.
            if cancel_during_read:
                release_first.set()
                await second_started.wait()
                revision = 3
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second
            release_first.set()
            assert (await first).text == "1"
            responses = await asyncio.gather(*followers)
            assert [response.text for response in responses] == [str(revision)] * len(followers)
            assert reads == list(range(1, revision + 1))

    asyncio.run(asyncio.wait_for(scenario(), 5))


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


def test_depth_reads_expire_and_release_the_worker(client, isolate_settings, monkeypatch):
    from app import db
    from tests.test_coverage_by_family import DEEP_HOST, _insert_unit

    _write_engagement(isolate_settings["engagements_dir"])
    engagement_id = client.get(f"/engagements/{KEY}").json()["id"]
    _insert_unit(engagement_id, host=DEEP_HOST, path_prefix="/", deep_required=1)
    monkeypatch.setattr(aggregate_reads, "DEPTH_READ_TIMEOUT_SECONDS", 0.2, raising=False)

    # Make one shared projection input slow in SQLite without delaying unrelated
    # reads, acquiring a writer lock or constructing millions of fixture rows.
    with db.get_connection() as connection:
        connection.execute("ALTER TABLE assessment_surfaces RENAME TO original_surfaces")
        connection.execute(
            "CREATE VIEW assessment_surfaces AS "
            "WITH RECURSIVE steps(n) AS (VALUES(1) UNION ALL "
            "SELECT n+1 FROM steps WHERE n < 4000000) "
            f"SELECT {engagement_id:d} AS engagement_id, 'web' AS surface_type, "
            "CAST(sum(n) AS TEXT) AS target_descriptor FROM steps"
        )

    paths = [f"{BASE}/coverage-readiness/by-family", f"{BASE}/application-units/depth-ledger"]

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as http:
            readers = [asyncio.create_task(http.get(path)) for path in paths]
            ordinary = await http.get(f"{BASE}/application-units")
            return ordinary, await asyncio.gather(*readers)

    ordinary, expired = asyncio.run(scenario())
    assert ordinary.status_code == 200 and len(ordinary.json()) == 1
    assert [response.status_code for response in expired] == [503, 503]
    assert all("deadline" in response.json()["detail"].lower() for response in expired)
    assert all(response.headers.get("retry-after") == "1" for response in expired)

    with db.get_connection() as connection:
        connection.execute("DROP VIEW assessment_surfaces")
        connection.execute("ALTER TABLE original_surfaces RENAME TO assessment_surfaces")
    monkeypatch.setattr(aggregate_reads, "DEPTH_READ_TIMEOUT_SECONDS", 10)
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert len(response.json()["units"]) == 1


def _hold_depth_process(fingerprint, *_):
    root = fingerprint.path.parent
    with closing(sqlite3.connect(root / "worker-test.sqlite3")) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with (root / "worker-entered").open("a") as started:
            started.write("started\n")
        # Bounded in case the assertion in the parent fails.
        deadline = time.monotonic() + 15
        while not (root / "worker-release").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        return b"{}"


@pytest.mark.parametrize("route", [
    "coverage-readiness/by-family", "application-units/depth-ledger",
    "phase-readiness?phase=consume", "phase-readiness?phase=verify", "application-units/terminal-block",
])
def test_db_read_while_process_busy_and_cancel_releases_its_resources(
    client, isolate_settings, monkeypatch, route,
):
    from app.api import assessment

    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{KEY}").status_code == 200
    root = isolate_settings["data_dir"]
    monkeypatch.setattr(assessment, "depth_projection_bytes", _hold_depth_process)

    async def scenario():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original_tokens = limiter.total_tokens
        limiter.total_tokens = 1
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as http:
            task = asyncio.create_task(http.get(f"{BASE}/{route}"))
            try:
                entered = root / "worker-entered"
                await _until(lambda: entered.exists() or task.done(), timeout=10)
                assert entered.exists(), "depth read ran outside the cancellable process"
                ordinary = await asyncio.wait_for(http.get(f"{BASE}/application-units"), 3)
                assert ordinary.status_code == 200
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                # Taking the same writer lock proves the child exited before the
                # cancellation returned. A detached thread would still hold it.
                with closing(sqlite3.connect(root / "worker-test.sqlite3", timeout=0)) as check:
                    check.execute("BEGIN IMMEDIATE")
            finally:
                (root / "worker-release").touch()
                limiter.total_tokens = original_tokens
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


def test_expired_depth_followers_do_not_leave_a_queued_flight(client, isolate_settings, monkeypatch):
    from app.api import assessment

    _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{KEY}").status_code == 200
    root = isolate_settings["data_dir"]
    route = f"{BASE}/coverage-readiness/by-family"

    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as http:
            # Warm the process. The deadlines below measure waiting and running,
            # independently of the machine's interpreter startup latency.
            assert (await http.get(route)).status_code == 200
            monkeypatch.setattr(assessment, "depth_projection_bytes", _hold_depth_process)
            monkeypatch.setattr(aggregate_reads, "DEPTH_READ_TIMEOUT_SECONDS", 2)
            leader = asyncio.create_task(http.get(route))
            try:
                marker = root / "worker-entered"
                await _until(marker.exists)
                monkeypatch.setattr(aggregate_reads, "DEPTH_READ_TIMEOUT_SECONDS", 0.1)
                followers = await asyncio.gather(*(http.get(route) for _ in range(4)))
                assert [r.status_code for r in followers] == [503] * 4
                assert (await leader).status_code == 503
                assert marker.read_text().splitlines() == ["started"]
                with closing(sqlite3.connect(root / "worker-test.sqlite3", timeout=0)) as check:
                    check.execute("BEGIN IMMEDIATE")
            finally:
                (root / "worker-release").touch()
                await leader

    asyncio.run(scenario())
