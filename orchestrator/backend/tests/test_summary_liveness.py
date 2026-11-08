from __future__ import annotations

import asyncio
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor

import anyio
import httpx
import pytest

from app.main import app
from tests.test_engagements_api import write_engagement

summary = importlib.import_module("app.services.state_manager.assessment_summary")
KEY = "2026-03-30-120000-example"


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])
    record = client.get(f"/engagements/{KEY}").json()
    summary.clear_assessment_summary_cache()
    return record["id"]


def test_summary_publication_failure_releases_ownership(
    client, isolate_settings, monkeypatch
):
    engagement_id = _seed(client, isolate_settings)
    original = summary.copy.deepcopy
    calls = 0

    def copy_once(value):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise MemoryError("Acme allocation failure")
        return original(value)

    monkeypatch.setattr(
        summary, "_build_assessment_summary", lambda eid: {"engagement_id": eid}
    )
    monkeypatch.setattr(summary.copy, "deepcopy", copy_once)
    with pytest.raises(MemoryError):
        summary.assessment_summary(engagement_id)
    # Recovery is observed through another caller, rather than inspecting cache internals.
    completed = threading.Event()
    result = []

    def read_again():
        result.append(summary.assessment_summary(engagement_id))
        completed.set()

    reader = threading.Thread(target=read_again, daemon=True)
    reader.start()
    recovered = completed.wait(0.3)
    if not recovered:
        # Unstick the baseline worker after recording the failed recovery outcome.
        with summary._summary_cache_lock:
            running = list(summary._summary_cache_inflight.values())
            summary._summary_cache_inflight.clear()
        for flight in running:
            flight.set_result(None)
        reader.join(1)
    assert recovered, "A failed publication must not strand all later summary callers"
    assert result == [{"engagement_id": engagement_id}]


def test_summary_copy_does_not_hold_invalidation_lock(
    client, isolate_settings, monkeypatch
):
    engagement_id = _seed(client, isolate_settings)
    entered, release, invalidated = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    original = summary.copy.deepcopy

    def copy_slow(value):
        entered.set()
        assert release.wait(2)
        return original(value)

    monkeypatch.setattr(
        summary, "_build_assessment_summary", lambda eid: {"engagement_id": eid}
    )
    monkeypatch.setattr(summary.copy, "deepcopy", copy_slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        build = pool.submit(summary.assessment_summary, engagement_id)
        assert entered.wait(1)

        def invalidate():
            summary.clear_assessment_summary_cache(engagement_id)
            invalidated.set()

        clearing = pool.submit(invalidate)
        progressed = invalidated.wait(0.3)
        release.set()
        build.result(timeout=1)
        clearing.result(timeout=1)
    assert progressed, (
        "Copying a summary must not delay unrelated mutation invalidation"
    )


@pytest.mark.parametrize("endpoint", ["summary", "report-export"])
def test_http_summary_joiners_leave_workers_for_readiness(
    client, isolate_settings, monkeypatch, endpoint
):
    engagement_id = _seed(client, isolate_settings)
    if endpoint == "report-export":
        from app.api import report_export

        monkeypatch.setattr(
            report_export,
            "_render_report_html",
            lambda payload: "<!doctype html>Acme report",
        )
    entered, release, joined = threading.Event(), threading.Event(), threading.Event()
    calls = 0
    lock = threading.Lock()
    lookup = summary._engagement_or_404

    def observed_lookup(eid):
        nonlocal calls
        record = lookup(eid)
        with lock:
            calls += 1
            if calls == 16:
                joined.set()
        return record

    def slow_build(eid):
        entered.set()
        assert release.wait(4)
        return {"engagement_id": eid}

    monkeypatch.setattr(summary, "_engagement_or_404", observed_lookup)
    monkeypatch.setattr(summary, "_build_assessment_summary", slow_build)

    async def check():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        limiter.total_tokens = 16
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://acme.example"
        ) as reader:

            async def fetch():
                if endpoint == "summary":
                    return await reader.get(f"/engagements/{KEY}/assessment/summary")
                return await reader.post(
                    f"/engagements/{KEY}/assessment/report-export",
                    json={"mode": "draft"},
                )

            requests = [asyncio.create_task(fetch()) for _ in range(16)]
            try:
                assert await asyncio.to_thread(entered.wait, 1)
                assert await asyncio.to_thread(joined.wait, 2)
                probe = await asyncio.wait_for(reader.get("/readyz"), 0.7)
                assert probe.status_code == 200
            finally:
                release.set()
                replies = await asyncio.wait_for(asyncio.gather(*requests), 2)
                limiter.total_tokens = original
            assert all(r.status_code == 200 for r in replies), [r.text for r in replies]
            if endpoint == "summary":
                assert all(
                    r.json() == {"engagement_id": engagement_id} for r in replies
                )
            else:
                assert len({r.json()["artifact_id"] for r in replies}) == 16

    asyncio.run(check())


@pytest.mark.parametrize("bridge", ["mutation", "websocket"])
def test_blocking_lookup_or_cache_invalidation_does_not_park_event_loop(
    monkeypatch, bridge
):
    from app.api import assessment
    from app import main
    from starlette.websockets import WebSocketDisconnect

    entered, release = threading.Event(), threading.Event()

    def blocked(*args):
        entered.set()
        assert release.wait(2)

    class Socket:
        headers = {"origin": "http://127.0.0.1:18000"}

        async def accept(self):
            pass

        async def receive_text(self):
            raise WebSocketDisconnect(1000)

    if bridge == "mutation":
        monkeypatch.setattr(
            assessment.state_manager, "clear_assessment_summary_cache", blocked
        )

        async def operation():
            await assessment._broadcast("acme", "finding_patch", {"engagement_id": 1})
    else:
        monkeypatch.setattr(main, "get_engagement_or_404", blocked)

        async def operation():
            await main.engagement_stream(Socket(), "acme")

    async def check():
        timer = threading.Timer(0.3, release.set)
        timer.start()
        task = asyncio.create_task(operation())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            progressed = not release.is_set()
            release.set()
            await task
            assert progressed, (
                "Another coroutine must progress while synchronous work waits"
            )
        finally:
            release.set()
            timer.cancel()

    asyncio.run(check())


def test_invalidated_build_cannot_populate_cache_for_waiters(
    client, isolate_settings, monkeypatch
):
    engagement_id = _seed(client, isolate_settings)
    entered, release = threading.Event(), threading.Event()
    builds = []

    def build(eid):
        builds.append(eid)
        revision = len(builds)
        if revision == 1:
            entered.set()
            assert release.wait(2)
        return {"revision": revision}

    monkeypatch.setattr(summary, "_build_assessment_summary", build)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(summary.assessment_summary, engagement_id)
        assert entered.wait(1)
        second = pool.submit(summary.assessment_summary, engagement_id)
        summary.clear_assessment_summary_cache(engagement_id)
        release.set()
        assert first.result(timeout=1) == {"revision": 1}
        assert second.result(timeout=1) == {"revision": 2}
    assert summary.assessment_summary(engagement_id) == {"revision": 2}
    assert builds == [engagement_id, engagement_id]


def test_cancelled_async_caller_does_not_abandon_owner_or_cancel_joiners(
    client, isolate_settings, monkeypatch
):
    engagement_id = _seed(client, isolate_settings)
    entered, release, joined = threading.Event(), threading.Event(), threading.Event()
    original = summary._summary_step

    def step(*args):
        result = original(*args)
        if result[1] is not None:
            joined.set()
        return result

    def build(eid):
        entered.set()
        assert release.wait(2)
        return {"engagement_id": eid}

    monkeypatch.setattr(summary, "_build_assessment_summary", build)
    monkeypatch.setattr(summary, "_summary_step", step)

    async def check():
        owner = asyncio.create_task(summary.assessment_summary_async(engagement_id))
        assert await asyncio.to_thread(entered.wait, 1)
        abandoned = asyncio.create_task(summary.assessment_summary_async(engagement_id))
        assert await asyncio.to_thread(joined.wait, 1)
        abandoned.cancel()
        with pytest.raises(asyncio.CancelledError):
            await abandoned
        owner.cancel()
        with pytest.raises(asyncio.CancelledError):
            await owner
        surviving = asyncio.create_task(summary.assessment_summary_async(engagement_id))
        release.set()
        assert await asyncio.wait_for(surviving, 1) == {"engagement_id": engagement_id}
        assert await summary.assessment_summary_async(engagement_id) == {
            "engagement_id": engagement_id
        }

    asyncio.run(check())


def test_tcp_summary_recovers_after_publication_failure_and_disconnected_joiners(
    client,
    isolate_settings,
    monkeypatch,
):
    import socket
    import uvicorn

    _seed(client, isolate_settings)
    entered, release, joined, started = (threading.Event() for _ in range(4))
    copy_failure = threading.Event()
    original_copy = summary.copy.deepcopy
    original_lookup = summary._engagement_or_404
    lookups = 0
    count_lock = threading.Lock()

    def copy_once(value):
        if (
            isinstance(value, dict)
            and value.get("acme_summary")
            and not copy_failure.is_set()
        ):
            copy_failure.set()
            raise MemoryError("Acme cache publication failure")
        return original_copy(value)

    def lookup(eid):
        nonlocal lookups
        record = original_lookup(eid)
        with count_lock:
            lookups += 1
            if lookups >= 17:
                joined.set()
        return record

    def build(eid):
        if copy_failure.is_set():
            entered.set()
            assert release.wait(8)
        return {"acme_summary": True, "engagement_id": eid}

    monkeypatch.setattr(summary.copy, "deepcopy", copy_once)
    monkeypatch.setattr(summary, "_engagement_or_404", lookup)
    monkeypatch.setattr(summary, "_build_assessment_summary", build)

    class Server(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            started.set()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,
            access_log=False,
            log_level="critical",
            timeout_graceful_shutdown=2,
        )
    )
    worker = threading.Thread(
        target=lambda: server.run(sockets=[listener]), daemon=True
    )
    worker.start()
    try:
        assert started.wait(3)
        port = listener.getsockname()[1]

        async def check():
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as reader:
                route = f"/engagements/{KEY}/assessment/summary"
                failed = await reader.get(route)
                assert failed.status_code == 500
                requests = [
                    asyncio.create_task(reader.get(route, timeout=1)) for _ in range(16)
                ]
                try:
                    assert await asyncio.to_thread(entered.wait, 2)
                    assert await asyncio.to_thread(joined.wait, 2)
                    outcomes = await asyncio.gather(*requests, return_exceptions=True)
                    assert all(
                        isinstance(value, httpx.ReadTimeout) for value in outcomes
                    ), outcomes
                    # Disconnected joiners may still be waiting on the server,
                    # but they must not occupy its general request workers.
                    probe = await reader.get("/readyz", timeout=1)
                    assert probe.status_code == 200, probe.text
                finally:
                    release.set()
                    await asyncio.gather(*requests, return_exceptions=True)
                recovered = await reader.get(route, timeout=2)
                assert recovered.status_code == 200, recovered.text
                assert recovered.json()["acme_summary"] is True

        asyncio.run(check())
    finally:
        release.set()
        server.should_exit = True
        worker.join(4)
        listener.close()
        assert not worker.is_alive(), (
            "The isolated HTTP server must shut down after recovery"
        )
