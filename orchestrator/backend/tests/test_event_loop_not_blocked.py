"""E1 regression: async write handlers must not block the event loop.

The root cause of the engagement's "orchestrator timeouts under concurrent
agents" was that an ``async def`` write handler called synchronous SQLite
inline, stalling the event loop for the whole write (~169ms reproduced). No
other coroutine — including a cheap ``GET /healthz`` — could run during that
window.

The fix off-loads every synchronous DB call in the async write handlers to the
anyio worker threadpool (``anyio.to_thread.run_sync``). With the off-load in
place, a slow write occupies a worker thread, the event loop stays free, and
concurrent ``GET /healthz`` requests return immediately.

These tests drive the real ASGI app via ``httpx.ASGITransport`` + asyncio and
monkeypatch ``state_manager.record_command_run`` to block for ~0.3s. They are
deterministic: the assertions compare the latency of healthz calls fired DURING
a blocking write against a generous ceiling that the pre-fix (inline) code path
could not meet, and a control test proves the harness actually detects a stalled
loop.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx

from app.main import app
from app.services import state_manager


ENGAGEMENT_KEY = "2026-06-13-000000-loopguard"

# The monkeypatched write blocks for this long. It is the signal we use to tell
# "loop stalled" (healthz waited behind the write) from "loop free" (healthz
# returned promptly).
BLOCKING_WRITE_SECONDS = 0.3


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-06-13T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    return engagement_dir


def _command_run_payload() -> dict:
    return {
        "command": "nmap -sV 10.0.0.1",
        "argv": ["nmap", "-sV", "10.0.0.1"],
        "tool_name": "nmap_scan",
        "route": "/api/tools/nmap/scan",
        "agent_name": "recon-specialist",
        "phase": "recon",
        "return_code": 0,
        "timed_out": False,
        "success": True,
        "started_at": "2026-06-13T00:00:00Z",
        "completed_at": "2026-06-13T00:00:02Z",
        "duration_ms": 2000,
        "stdout": "Nmap scan report for 10.0.0.1\n22/tcp open ssh\n",
        "stderr": "",
        "notes": "",
        "technique": None,
        "intent": None,
        "probe_kind": None,
        "destructive": None,
    }


async def _timed_healthz(client: httpx.AsyncClient) -> float:
    start = time.perf_counter()
    response = await client.get("/healthz")
    elapsed = time.perf_counter() - start
    assert response.status_code == 200, response.text
    return elapsed


def _run(coro):
    return asyncio.run(coro)


def _percentile(samples: list[float], pct: float) -> float:
    ordered = sorted(samples)
    if not ordered:
        return 0.0
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def test_healthz_stays_responsive_while_a_write_handler_runs(
    client, isolate_settings, monkeypatch
):
    """A blocking SQLite write must not delay concurrent GET /healthz.

    The ``client`` fixture initializes the DB and runs the app lifespan (which
    also bumps the threadpool cap). We then drive the same ASGI app over httpx
    with asyncio so multiple requests are genuinely in flight at once.
    """
    _write_engagement(isolate_settings["engagements_dir"])

    real_record_command_run = state_manager.record_command_run

    def _slow_record_command_run(*args, **kwargs):
        # Simulate a heavy synchronous SQLite write. If the handler ran this
        # inline on the event loop (the pre-E1 shape), the loop would be frozen
        # for BLOCKING_WRITE_SECONDS and the healthz calls below would queue
        # behind it. With the off-load, this runs on a worker thread instead.
        time.sleep(BLOCKING_WRITE_SECONDS)
        return real_record_command_run(*args, **kwargs)

    monkeypatch.setattr(state_manager, "record_command_run", _slow_record_command_run)

    async def scenario() -> tuple[float, list[float], int]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as ac:
            # Kick off the slow write; do NOT await it yet.
            write_task = asyncio.create_task(
                ac.post(
                    f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
                    json=_command_run_payload(),
                )
            )
            # Give the POST a moment to enter the handler and begin the blocking
            # write so the healthz calls truly overlap it.
            await asyncio.sleep(0.02)

            # Fire a burst of healthz calls while the write is still blocking.
            health_latencies = await asyncio.gather(
                *[_timed_healthz(ac) for _ in range(20)]
            )

            write_response = await write_task
            return write_response.status_code, list(health_latencies), 0

    start = time.perf_counter()
    status_code, health_latencies, _ = _run(scenario())
    total_elapsed = time.perf_counter() - start

    assert status_code == 201

    p95 = _percentile(health_latencies, 95)
    # If the write blocked the loop, every overlapping healthz call would have
    # waited out the full BLOCKING_WRITE_SECONDS. With the off-load they return
    # in well under that. A generous ceiling (half the block) keeps the test
    # robust on a busy CI box while still failing loudly on a regression.
    assert p95 < BLOCKING_WRITE_SECONDS / 2, (
        f"healthz p95={p95:.3f}s under a concurrent write — the event loop "
        f"appears stalled (block was {BLOCKING_WRITE_SECONDS}s); the async "
        f"write handler is running sync SQLite inline again"
    )
    # The whole scenario still completed in roughly one block window, proving
    # the work overlapped rather than serialized.
    assert total_elapsed < BLOCKING_WRITE_SECONDS * 3


def test_harness_detects_a_stalled_loop_control(isolate_settings):
    """Control: an async handler that runs the blocking work INLINE (the
    pre-E1 shape) DOES delay concurrent GET /healthz.

    This proves the probe in the primary test can actually observe a stalled
    loop — so a passing primary test means the off-load works, not that the
    measurement is blind. We mount a throwaway route on the real app whose
    ``async def`` body calls ``time.sleep`` directly on the event loop (exactly
    what the write handlers used to do), drive it concurrently with healthz over
    the same ASGI transport, and assert healthz was delayed by ~the block.
    """
    from fastapi import APIRouter

    control_router = APIRouter()

    @control_router.post("/__loopguard_control_inline_block")
    async def _inline_block() -> dict[str, str]:
        # Synchronous sleep inside an async handler == frozen event loop. No
        # off-load, so every other coroutine (including healthz) waits.
        time.sleep(BLOCKING_WRITE_SECONDS)
        return {"status": "blocked"}

    app.include_router(control_router)
    try:
        async def scenario() -> list[float]:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as ac:
                # Measure each healthz's completion relative to ONE shared
                # reference captured before anything is scheduled, so the result
                # is independent of cooperative task-start ordering. If the
                # inline block freezes the loop, the healthz coroutines cannot
                # make progress until it returns and their completion time
                # relative to t0 includes the block.
                t0 = time.perf_counter()

                async def healthz_since_t0() -> float:
                    response = await ac.get("/healthz")
                    assert response.status_code == 200, response.text
                    return time.perf_counter() - t0

                results = await asyncio.gather(
                    ac.post("/__loopguard_control_inline_block"),
                    *[healthz_since_t0() for _ in range(5)],
                )
                return list(results[1:])

        health_latencies = _run(scenario())
    finally:
        # Drop the throwaway route so we don't leak it into the shared app
        # instance used by other tests.
        app.router.routes = [
            route
            for route in app.router.routes
            if getattr(route, "path", None) != "/__loopguard_control_inline_block"
        ]
        app.openapi_schema = None

    worst = max(health_latencies)
    # At least one healthz call must have been caught behind the frozen loop.
    assert worst >= BLOCKING_WRITE_SECONDS * 0.5, (
        f"control failed: worst healthz latency {worst:.3f}s did not reflect "
        f"the {BLOCKING_WRITE_SECONDS}s on-loop block, so the primary test "
        f"cannot be trusted to detect a stall"
    )
