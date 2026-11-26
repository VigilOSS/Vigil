"""Engagement-wide aggregate reads: a small worker budget and single-flight coalescing.

Readiness, coverage, resume-brief and similar reads walk a whole engagement and
can each take seconds. Every request handler, read or write, runs its SQLite
work on the same worker pool (`VIGIL_BACKEND_THREADPOOL`), so an unbounded
burst of these reads would hold every worker and park writes behind them. This
middleware lets at most `aggregate_read_budget` of them run at once; the rest
wait on the event loop without holding a worker, so writes always find one.

Identical requests (same route, path parameters and query parameters, in any
order) coalesce. A request that arrives while an identical one is running
waits for that flight to finish and then shares the NEXT flight with every
other request that arrived meanwhile, so each response is computed after its
request arrived: coalescing removes duplicate work and never serves an answer
older than the request. Followers receive the leader's status, headers and
body byte for byte.
"""
from __future__ import annotations

import asyncio
import math
import os
import re
import weakref
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl

from anyio import to_thread
from pydantic import TypeAdapter
from starlette.datastructures import QueryParams
from starlette.responses import JSONResponse
from starlette.routing import compile_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import db
from .services.state_manager.phase_readiness import phase_includes_depth

_ASSESSMENT = "/engagements/{engagement_key}/assessment"

# Route templates (as registered) whose GET handlers compute an engagement-wide
# aggregate. `/summary` is not listed: it already single-flights its build
# without holding a worker (`assessment_summary_async`).
_DEPTH_READ_ROUTES = frozenset({
    f"{_ASSESSMENT}/coverage-readiness/by-family",
    f"{_ASSESSMENT}/application-units/depth-ledger",
    f"{_ASSESSMENT}/application-units/terminal-block",
})

AGGREGATE_READ_ROUTES = _DEPTH_READ_ROUTES | frozenset({
    f"{_ASSESSMENT}/coverage-readiness",
    f"{_ASSESSMENT}/coverage-readiness/by-host",
    f"{_ASSESSMENT}/report-readiness",
    f"{_ASSESSMENT}/phase-readiness",
    f"{_ASSESSMENT}/resume-brief",
    f"{_ASSESSMENT}/code/readiness",
    f"{_ASSESSMENT}/code/coverage",
    f"{_ASSESSMENT}/code/coverage/by-path",
    f"{_ASSESSMENT}/code/coverage/inherited",
    f"{_ASSESSMENT}/code/repos/review-progress",
})

DEFAULT_AGGREGATE_READ_WORKERS = 3
DEPTH_READ_TIMEOUT_SECONDS = 60.0
_DEPTH_PATHS = tuple(compile_path(route)[0] for route in _DEPTH_READ_ROUTES)


_PHASE_PATH = compile_path(f"{_ASSESSMENT}/phase-readiness")[0]
DepthProjection = Literal["by-family", "depth-ledger", "terminal-block", "phase-readiness"]
_DEPTH_RESPONSE = TypeAdapter(dict[str, Any])


def depth_projection_bytes(
    database: db.DatabaseFingerprint, engagement_id: int, projection: DepthProjection,
    host: str, path_prefix: str, phase: str,
) -> bytes:
    """Run the canonical service and its JSON rendering in a cancellable worker."""
    from .services import state_manager
    from .services.state_manager.depth_ledger import by_family_coverage

    with db.projection_database(database, writable=projection == "terminal-block") as connection:
        if projection == "by-family":
            result = by_family_coverage(connection, engagement_id, host=host, path_prefix=path_prefix)
        elif projection == "terminal-block":
            result = state_manager.terminal_depth_block(engagement_id)
        elif projection == "phase-readiness":
            result = state_manager.phase_readiness(engagement_id, phase)
        else:
            result = state_manager.depth_ledger(engagement_id)
        return _DEPTH_RESPONSE.dump_json(result)


def _depth_read(scope: Scope) -> bool:
    if _PHASE_PATH.match(scope["path"]):
        return phase_includes_depth(QueryParams(scope.get("query_string", b"")).get("phase", ""))
    return any(pattern.match(scope["path"]) for pattern in _DEPTH_PATHS)


def aggregate_read_budget(pool_tokens: int) -> int:
    """How many aggregate reads may run at once on a pool of *pool_tokens* workers.

    `VIGIL_BACKEND_AGGREGATE_READS` (default 3), never below one and always at
    least one worker short of the pool, so writes keep a worker however it is set.
    """
    raw = os.environ.get("VIGIL_BACKEND_AGGREGATE_READS", str(DEFAULT_AGGREGATE_READ_WORKERS))
    try:
        configured = int(raw)
    except ValueError:
        configured = DEFAULT_AGGREGATE_READ_WORKERS
    return max(1, min(configured, int(pool_tokens) - 1))


_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    compile_path(template)[0] for template in sorted(AGGREGATE_READ_ROUTES)
)


def is_aggregate_read(scope: Scope) -> bool:
    """True for a GET whose path matches one of `AGGREGATE_READ_ROUTES`."""
    if scope["type"] != "http" or scope["method"] != "GET":
        return False
    path = scope["path"]
    return any(pattern.match(path) for pattern in _ROUTE_PATTERNS)


FlightKey = tuple[str, str, tuple[tuple[str, str], ...]]


def _flight_key(scope: Scope) -> FlightKey:
    """The request's identity: path (engagement included) and its query.

    Distinct keys may arrive in any order; a repeated key's values keep theirs,
    because a route may read them as an ordered list (the sort is stable and
    compares keys only).
    """
    query = scope.get("query_string", b"").decode("latin-1")
    return (
        scope.get("root_path", ""),
        scope["path"],
        tuple(sorted(parse_qsl(query, keep_blank_values=True), key=lambda pair: pair[0])),
    )


@dataclass
class _Flight:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    started: int = 0
    callers: int = 0
    messages: list[Message] | None = None


@dataclass
class _LoopState:
    budget: asyncio.Semaphore
    flights: dict[FlightKey, _Flight] = field(default_factory=dict)


class AggregateReadMiddleware:
    """Bound and coalesce `AGGREGATE_READ_ROUTES` reads (see the module docstring).

    State is kept per event loop, and every check-and-update of it runs without
    an intervening await, so the loop's single thread is its lock.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._states: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _LoopState] = (
            weakref.WeakKeyDictionary()
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not is_aggregate_read(scope):
            await self.app(scope, receive, send)
            return
        # Include queue time in the deadline. The projection itself runs in a
        # cancellable process so expiry also stops SQL and Python CPU work.
        deadline = DEPTH_READ_TIMEOUT_SECONDS if _depth_read(scope) else None
        timeout = asyncio.timeout(deadline)
        try:
            async with timeout:
                messages = await self._coalesced(self._state(), _flight_key(scope), scope, receive)
        except TimeoutError:
            if deadline is None or not timeout.expired():
                raise
            response = JSONResponse(
                {"detail": "Depth projection deadline exceeded"},
                status_code=503,
                headers={"Retry-After": str(max(1, math.ceil(deadline)))},
            )
            await response(scope, receive, send)
            return
        for message in messages:
            await send(message)

    def _state(self) -> _LoopState:
        loop = asyncio.get_running_loop()
        state = self._states.get(loop)
        if state is None:
            pool = to_thread.current_default_thread_limiter().total_tokens
            state = _LoopState(budget=asyncio.Semaphore(aggregate_read_budget(int(pool))))
            self._states[loop] = state
        return state

    async def _coalesced(
        self, state: _LoopState, key: FlightKey, scope: Scope, receive: Receive
    ) -> list[Message]:
        flight = state.flights.get(key)
        if flight is None:
            flight = state.flights[key] = _Flight()
        started_at_arrival = flight.started
        flight.callers += 1
        try:
            async with flight.lock:
                # Share a successful read only if it started after this caller
                # arrived. A cancelled or failed read leaves no result to share.
                if flight.started == started_at_arrival or flight.messages is None:
                    flight.started += 1
                    flight.messages = None
                    flight.messages = await self._run(state, scope, receive)
                return flight.messages
        finally:
            flight.callers -= 1
            if not flight.callers:
                del state.flights[key]

    async def _run(self, state: _LoopState, scope: Scope, receive: Receive) -> list[Message]:
        messages: list[Message] = []

        async def capture(message: Message) -> None:
            messages.append(message)

        async with state.budget:
            await self.app(scope, receive, capture)
        return messages

