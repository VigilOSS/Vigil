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
import os
import re
import weakref
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from anyio import to_thread
from starlette.routing import compile_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_ASSESSMENT = "/engagements/{engagement_key}/assessment"

# Route templates (as registered) whose GET handlers compute an engagement-wide
# aggregate. `/summary` is not listed: it already single-flights its build
# without holding a worker (`assessment_summary_async`).
AGGREGATE_READ_ROUTES = frozenset({
    f"{_ASSESSMENT}/coverage-readiness",
    f"{_ASSESSMENT}/coverage-readiness/by-host",
    f"{_ASSESSMENT}/coverage-readiness/by-family",
    f"{_ASSESSMENT}/report-readiness",
    f"{_ASSESSMENT}/phase-readiness",
    f"{_ASSESSMENT}/resume-brief",
    f"{_ASSESSMENT}/application-units/depth-ledger",
    f"{_ASSESSMENT}/application-units/terminal-block",
    f"{_ASSESSMENT}/code/readiness",
    f"{_ASSESSMENT}/code/coverage",
    f"{_ASSESSMENT}/code/coverage/by-path",
    f"{_ASSESSMENT}/code/coverage/inherited",
    f"{_ASSESSMENT}/code/repos/review-progress",
})

DEFAULT_AGGREGATE_READ_WORKERS = 3


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


@dataclass(eq=False)
class _Flight:
    done: asyncio.Event = field(default_factory=asyncio.Event)
    # The response every request sharing this flight receives; None when the
    # flight did not complete, and each of its joiners then runs on its own.
    messages: list[Message] | None = None


@dataclass(eq=False)
class _LoopState:
    budget: asyncio.Semaphore
    running: dict[FlightKey, _Flight] = field(default_factory=dict)
    queued: dict[FlightKey, _Flight] = field(default_factory=dict)


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
        for message in await self._coalesced(self._state(), _flight_key(scope), scope, receive):
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
        running = state.running.get(key)
        if running is None:
            flight = _Flight()
            state.running[key] = flight
            return await self._lead(state, key, flight, scope, receive)
        queued = state.queued.get(key)
        if queued is not None:
            await queued.done.wait()
            if queued.messages is not None:
                return queued.messages
            return await self._run(state, scope, receive)
        flight = _Flight()
        state.queued[key] = flight
        try:
            # The running flight started before this request arrived; its
            # finish promotes this one to running.
            await running.done.wait()
        except BaseException:
            self._abandon(state, key, flight)
            raise
        return await self._lead(state, key, flight, scope, receive)

    async def _lead(
        self, state: _LoopState, key: FlightKey, flight: _Flight, scope: Scope, receive: Receive
    ) -> list[Message]:
        try:
            flight.messages = await self._run(state, scope, receive)
            return flight.messages
        finally:
            self._finish(state, key, flight)

    @staticmethod
    def _finish(state: _LoopState, key: FlightKey, flight: _Flight) -> None:
        """Hand the key to the flight queued behind *flight*, then release its joiners."""
        if state.running.get(key) is flight:
            successor = state.queued.pop(key, None)
            if successor is None:
                del state.running[key]
            else:
                state.running[key] = successor
        flight.done.set()

    def _abandon(self, state: _LoopState, key: FlightKey, flight: _Flight) -> None:
        """A queued leader was cancelled: its joiners run on their own."""
        if state.queued.get(key) is flight:
            del state.queued[key]
            flight.done.set()
        else:
            # Already promoted to running: pass the key on as a finish would.
            self._finish(state, key, flight)

    async def _run(self, state: _LoopState, scope: Scope, receive: Receive) -> list[Message]:
        messages: list[Message] = []

        async def capture(message: Message) -> None:
            messages.append(message)

        async with state.budget:
            await self.app(scope, receive, capture)
        return messages

