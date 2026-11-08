"""Durable mutation replies never wait for a browser's notification transport."""
from __future__ import annotations

import asyncio

from app.ws import EngagementBroadcaster


class Socket:
    def __init__(self, *, blocked: bool = False):
        self.release = asyncio.Event()
        if not blocked:
            self.release.set()
        self.sent = []
        self.delivered = asyncio.Event()
        self.closed = asyncio.Event()
        self.close_code = None

    async def accept(self):
        pass

    async def send_json(self, payload):
        await self.release.wait()
        self.sent.append(payload)
        self.delivered.set()

    async def close(self, *, code, reason=""):
        self.close_code = code
        self.closed.set()


def test_a_slow_browser_does_not_hold_replies_or_other_browsers():
    async def check():
        broadcaster = EngagementBroadcaster()
        slow, fast = Socket(blocked=True), Socket()
        await broadcaster.connect("acme", slow)
        await broadcaster.connect("acme", fast)
        try:
            await asyncio.wait_for(broadcaster.publish("acme", {"sequence": 1}), 0.2)
            await asyncio.wait_for(broadcaster.publish("acme", {"sequence": 2}), 0.2)
            await asyncio.wait_for(fast.delivered.wait(), 0.2)
            # The independent sender drains in order without delaying writes.
            await asyncio.sleep(0)
            assert fast.sent == [{"sequence": 1}, {"sequence": 2}]
            assert slow.sent == []
        finally:
            broadcaster.disconnect("acme", slow)
            broadcaster.disconnect("acme", fast)
    asyncio.run(check())


def test_a_backlogged_browser_is_disconnected_for_durable_state_resync():
    async def check():
        broadcaster = EngagementBroadcaster()
        broadcaster._pending_limit = 2
        slow = Socket(blocked=True)
        await broadcaster.connect("acme", slow)
        for sequence in range(4):
            await asyncio.wait_for(broadcaster.publish("acme", {"sequence": sequence}), 0.2)
        await asyncio.wait_for(slow.closed.wait(), 0.2)
        assert slow.close_code == 1013
        # A fresh subscription receives future notifications normally.
        recovered = Socket()
        await broadcaster.connect("acme", recovered)
        try:
            await broadcaster.publish("acme", {"sequence": 4})
            await asyncio.wait_for(recovered.delivered.wait(), 0.2)
            assert recovered.sent == [{"sequence": 4}]
        finally:
            broadcaster.disconnect("acme", recovered)
    asyncio.run(check())


def test_connections_can_change_while_an_earlier_send_is_pending():
    async def check():
        broadcaster = EngagementBroadcaster()
        slow = Socket(blocked=True)
        await broadcaster.connect("acme", slow)
        publication = asyncio.create_task(broadcaster.publish("acme", {"sequence": 1}))
        await asyncio.sleep(0)
        newcomer = Socket()
        await broadcaster.connect("acme", newcomer)
        slow.release.set()
        try:
            await publication
            await broadcaster.publish("acme", {"sequence": 2})
            await asyncio.wait_for(newcomer.delivered.wait(), 0.2)
            assert newcomer.sent == [{"sequence": 2}]
        finally:
            broadcaster.disconnect("acme", slow)
            broadcaster.disconnect("acme", newcomer)
    asyncio.run(check())
