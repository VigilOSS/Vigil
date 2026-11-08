"""Activity notifications preserve authored Unicode through a UTF-8 transport."""

from __future__ import annotations

import asyncio
import json

from starlette.websockets import WebSocket

from app.ws import EngagementBroadcaster


def test_surrogate_notification_preserves_subscriber_and_next_delivery():
    async def check():
        frames = asyncio.Queue()

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            # Match Uvicorn's text-frame encoding, which TestClient omits.
            if message["type"] == "websocket.send":
                message["text"].encode("utf-8")
            if message["type"] != "websocket.accept":
                await frames.put(message)

        socket = WebSocket({"type": "websocket"}, receive, send)
        broadcaster = EngagementBroadcaster()
        await broadcaster.connect("acme", socket)
        normal = {"metadata": {"note": "Acme café 😀"}}
        surrogate = {"metadata": {"notes": ["Acme \ud800", {"low": "\udfff"}]}}
        next_message = {"sequence": 3, "metadata": {"note": "Acme continuation"}}
        try:
            for payload in (normal, surrogate, next_message):
                await broadcaster.publish("acme", payload)
                frame = await asyncio.wait_for(frames.get(), 1)
                assert frame["type"] == "websocket.send", frame
                assert json.loads(frame["text"]) == payload
                if payload is normal:
                    assert frame["text"] == json.dumps(
                        payload, separators=(",", ":"), ensure_ascii=False
                    )
                if payload is surrogate:
                    assert frame["text"].isascii()
        finally:
            broadcaster.disconnect("acme", socket)

    asyncio.run(check())


def test_normal_websocket_nonfinite_number_serialization_is_unchanged():
    async def check():
        frames = asyncio.Queue()

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            if message["type"] == "websocket.send":
                message["text"].encode("utf-8")
                await frames.put(message["text"])

        socket = WebSocket({"type": "websocket"}, receive, send)
        broadcaster = EngagementBroadcaster()
        await broadcaster.connect("acme", socket)
        payload = {"metadata": {"value": float("nan")}}
        try:
            await broadcaster.publish("acme", payload)
            text = await asyncio.wait_for(frames.get(), 1)
            assert text == json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False
            )
        finally:
            broadcaster.disconnect("acme", socket)

    asyncio.run(check())
