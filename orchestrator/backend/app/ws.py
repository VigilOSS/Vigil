from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import WebSocket


def websocket_origin_allowed(origin: str | None, public_url: str) -> bool:
    """Accept browser sockets only from the configured local UI origin."""
    if not origin:
        return False
    configured = urlsplit(public_url)
    if configured.scheme not in {"http", "https"} or not configured.hostname:
        return False
    port = configured.port or (443 if configured.scheme == "https" else 80)
    hosts = {configured.hostname.lower()}
    if configured.hostname.lower() in {"127.0.0.1", "localhost", "::1"}:
        hosts.update({"127.0.0.1", "localhost", "::1"})
    allowed = {
        f"{configured.scheme}://{f'[{host}]' if ':' in host else host}:{port}"
        for host in hosts
    }
    return origin.rstrip("/").lower() in allowed


@dataclass
class _Subscriber:
    pending: asyncio.Queue
    sender: asyncio.Task | None = None


class EngagementBroadcaster:
    def __init__(self) -> None:
        self._connections: dict[str, dict[WebSocket, _Subscriber]] = defaultdict(dict)
        self._pending_limit = 64
        self._closing: set[asyncio.Task] = set()

    async def connect(self, engagement_key: str, websocket: WebSocket) -> None:
        await websocket.accept()
        subscriber = _Subscriber(asyncio.Queue(maxsize=self._pending_limit))
        self._connections[engagement_key][websocket] = subscriber
        subscriber.sender = asyncio.create_task(
            self._send(engagement_key, websocket, subscriber)
        )

    def disconnect(self, engagement_key: str, websocket: WebSocket) -> None:
        subscribers = self._connections.get(engagement_key)
        if subscribers is None:
            return
        subscriber = subscribers.pop(websocket, None)
        if subscriber and subscriber.sender and subscriber.sender is not asyncio.current_task():
            subscriber.sender.cancel()
        if not subscribers:
            self._connections.pop(engagement_key, None)

    async def _send(self, engagement_key: str, websocket: WebSocket, subscriber: _Subscriber) -> None:
        try:
            while True:
                payload = await subscriber.pending.get()
                try:
                    await websocket.send_json(payload)
                except UnicodeEncodeError:
                    # A text frame cannot encode lone surrogates; JSON escapes
                    # preserve authored values without dropping the subscriber.
                    await websocket.send_text(
                        json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            self._close_for_resync(websocket)
        finally:
            self.disconnect(engagement_key, websocket)

    def _close_for_resync(self, websocket: WebSocket) -> None:
        async def close() -> None:
            try:
                await asyncio.wait_for(
                    websocket.close(code=1013, reason="Reconnect to refresh durable state"),
                    timeout=1.0,
                )
            except Exception:
                pass
        task = asyncio.create_task(close())
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def publish(self, engagement_key: str, payload: dict) -> None:
        # Notifications trigger a read of durable state, not the mutation's commit.
        # Each browser has an ordered sender; its transport can never hold a
        # successful HTTP response open. A browser that falls behind reconnects
        # and the frontend's existing onopen handler refreshes missed state.
        for websocket, subscriber in tuple(self._connections.get(engagement_key, {}).items()):
            try:
                subscriber.pending.put_nowait(payload)
            except asyncio.QueueFull:
                self.disconnect(engagement_key, websocket)
                self._close_for_resync(websocket)


broadcaster = EngagementBroadcaster()
