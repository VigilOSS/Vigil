from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket


class EngagementBroadcaster:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, engagement_key: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[engagement_key].add(websocket)

    def disconnect(self, engagement_key: str, websocket: WebSocket) -> None:
        self._connections[engagement_key].discard(websocket)
        if not self._connections[engagement_key]:
            self._connections.pop(engagement_key, None)

    async def publish(self, engagement_key: str, payload: dict) -> None:
        stale: list[WebSocket] = []
        for websocket in self._connections.get(engagement_key, set()):
            try:
                await websocket.send_json(payload)
            except EngagementtimeError:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(engagement_key, websocket)


broadcaster = EngagementBroadcaster()
