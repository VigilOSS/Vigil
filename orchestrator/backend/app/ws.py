from __future__ import annotations

from collections import defaultdict
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
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(engagement_key, websocket)


broadcaster = EngagementBroadcaster()
