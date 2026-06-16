---
name: gf-patterns:websocket
description: WebSocket and real-time transport endpoint patterns (/ws, /socket.io, /stomp, /mqtt)
origin: local overlay (no upstream gf equivalent)
bucket: websocket
weight: 30
---

# gf: websocket

## What this bucket classifies

WebSocket and real-time message-transport upgrade paths where an attacker can exploit
cross-site WebSocket hijacking (CSWSH), missing origin validation, IDOR over channel/room
IDs, or injection via message payloads.

## Load this reference when

- The corpus contains `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/stomp`, or `/mqtt` paths
- Param keys `channel`, `room`, or `topic` appear in the initial handshake query string
- Operator is assessing real-time features (chat, notifications, live dashboards, IoT bridges)

## Parameter keys that match

`channel, room, topic`

These are the common handshake query-string keys for multiplexed WebSocket sessions. They are
rarely set as HTTP body or path params, but `collect_keys` normalizes all three param columns.

## Path patterns that match

`/ws`, `/wss`, `/websocket`, `/socket.io`, `/sockjs`, `/stomp`, `/mqtt`

`/ws` is boundary-anchored via `_fragment_pattern` (which appends `_FRAGMENT_BOUNDARY`):
it matches `/ws` and `/ws/feed` but NOT `/wsdl` or `/wsus` (next character after `ws`
is not a boundary character).

## Weight and priority interpretation

- Baseline priority score: 30
- Path alone does not confirm exploitability — a WebSocket upgrade path may require a valid
  session or JWT; specialist dispatch at 30 is correct before confirming unauthenticated access
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/ws` — bare WebSocket upgrade endpoint
- `https://target.example/ws/feed` — namespaced feed channel
- `https://target.example/websocket` — explicit path alias
- `https://target.example/socket.io/?EIO=4&transport=websocket` — Socket.IO endpoint
- `https://target.example/sockjs/websocket` — SockJS compatibility shim
- `https://target.example/stomp/ws` — STOMP-over-WebSocket broker endpoint
- `https://target.example/mqtt` — MQTT-over-WebSocket (IoT bridge)
- `https://target.example/realtime?channel=user-events` — param-key match via `channel`
- `https://target.example/chat?room=support-1234` — room-scoped WebSocket connection

## What it does NOT classify

- `/wsdl` (SOAP WSDL) — next character after `ws` is `d`, not a boundary; deliberately excluded
- `/wsus` (Windows Update Services) — same boundary exclusion
- Long-polling REST endpoints that simulate real-time with polling (`?poll=1`) — no WebSocket
  upgrade path; those fall to `ssrf`/`idor` or the path fallback based on their params

## Attack classes

- **Cross-site WebSocket hijacking (CSWSH):** the WS handshake is an HTTP GET with session
  cookies but no CSRF token; an attacker page can open a WS connection as the victim
- **Missing origin validation:** server accepts `Origin: https://evil.example` without checking
  against an allow-list; pair with CSWSH for full data exfiltration
- **IDOR via channel/room ID:** `channel=user-1024` can be swapped to another user's channel
  ID to subscribe to their event stream
- **Message-payload injection:** if the server template-renders or SQL-queries using
  WebSocket message content, standard injection classes apply over the persistent channel

## Sources

- [PortSwigger — WebSocket security vulnerabilities](https://portswigger.net/web-security/websockets)
- [OWASP — Testing WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)

## Related

- `agent/references/gf-patterns/idor.md` — channel/room ID as object reference (BOLA over real-time)
- `agent/references/gf-patterns/cors.md` — origin-validation failure is the WebSocket analog of CORS
- `agent/references/gf-patterns/graphql.md` — GraphQL-over-WebSocket upgrade paths also fire this bucket
