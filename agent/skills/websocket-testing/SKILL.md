---
name: websocket-testing
description: Test WebSocket endpoints for authentication bypass, injection, cross-site hijacking, and message manipulation
origin: Vigil
vuln_class: websocket
---

# WebSocket Security Testing

## When to Activate

- `ws://`/`wss://` endpoints or `Upgrade: websocket` traffic: chat, notifications, live updates,
  trading, collaborative editing. Find them in bundles with `rg "new WebSocket|\.connect\(.*ws"`
  (`agent/skills/source-analysis/SKILL.md`).

`--technique WEBSOCKET` for protocol, auth and CSWSH probing; the specific class (`SQLI`, `XSS`,
`CMDI`, `IDOR`, `AUTH`) when a frame carries that payload. The runtime image ships no websocat;
script the client in Python with the system `aiohttp` (`ClientSession().ws_connect(url,
headers={…}, origin=…)`) and run it via `vigil assess kali exec --technique WEBSOCKET --intent
"<purpose>" --probe-kind payload --phase consume-test --timeout 60 --identity-env A=user_a --
python3 <script>` so the identity's `$VIGIL_COOKIE_A` is available to it
(`agent/skills/write-probe-script/SKILL.md`). Browser-side behaviour: `vigil assess kali browser`.

## Checks

1. **Handshake auth:** connect with no cookie or token, an expired one, and another user's; check
   whether authorization is re-checked per message after the session expires or the role changes.
2. **Authorization in frames:** other users' IDs, room/channel IDs and unauthorized subscriptions
   (`{"subscribe":"admin-events"}`); the IDOR method is `agent/skills/idor-testing/SKILL.md`.
   Open two connections as two owned identities and compare what each receives: broadcasts that
   carry the other user's data are a leak even without any injection.
3. **Injection in frame fields** with the class skills (SQLi, NoSQL, command injection, XSS). XSS
   that renders to other users needs the side-effect preflight (`agent/shared-constraints.md`
   §2d).
4. **Message handling:** replay (nonce/sequence checks), out-of-order and binary tampering,
   malformed JSON for verbose errors.
5. **Resource limits** (many connections, message floods, oversized frames, idle timeouts) are
   denial of service: one bounded probe within the ROE and operator approval
   (`agent/shared-constraints.md` §1); never background connection loops.

## Cross-Site WebSocket Hijacking (CSWSH)

The handshake carries cookies but no CSRF token, so Origin validation is the only defence; a
hijacked socket is bidirectional and persistent (the attacker reads the stream and sends
commands). What to check:

- Does the upgrade request carry cookies, and with which `SameSite`? Chromium withholds `Lax`
  cookies from a cross-site handshake, so CSWSH needs `SameSite=None` cookies, a same-site
  attacker origin (a subdomain you control), or a non-Chromium victim.
- Is `Origin` validated on the handshake (send a foreign `Origin` from the script)?
- Is a per-connection ticket required in the URL that the attacker page cannot obtain? That makes
  CSWSH much harder even with a missing Origin check.
- What flows over the socket (messages, transactions, tokens) and which commands it accepts?

Proof: a PoC page on an attacker origin, loaded in a browser session of an owned victim identity,
opens the socket and receives that identity's data or performs an action.

## What to Record

Endpoint and protocol, the authentication mechanism, the vulnerability and proof frame, and the
outcome (`agent/rules/hunting.md` §2): data received that belongs to another identity, an action
performed through a hijacked socket, injection output. Severity:
`agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.
