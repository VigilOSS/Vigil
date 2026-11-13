---
description: "Vigil's shared mitmproxy: start, browser proxy and CA trust, login capture into the multi-identity credential store, liveness and keepalives, hostname routing, attribution headers, full-flow capture policy"
---

# Mitmproxy Session Capture

Vigil's shared mitmproxy intercepts browser traffic and captures authenticated sessions (cookies,
tokens, headers) into the engagement's backend credential store. Capture is append-only and
multi-identity: each distinct login becomes its own identity row instead of overwriting the last.

## Quick Start

```bash
vigil mitmproxy start            # --port <n> to bind another host port (default 8080)
```

`vigil mitmproxy start` takes no engagement key. One shared proxy serves every active engagement
and routes each captured flow to the owning engagement by hostname ("How It Works"). A host no
engagement claims falls back to the `vigil use` / launcher-selected engagement only when its
`scope.json` declares `scope_enforcement: bypass`. Capture is a per-engagement policy, not a
launch-time selector. `vigil mitmproxy status | stop | routes | reload` and
`vigil logs mitmproxy --lines 80` manage it.

## Browser proxy and CA trust

- Set the browser proxy (FoxyProxy or similar) to type **HTTP**, `127.0.0.1:8080`, with nothing in
  an HTTPS/SSL proxy field. An HTTPS proxy type wraps TLS around the `CONNECT` tunnel and breaks
  interception; it is the usual cause of `http://mitm.it` saying traffic is not passing through
  mitmproxy.
- Trust the CA once: `vigil mitmproxy cert` prints the `docker cp` and macOS keychain-trust
  commands for the running proxy (or download it from `http://mitm.it` with the proxy active).
  Quit and reopen the browser afterwards; browsers cache certificate decisions per session.
- The CA keys live in the `mitmproxy-ca` Docker volume, so restarts and rebuilds keep the same CA.
  Certificate errors after a restart mean the volume is gone and the CA was regenerated; re-trust
  it. To rotate deliberately: `docker volume rm mitmproxy-ca`, then `vigil mitmproxy start` and
  re-trust.
- A proxy container that exits immediately usually means port 8080 is taken; check
  `vigil logs mitmproxy --lines 20`.

## Login Capture Workflow

1. `vigil mitmproxy start`. For a global-bypass engagement, select it first with `vigil use <key>`
   so otherwise-unclaimed hosts have an explicit owner.
2. Point the browser at the proxy, log in to the target, and browse a few authenticated pages
   (admin, settings, API calls).
3. The addon detects the login flow and posts the session material to the credential store, which
   derives the identity name and appends or refreshes ("Multi-Identity Capture").
4. Turn the browser proxy off when done.

If `vigil auth status` still shows anonymous after a login, read `vigil logs mitmproxy --lines 30`
for addon errors; the detector keys on `set-cookie` headers and token fields in response bodies, so
a non-standard login flow can need manual extraction from DevTools and `vigil auth import`. To
capture a second account for cross-account testing, repeat the login as the other user through the
same proxy.

## Multi-Identity Capture (append-only)

The backend derives an opaque identity name from the capture's session-anchor cookies (`sid`,
`sessionid`, `jsessionid`, `connect.sid`, `laravel_session`, ... case-insensitive) or a JWT
`sub`/`uid`/`user_id`/`email` claim, never from high-entropy cookies in general: a shared
load-balancer cookie (`AWSALB`) would merge two accounts and a rotating anti-CSRF cookie would mint
a fresh identity on every reload. Reloading a captured login refreshes that identity in place;
logging in as a different account appends a new one, which cross-account IDOR/BOLA testing depends
on. Pre-login traffic (a consent-banner cookie, no session material) carries no anchor and is never
captured.

```bash
vigil assess auth list --host <host> [--include-dead] [--json]
```

Rows show identity name, `auth_context`, `state`, liveness verdict, age, and cookie names; the
active identity is marked `*`. No fresh capture for 8h flags an identity `stale` (advisory); 5 days
purges it. Age alone never marks an identity `dead`.

## Per-Identity Liveness

```bash
vigil assess auth status --probe --identity <name> --probe-url <authed-url>
```

Prove liveness before trusting a captured identity and before recording a dead or unreachable
verdict against it; re-probe on a 401, 403 or redirect-to-login shape. The probe never follows
redirects and returns a real verdict only once the identity has a `material.liveness =
{expect_status, authed_marker, dead_marker}` oracle (set with `vigil auth import` or `edit`); a
transport error or missing signature returns `unknown`. `live` clears `stale`; only this probe
writes `dead`.

## Keeping a Captured Session Alive (Keepalives)

Enterprise auth stacks (F5 BIG-IP APM, SiteMinder, Okta) enforce a short idle timeout (often 15–30
minutes) and a longer absolute lifetime (often several hours). When the idle clock expires during a
long dispatch or in the gap between dispatches, every later probe gets a soft 2xx/3xx
session-expired page (for example `203 {"sessionExpired":"true"}`): a silent false negative that
reads like fail-closed. Any successful authenticated request resets the idle clock, since SPAs
typically call a session-extend on every XHR, so periodic touches keep a session warm for its whole
absolute lifetime.

`vigil auth keepalive <engagement> --anchor-cookie <name> --probe-url <authed-read> --detach` does
this: one read-only authenticated GET per identity per `--interval` (keep it under the idle window),
routed through `vigil assess kali exec` for audit and identity injection, with a LIVE/DEAD verdict
logged to `<engagement>/tools/keepalive.log`. `vigil auth keepalive --help` has the rest.

- Pick the cheapest state-free read (`whoami`, `user/profile`, `session`) so the keepalive never
  mutates state or notifies a human queue such as an approver inbox. Confirm a 200 with the expected
  identity in the body.
- During an active dispatch the specialist's own probes keep the session warm; the risk is the idle
  gap between dispatches. The operator covers that gap with `vigil auth keepalive`: one read-only
  authenticated GET per identity, an operator-executed exception of the same kind as credential
  auto-use validation. Cross-user BOLA/BFLA tests need both identities warm.
- Keepalives defeat only the idle clock. A real logout kills the session at once, so never send the
  proxied browser to a logout URL while a session is in use, and a same-user browser re-login ends
  the prior session.
- Once the absolute lifetime is hit, only a fresh login helps. If the program mailbox is a
  configured Mail.app account, `vigil email <mailbox> --from <sender> --extract` retrieves the MFA
  or verification code so an operator with the password can log in again through the proxied
  browser, which re-captures. Keep credentials out of durable notes.

## How It Works

The proxy runs `mitmdump` with `proxy_addon.py`, which:

- **Routes every flow by hostname across all active engagements.** The addon keeps a registry of
  in-progress engagements (synced from the orchestrator, with a filesystem `scope.json` scan as
  fallback). Literal scope hosts beat wildcards and narrower wildcards beat broader ones. An
  `out_of_scope` carve-out (host, URL, or CIDR) leaves the flow unowned for capture. When no
  hostname pattern claims a host, the addon consults `<engagements_root>/.active` and binds the flow
  only if that engagement declares `scope_enforcement: bypass`; a normal hostname owner always wins,
  so a selected bypass engagement cannot take another engagement's traffic. Ownership never blocks
  the proxied request or replaces its response.
- **Injects program-mandated attribution headers** (`scope.json` `required_headers`, such as
  `X-Bug-Bounty: <handle>`) on outbound in-scope requests, the same set the tool-exec path injects,
  so manual browsing and login capture are ROE-compliant without setting headers by hand. It uses
  the same engagement binding as capture, never overwrites a header the client set, and
  `vigil mitmproxy routes` shows which headers each engagement injects.
- Filters analytics, CDN and tracking noise, and classifies requests (API, form, page, JS, GraphQL,
  WebSocket).
- Posts session material to the credential store ("Multi-Identity Capture").
- Posts request observations to the backend, which derives the work-buffer row
  (`assessment_work_items`) server-side in the same transaction.
- Records full-flow metadata, and body sidecars, only under the engagement's capture policy (below).

## Full-Flow Capture Policy

Beyond the compact observation and derived work item it always records, each engagement has an
opt-in full-flow policy (`vigil assess http policy set`; reference: `vigil assess contract http`):

1. `--no-enabled` (default): compact observation only.
2. `--enabled` with both body flags off: full-flow metadata in the JSONL index and backend, no bodies.
3. `--enabled` plus `--capture-request-bodies` and/or `--capture-response-bodies`: the same metadata
   plus the selected body sidecars, subject to `--max-body-bytes` and the content-type filters.

Restarting the proxy never changes capture behavior. The policy is authoritative in the backend and
mirrored to `capture-policy.json` next to `scope.json`, so the proxy honors it when the registry
fetch is unavailable. While recording is enabled the engagement root holds:

```
traffic/mitmproxy/bodies/<sha256>.bin       # one file per distinct stored body
traffic/mitmproxy/flows/<YYYY-MM-DD>.jsonl  # one JSON line per captured flow
```

Bodies over `max-body-bytes` are truncated on disk, with the truncation flag set in both the JSONL
index and the backend record. Query or export flows with `vigil assess http list | show | search |
export-har | import-har`.
