---
description: "Mitmproxy session capture: setup, CA cert install, FoxyProxy config, login capture workflow, troubleshooting"
---

# Mitmproxy Session Capture

Intercept browser traffic to capture authenticated sessions (cookies, tokens, headers) into the engagement's backend credential store for use by engagement agents. Capture is append-only and multi-identity — each distinct login becomes its own identity row rather than overwriting whatever was captured before.

## Quick Start

```bash
vigil mitmproxy start
```

`vigil mitmproxy start` takes **no engagement key**. One shared proxy serves
every active engagement at once and routes each captured flow to the matching
engagement by hostname (see "How It Works"). Capture is a per-engagement policy,
not a launch-time selector.

## Browser Proxy Setup (FoxyProxy)

1. Install FoxyProxy browser extension
2. Add a new proxy:
   - **Type: HTTP** (not HTTPS -- this is the most common mistake)
   - **Host:** `127.0.0.1`
   - **Port:** `8080`
   - Do NOT set anything in the HTTPS/SSL proxy field
3. Enable the proxy profile

**Why HTTP, not HTTPS?** The browser sends a plaintext HTTP `CONNECT` request to the proxy, which then handles TLS interception internally. Setting the proxy type to HTTPS double-wraps TLS around the CONNECT tunnel, which breaks mitmproxy's interception.

## CA Certificate Installation (First Time Only)

The CA cert must be trusted by your browser/OS for HTTPS interception to work.

### Option A: Browser Install

1. With the proxy active, navigate to **http://mitm.it** (note: **http**, not https)
2. If the page says "traffic is not passing through mitmproxy" -- verify FoxyProxy is set to HTTP mode
3. Download the macOS certificate
4. Open **Keychain Access** > search `mitmproxy`
5. Double-click the cert > expand **Trust** > set to **Always Trust**
6. **Quit and reopen your browser** (browsers cache cert decisions per session)

### Option B: Terminal Install

```bash
docker cp vigil-proxy:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem
```

`vigil mitmproxy cert` prints the same commands for the active Docker-managed proxy.

Restart the browser after trusting.

### CA Key Persistence

The launcher stores CA keys in a named Docker volume (`mitmproxy-ca`). Container restarts and rebuilds reuse the same CA keys, so you only need to install and trust the certificate once.

If you need to regenerate the CA (e.g., compromise, rotation):
```bash
docker volume rm mitmproxy-ca
vigil mitmproxy start
# Re-install the new cert using Option A or B above
```

## Login Capture Workflow

1. Start the shared proxy (no engagement key): `vigil mitmproxy start` — it routes captures to whichever active engagement owns the hostname
2. Configure browser proxy (see above)
3. Navigate to the target login page and authenticate
4. Browse a few authenticated pages (admin, settings, API endpoints)
5. The proxy addon auto-detects login flows and POSTs the captured cookies/tokens to the engagement's backend credential store, which derives an identity name from the session-anchor material and appends or refreshes accordingly (see "Multi-Identity Capture" below)
6. Disable the proxy in FoxyProxy when done

If auto-capture misses the session (addon error, non-standard login flow):
- Check proxy logs: `vigil logs mitmproxy --lines 30`
- Fall back to manual cookie extraction from browser DevTools

To capture a second account for cross-account testing, repeat steps 2-5 logged
in as the other user through the same proxy — the addon detects the different
session-anchor material and appends a new identity instead of overwriting the
first.

## Multi-Identity Capture (append-only)

Each captured login becomes its own identity in the credential store. The
backend derives an opaque identity name server-side from the capture's
session-anchor cookies (`sid`, `sessionid`, `jsessionid`, `connect.sid`,
`laravel_session`, ... case-insensitive) or a JWT `sub`/`uid`/`user_id`/`email`
claim — never from raw high-entropy cookies in general, since a shared
per-CDN/load-balancer cookie (`AWSALB`) would otherwise merge two accounts and a
rotating anti-CSRF cookie would otherwise churn a fresh identity on every
reload. Reloading an already-captured login refreshes that one identity in
place; logging in as a different account appends a new identity — the property
cross-account IDOR/BOLA testing depends on. Anonymous/pre-login traffic (a
consent-banner cookie, no session material yet) carries no anchor and is never
captured.

List what's stored for a host, and which identity is active:

```bash
vigil assess auth list --host <host> [--include-dead] [--json]
```

Each row shows the identity name, `auth_context`, `state`, liveness verdict,
age, and cookie *names* only — never raw values; the active identity is marked
`*`. A session with no fresh capture for 8h is flagged `stale` (advisory — not
dead); one with no fresh capture for 5 days is purged. Age alone never marks an
identity `dead` — only a proven-dead liveness probe does (next section).

## Per-Identity Liveness

Keepalives (below) defeat the *idle* clock; they don't tell you whether a
session has already died (logout, absolute-lifetime expiry, server-side
revocation). Prove liveness explicitly before trusting a captured identity and
before recording a "dead"/"unreachable" verdict against it:

```bash
vigil assess auth-status --probe --identity <name> --probe-url <authed-url>
```

The probe never follows redirects and returns a real verdict only once that
identity has a declared `material.liveness = {expect_status, authed_marker,
dead_marker}` oracle (set via `vigil auth import`/`edit`) — a transport error
or a missing signature returns `unknown`, never a false verdict. `live` clears
a `stale` mark; `dead` is written only by this probe, never by hand and never
by age alone. Liveness is per-identity and LLM/operator-owned: whoever takes an
identity for a task probes it before trusting it, and re-probes on a
401/403/redirect-to-login shape.

## Keeping a Captured Session Alive (Keepalives)

A captured session is not static — it idle-times-out. Enterprise auth stacks
(F5 BIG-IP APM, SiteMinder, Okta) enforce **two** clocks: a short **idle timeout**
(commonly ~15–30 min of no activity) and a longer **absolute lifetime** (often
several hours). The failure mode operators hit repeatedly: a long dispatch, or a
gap *between* dispatches, lets the idle clock expire, and every subsequent probe
comes back as a soft `HTTP 2xx/3xx` session-expired page (e.g. CMS portal returns
`203 {"sessionExpired":"true"}`) — a silent false-negative that looks like
"fail-closed" but just means "your session went stale."

**The key mechanic: activity resets the idle clock.** Modern SPAs call a
session-extend on essentially every XHR (the CMS portal's Angular
`SessionInterceptor` invokes `oktaSessionExtend()` on each request). So **any**
successful authenticated request slides the idle window forward. A session that
would die in 20 idle minutes stays live for the full multi-hour absolute lifetime
**as long as you touch it periodically**.

**Technique — periodic keepalive probe.** Fire one benign, READ-ONLY authenticated
request every N minutes, where N is comfortably under the idle timeout (every
~5–10 min is safe for a 15–30 min idle window):

```bash
# bare top-level curl through the credential store — NOT wrapped in bash -c
vigil assess kali exec --identity <name> \
  --technique AUTH --intent "session keepalive" --probe-kind fingerprint \
  --phase <phase> --timeout 30 \
  -- curl -sS -i https://<host>/<lightweight-authed-read> \
     -H 'Xhr_Request: true' -H 'Accept: application/json' \
     -H 'X-Bug-Bounty: <handle>' -H 'X-Bug-Bounty-Program: <program>' \
     --resolve <host>:443:<pin-ip>
```

Pick the cheapest state-non-mutating read as the keepalive target — a
`whoami` / `user/profile` / `session` / `role/summary`-style endpoint. Confirm a
`200` with the expected identity in the body; a session-expired soft page means
the absolute lifetime was hit and you must re-authenticate.

**Why this matters for future engagements:**
- It converts a fragile 15–30-minute testing window into a **stable multi-hour
  session**, so long specialist dispatches and serialized one-at-a-time portal
  runs don't die mid-flight and burn a context window on a false negative.
- During an *active* dispatch the specialist's own probes are the keepalive; the
  real risk is the **idle gap between dispatches** — fire one operator keepalive
  in that gap (a Core-Loop step-7 credential-validation carve-out: a single
  authenticated GET) to hand the next dispatch a warm session.
- Multi-account cross-user tests (BOLA/BFLA needing two live sessions
  simultaneously) are only feasible if **both** captured identities stay warm —
  keepalive each named identity.

**When keepalives are not enough — self-service re-auth.** Once the absolute
lifetime is hit, only a fresh login helps. If the program mailbox is a configured
Mail.app account, `vigil email <mailbox> --from <sender> --extract` retrieves the
short-lived MFA/verification code, so an operator with the account password can
drive a fresh login (through the proxied browser, which re-captures) rather than
blocking on the user. Keep credentials out of durable notes; pull the code
on-demand.

**Caveats:**
- The keepalive **must** be a bare top-level `curl` under `--identity` — a
  `bash -c`/`sh -c` wrapper sends the injected `Cookie`/`Authorization` to the
  shell, so the inner curl runs unauthenticated and the "keepalive" actually
  reports the session as expired (a self-inflicted false negative).
- A genuine **logout** (not idle timeout) still kills the session immediately;
  keepalives only defeat the idle clock. Don't navigate the proxied browser to a
  logout URL while a session is in use.
- Keep the keepalive **read-only** so it never mutates state or notifies a
  human queue (e.g. an approver inbox).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `http://mitm.it` says "traffic not passing through mitmproxy" | FoxyProxy is set to HTTPS mode -- change to HTTP |
| Certificate errors after proxy restart | Check if the `mitmproxy-ca` volume exists: `docker volume ls \| grep mitmproxy`. If missing, the CA was regenerated -- re-install the cert |
| Proxy container exits immediately | Check logs: `vigil logs mitmproxy --lines 20`. Common: port 8080 already in use |
| Credentials not updated after login (`vigil auth status` still anonymous) | Check for addon errors in logs. The `_detect_login` function looks for `set-cookie` headers and token fields in response bodies |
| Browser still shows cert errors after trusting | Quit browser fully and reopen. macOS may also need: System Settings > Network > clear DNS cache |

## Container Management

```bash
# Status
vigil mitmproxy status

# Logs
vigil logs mitmproxy --lines 80

# Stop
vigil mitmproxy stop

# Restart (reuses same CA cert from volume)
vigil mitmproxy start

# Custom port
vigil mitmproxy start --port 9090
```

## How It Works

The proxy runs `mitmdump` with `proxy_addon.py`, which:
- **Serves every active engagement from one shared, selector-less proxy.**
  `vigil mitmproxy start` takes no engagement key. The addon keeps a registry of
  all in-progress engagements (synced from the orchestrator, with a filesystem
  `scope.json` scan as fallback) and routes each captured flow to the
  best-matching engagement **by hostname** — literal scope hosts beat wildcards,
  narrower wildcards beat broader ones, and an `out_of_scope` carve-out (host,
  URL, or CIDR) always drops the flow. A host no engagement claims is not
  captured. This is why capture is a per-engagement **policy**, not a launch-time
  selector.
- **Injects program-mandated attribution headers on outbound in-scope
  requests.** For an engagement whose `scope.json` declares `required_headers`
  (e.g. a BugCrowd program that mandates `X-Bug-Bounty: <handle>`), the addon
  adds those headers to each in-scope request it forwards — the same
  `required_headers` the tool-exec path injects (ADR 0010), now applied to
  browser/proxied traffic too. This makes **manual browsing and login capture
  through FoxyProxy ROE-compliant** without you setting the header per request.
  It is gated by the same hostname scope + `out_of_scope` carve-out as capture
  (out-of-scope hosts get nothing) and is non-destructive — a header the client
  already set is never overwritten. Engagements without `required_headers` are
  unaffected. Run `vigil mitmproxy routes` to see which headers each engagement
  will inject.
- Filters noise (analytics, CDNs, tracking pixels)
- Classifies requests by type (API, form, page, JS, GraphQL, WebSocket, etc.)
- Detects login flows and POSTs captured session material to the backend credential store, which derives the identity name from the capture's session-anchor material so distinct logins append rather than overwrite (see "Multi-Identity Capture" above)
- Records intercepted traffic to `cases.db` for work-buffer ingestion
- Posts request observations to the orchestrator backend (when available)
- When an engagement's capture policy is enabled, additionally persists the
  **full request/response flow** — body sidecars + a JSONL flow index under the
  engagement root — and posts a compact flow record to the backend (see below)

## Full-Flow Capture Policy

Beyond the compact request-observation + `cases.db` snippet the addon always
records, each engagement has an opt-in **full-flow capture policy**. When
enabled, the addon writes the raw request/response bodies as engagement-local
sidecars and a JSONL flow index, and posts a compact per-flow record (sha256s,
byte counts, truncation flags, timing, auth context, and host-mismatch
telemetry) to the backend `POST .../assessment/http-flows` ingest route.

**Raw-body capture is OFF by default.** Restarting the shared proxy never
silently changes capture behavior; you must turn it on per engagement.

For the full `vigil assess http policy` command reference (inspecting,
enabling/scoping, and disabling raw-body capture), run `vigil assess contract
http`.

The policy is authoritative in the backend and mirrored to
`capture-policy.json` next to `scope.json` in the engagement root, so the shared
proxy honors it even when the orchestrator registry fetch is unavailable.

On-disk layout (engagement-root-relative), written only while capture is enabled:

```
traffic/mitmproxy/bodies/<sha256>.bin   # one file per distinct stored body
traffic/mitmproxy/flows/<YYYY-MM-DD>.jsonl  # one JSON line per captured flow
```

Bodies larger than `max-body-bytes` are truncated on disk with the truncation
flag set honestly in both the JSONL index and the backend record. Query or
export captured flows with the `vigil assess http` verbs (`list` / `show` /
`search` / `export-har` / `import-har`; run `vigil assess contract http` for the
full reference) — these wrap the backend `GET .../assessment/http-flows` routes
so query-string details stay out of operator instructions.
