# Engagement authentication

A new engagement starts with no stored credentials (anonymous). Engagement
credentials live in the orchestrator backend — the `engagement_credentials`
table, one record per `(engagement, identity)` — and are managed entirely through
the `vigil auth` CLI. There is no `auth.json` file on disk.

## Three ways to add an authenticated session

**1. Capture through the MITM proxy.** Run `vigil mitmproxy start` (one proxy
serves every active engagement) and browse through `127.0.0.1:8080`.
`proxy_addon.py` matches the captured host against each engagement's `scope.json`
and POSTs the captured cookies and headers to that engagement's credential store.

Capture is append-only and multi-identity: the identity name is derived
server-side from the login's session-anchor cookies (or a JWT `sub`), so a second
distinct login on the same host appends a new identity instead of overwriting the
first, while reloading the same login refreshes that one identity in place. No
engagement context is required at proxy-start time, and multiple engagements can
be authenticated in parallel without restarting the proxy.

**2. Import material directly.**

```bash
vigil auth import <key> --source cookies-and-headers.json
```

The JSON is the material itself — `{"cookies": {...}, "headers": {...},
"tokens": {...}}` (each optional), plus an optional `material.liveness` block. Do
**not** wrap it in `{"material": {...}}`: that wrapper is the shape an export
produces, it carries no replayable material at the top level, and the import
refuses it by name rather than storing an empty identity.

**3. Edit in place.** `vigil auth edit <key>` fetches the current identity, opens
it in `$EDITOR`, and saves it back.

## What a credential record holds

| Field | Meaning |
|---|---|
| `use_for_requests` | Whether crawling and recollection should apply the stored auth |
| `auth_context` | The label used for authenticated request variants |
| `expires_at` | Optional ISO8601 expiry timestamp |
| `state` | `available` / `stale` / `dead` / `expired` |
| freshness fields | `created_at`, `last_seen_at`, `liveness_verdict`, `last_probed_at` |
| `cookies`, `headers` | The replayable material |

## The freshness clocks

A session that has neither been re-captured nor replayed for 8h is flagged
`stale` — advisory, meaning re-probe it. After 5 days it is purged.

Both clocks read `last_seen_at`, which a resolve-for-replay refreshes as well as a
capture; otherwise an identity in constant use would still age out. Read-only
inspection does not touch it: `vigil assess auth status` without `--probe`
resolves with `record_use=false`, so looking at a session never resets the clock
the backstop exists to measure.

## Why a 403 reports `unknown`

Age never marks a session `dead` — only a proven-dead liveness probe does, and
that probe requires positive evidence: a configured `dead_marker` hit, or a
response that is itself an authentication challenge. A missing marker, an
unexplained status mismatch, and a `403` all report `unknown` and leave the
identity usable — a `403` is an authorization verdict, and on another principal's
object it is the signal you were testing for.

If auth is expired, dead, or missing, the workflow warns and continues
anonymously.

## Operator CLI

```bash
vigil auth status <engagement-key>
vigil auth show <engagement-key>
vigil auth import <engagement-key> --source cookies-and-headers.json
vigil auth set-active <engagement-key> --identity user_a
vigil auth alias <engagement-key> --name member --principal jwt:sub:user-42 --scope billing
vigil auth env-check <engagement-key> --keys APP_USER APP_PASSWORD
vigil auth clear <engagement-key>
vigil auth status --probe --identity <name> --probe-url <authed-url> --scope <logical-scope>
```

## Agent-facing surface

Agents list every stored identity for a host — name, `auth_context`, `state`,
liveness verdict, age, and cookie names (never raw values), with the active
identity marked `*`:

```bash
vigil assess auth list --host <host> [--include-dead] [--json]
```

They prove a specific identity's liveness before trusting it:

```bash
vigil assess auth status --probe --identity <name> --probe-url <authed-url> --scope <logical-scope>
```

Execute through a scoped alias with both `--identity <alias>` and
`--identity-scope <logical-scope>`. Vigil does not infer logical liveness scope
from the destination hostname.

## MITM proxy routing

The addon routes each captured response to the engagement whose `scope.json` best
matches the hostname. It ranks candidates by `(pattern_score, scope_priority)` —
a literal host beats a narrower wildcard beats a broader wildcard, and
`scope_priority` breaks ties between equal patterns.

If two engagements tie on both, the addon logs a warning naming them and **leaves
the flow unattributed** rather than guessing. Raise one engagement's
`scope_priority`, or narrow its scope roots, to disambiguate.

An explicit `out_of_scope` carve-out by a declared owner suppresses the host
entirely; it is not handed to a global bypass entry.

After creating or scope-editing an engagement, `vigil mitmproxy reload` forces the
addon to refresh its registry, and `vigil mitmproxy routes` prints the current
mapping for verification.

If you need HTTPS interception, install the mitmproxy CA certificate in the
browser or device before logging in.
