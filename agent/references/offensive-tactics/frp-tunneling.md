---
description: "`vigil oob` frp/interactsh setup, per-agent OOB clients, tunnel logging, reverse shell and OOB DNS/HTTP callback conventions — paired with `agent/skills/exploit-playbook-authoring/SKILL.md` for playbook authoring conventions"
skill: exploit-playbook-authoring
---

# FRP Tunneling & OOB Callbacks

## Overview

frp exposes local runtime services to remote targets. interactsh records out-of-band callbacks
for blind SSRF, XXE, command injection, SQLi, Log4Shell-style probes, and similar tests.

FRP tunnels, listeners, and OOB callback servers are **operator-controlled shared
infrastructure**. Agents must not start, stop, restart, or reconfigure shared
`frpc` / `oob-server` sessions because those sessions are global runtime state.

Agents do their own OOB readiness checks and per-agent client handling through
`vigil`. This keeps routine status/log checks out of the operator loop while
preserving the operator boundary for shared infrastructure and secrets.

Traffic path:

```text
Internet -> Caddy/TLS -> frps -> frpc in vigil -> interactsh or local listener
Internet -> frps TCP/UDP port -> frpc in vigil -> local runtime service
```

DNS is the primary OOB signal because most blind vulnerabilities resolve DNS before attempting
HTTP. HTTP callbacks are useful when target egress allows them, but DNS hits are usually the
earliest proof.

## One-Time External Prerequisites

DNS and the frp server are outside the local CLI:

- Delegate the OOB zone with an NS record such as `oob NS <frp-host>`. The NS
  value MUST be the frp host's NAME, never a raw IP — a hostname lets the delegation track
  the frp host's address automatically (its A record is kept current by the EC2→Route53
  dynamic-DNS Lambda). A literal-IP NS silently breaks every interactsh client with
  `no address found for host` once the frp host's IP changes.
- Keep wildcard HTTP routing for the frp HTTP domain, such as `*.<frp-http-domain>`.
- Allow the frps bind port, OOB DNS UDP 53, HTTP/HTTPS, and any listener ports on the server
  security group.

Store the frp token in `vigil config`, not tracked docs — secrets in version control are a leak vector.

## Local Configuration

Configure once per workstation or install:

```bash
vigil config set oob.frp_host <frp-host>
vigil config set oob.frp_port 7000
vigil config set oob.domain <configured-oob-domain>
vigil config set oob.frp_token <token>
```

After both endpoints are configured, installation persists an isolated tenant domain and FRP port
block under `.runtime-data/oob/tenant-routing.json`. Inspect that authoritative allocation with
`vigil oob routing --format all`; apply its DNS/Caddy output to the shared edge before relying on callbacks.
Existing single-tenant installs retain their legacy domain and ports until an explicitly
coordinated migration. See README "Per-tenant OOB routing and upgrade behavior" for the deployment
contract.

There is no built-in host or domain. The port defaults to `7000`, while `oob.frp_host`,
`oob.domain`, and `oob.frp_token` are required. Environment
variables override config where allowed; a persisted tenant route rejects a conflicting ambient
OOB domain so callback correlation cannot move silently:

```bash
VIGIL_FRP_HOST
VIGIL_FRP_PORT
VIGIL_FRP_TOKEN
VIGIL_OOB_DOMAIN
```

## Starting Shared OOB Infrastructure

Start or verify the shared frp/interactsh sessions:

```bash
vigil oob start
vigil oob status --json
```

`vigil oob start` is idempotent. It renders runtime config under `/data/oob/`, starts missing tmux
sessions, and does nothing destructive when the existing sessions are healthy.

Runtime sessions:

| Session | Purpose |
|---------|---------|
| `frpc` | Shared frp tunnels |
| `oob-server` | interactsh-server watcher |
| `oob-client-<name>` | Per-agent or per-engagement interactsh-client |

Logs:

| Path | Source | Purpose |
|------|--------|---------|
| `/data/oob/frpc.log` | frpc | Tunnel registration and reconnect events |
| `/data/oob/watch.log` | server watcher | frp IP changes and interactsh restarts |
| `/data/oob/server.log` | interactsh-server | Raw callback stream; noisy |
| `/data/oob/clients/<name>.log` | interactsh-client | Raw per-client callback tail (read by `vigil oob client logs`); infra debug only — nonce<->probe correlation is `vigil oob poll` |

Use centralized logs from the host:

```bash
vigil logs oob --lines 80
```

## Retention cleanup

Per-client OOB artifacts under `/data/oob/clients/` (logs, metadata, and tmux
session files) accumulate as agents come and go. Prune the stopped ones:

```bash
vigil oob clean --dry-run    # preview only — list what would go, delete nothing
vigil oob clean              # remove non-running clients whose artifacts are all idle > 5 days
vigil oob clean --days 14    # widen the retention window to the last two weeks
```

`vigil oob clean` deletes the log, metadata, and session files only for clients
that are **not currently running** and whose every artifact is older than
`--days` days (default 5). Running clients — and any client touched inside the
window — are never removed. Add `--json` for a machine-readable summary of what
was cleaned.

## Agent OOB Readiness Check

Before sending blind payloads, agents verify OOB state directly:

```bash
vigil oob status --json
vigil logs oob --lines 80
```

Interpretation:

| Check | Ready signal | Agent action |
|-------|--------------|--------------|
| `server` | `true` | interactsh-server is available for callbacks |
| `frpc` | `true` | FRP tunnel registration is active |
| `clients` | contains your named client | the listener is up; `vigil oob poll --client <name>` can correlate hits |

If `server` or `frpc` is false, inspect `vigil logs oob --lines 80` and record a
runtime issue in your handoff. Escalate to the operator only for shared
infrastructure, token, DNS, or authentication failures because those are
operator-owned controls.

## OOB Procedure (mint→poll→correlate)

This is the **canonical** mint→fire→poll→correlate workflow. Every OOB-callback
technique (blind SSRF, XXE, blind SQLi, blind command injection, Log4Shell-style
probes, and similar) follows this same loop — do not re-derive it, shortcut it, or
eyeball the raw listener log in its place. This section is the single source other
docs point to for this procedure.

### 0. Readiness

Confirm shared OOB infrastructure is up before minting anything:

```bash
vigil oob status --json
```

Proceed only when `server=true` and `frpc=true` (see "Agent OOB Readiness Check"
above for the full interpretation table). If either is false, this is shared
infrastructure — inspect `vigil logs oob --lines 80` and record a runtime issue
rather than repairing it yourself.

### 1. Start or reuse a named client

Start one named client per agent/task that needs to run the listener. Agents
can manage these client sessions directly because they are correlation handles,
not shared FRP/server infrastructure:

```bash
vigil engagement list --json
vigil oob client list
vigil oob client start vuln-ssrf-api --engagement <engagement-key> --agent vulnerability-analyst
```

The client runs the listener; it is not where you read the callback URL or the
hits. Do NOT read the callback URL out of the client log. Stop it when the task
is done: `vigil oob client stop vuln-ssrf-api`.

### 2. Mint

Mint a nonce-tagged callback URL per payload, then fire the **exact host `mint`
prints** — call it `$OOB_HOST`:

```bash
vigil oob mint --client vuln-ssrf-api --technique ssrf --target-url <url> --param <p>
# → host  <nonce>.<client-id>.oob.example.com      ← this is $OOB_HOST
# → http  http://<nonce>.<client-id>.oob.example.com/
```

`mint` **binds the nonce under the running client's interactsh id** (`mint`
auto-selects the sole running client; pass `--client <name>` when several run)
and prints the exact host to fire as its `host`/`dns` output. That binding is
what lets `poll` see the hit: interactsh only delivers a callback to a client's
poll when the host carries that client's id, so a bare `<nonce>.oob.example.com`
would land only in the raw server log — never in the per-client log `poll`
reads, and never reachable by `poll` at all. **Never hand-build the host from
the nonce — substitute `$OOB_HOST` (mint's `host`/`dns` output) verbatim.**

### 3. Fire

Embed `$OOB_HOST` verbatim in the payload:

```text
http://$OOB_HOST/ssrf-users-endpoint
nslookup $OOB_HOST
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://$OOB_HOST/xxe">]>
```

### 4. Poll — correlate with the SAME client you minted under

```bash
vigil oob poll --client vuln-ssrf-api
```

`poll` must run against the **same client name you minted under in step 2** —
polling a different client will not see the hit, because the nonce is bound to
the minting client's interactsh id, not to the technique or target. `poll`
prints `matched <N> unmatched <M>` then one line per correlated hit carrying the
technique + target you minted with, so a matched probe<->callback pair is
self-documenting confirmation of the vulnerability. Add `--json` to capture the
matched set as evidence.

### 5. Client logs are a raw tail, never correlation

```bash
vigil oob client logs vuln-ssrf-api --lines 80
```

This is only a raw tail of this client's listener log, useful for infra
debugging (is the listener up, is anything arriving at all) — never the
correlation surface. Do not read this raw tail, or the shared
`vigil logs oob --lines 80` server/FRP tail, to decide whether a probe hit.
Nonce<->probe attribution is `vigil oob poll --client <name>` only (step 4).

### Fallback

If OOB is unavailable, fall back to time-based detection (sleep payloads) and
state in your output that OOB proof was not available. If time-based detection
also fails and OOB proof would have been decisive, record a runtime issue that
shared OOB infrastructure was unavailable — do not treat the technique as
untestable and drop it silently.

## Validation

Run a smoke test after starting OOB:

```bash
vigil oob test
```

For manual validation:

```bash
dig test123.oob.example.com @8.8.8.8
curl http://test123.oob.example.com/
vigil logs oob --lines 40
```

This smoke test only proves the shared infrastructure is reachable. For real
per-payload vulnerability confirmation, use the full "OOB Procedure
(mint→poll→correlate)" above — never the smoke-test's raw `curl`/`dig` output —
as the correlation evidence.

## Notes

- DNS uses UDP. The frp DNS proxy must stay UDP port 53.
- HTTP tunnels go through Caddy/TLS and frps HTTP routing.
- TCP/UDP tunnels bypass Caddy and bind direct ports on frps.
- Proxy names must be globally unique across active frpc clients; `vigil oob start` prefixes names
  with the runtime container hostname.
- `/data/oob/` persists through the runtime data volume.
