# FRP Tunneling & OOB Callbacks

## Overview

frp exposes local runtime services to remote targets. interactsh records out-of-band callbacks
for blind SSRF, XXE, command injection, SQLi, Log4Shell-style probes, and similar tests.

FRP tunnels, listeners, and OOB callback servers are **operator-controlled shared
infrastructure**. Agents must not start, stop, restart, or reconfigure shared
`frpc` / `oob-server` sessions because those sessions are global runtime state.

Agents do their own OOB readiness checks and per-agent client handling through
`aith`. This keeps routine status/log checks out of the operator loop while
preserving the operator boundary for shared infrastructure and secrets.

Traffic path:

```text
Internet -> Caddy/TLS -> frps -> frpc in security-research -> interactsh or local listener
Internet -> frps TCP/UDP port -> frpc in security-research -> local runtime service
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

Do not store the frp token in tracked docs. Put local values in `aith config`.

## Local Configuration

Configure once per workstation or install:

```bash
aith config set oob.frp_host researcher.example
aith config set oob.frp_port 7000
aith config set oob.domain researcher.example
aith config set oob.frp_token <token>
```

Defaults exist for host, port, and OOB domain, but `oob.frp_token` is required. Environment
variables override config when needed:

```bash
AI_THREAT_HUNTING_FRP_HOST
AI_THREAT_HUNTING_FRP_PORT
AI_THREAT_HUNTING_FRP_TOKEN
AI_THREAT_HUNTING_OOB_DOMAIN
```

## Starting Shared OOB Infrastructure

Start or verify the shared frp/interactsh sessions:

```bash
aith oob start
aith oob status --json
```

`aith oob start` is idempotent. It renders runtime config under `/data/oob/`, starts missing tmux
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
| `/data/oob/clients/<name>.log` | interactsh-client | Correlated callback stream; preferred |

Use centralized logs from the host:

```bash
aith logs oob --lines 80
```

## Agent OOB Readiness Check

Before sending blind payloads, agents verify OOB state directly:

```bash
aith oob status --json
aith logs oob --lines 80
```

Interpretation:

| Check | Ready signal | Agent action |
|-------|--------------|--------------|
| `server` | `true` | interactsh-server is available for callbacks |
| `frpc` | `true` | FRP tunnel registration is active |
| `clients` | contains your named client | correlated callback logs are available |

If `server` or `frpc` is false, inspect `aith logs oob --lines 80` and record a
runtime issue in your handoff. Escalate to the operator only for shared
infrastructure, token, DNS, or authentication failures because those are
operator-owned controls.

## Per-Agent Clients

Start one named client per agent/task that needs correlated callback logs. Agents
can manage these client sessions because they are correlation handles, not shared
FRP/server infrastructure:

```bash
aith engagement list --json
aith oob client start vuln-ssrf-api --engagement <engagement-key> --agent vulnerability-analyst
aith oob client logs vuln-ssrf-api --lines 80
```

The client log includes a unique callback URL such as `<id>.oob.example.com`.
Use the full unique URL in payloads, not only the base OOB domain.

Examples:

```text
http://<id>.oob.example.com/ssrf-users-endpoint
nslookup <id>.oob.example.com
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<id>.oob.example.com/xxe">]>
```

List and stop clients:

```bash
aith oob client list
aith oob client stop vuln-ssrf-api
```

## Validation

Run a smoke test after starting OOB:

```bash
aith oob test
```

For manual validation:

```bash
dig test123.oob.example.com @8.8.8.8
curl http://test123.oob.example.com/
aith logs oob --lines 40
```

Use client logs for vulnerability confirmation and raw server logs for infrastructure debugging.

## Agent Workflow

Agents should:

1. Run `aith oob status --json` and confirm `server=true`, `frpc=true`, and the expected `domain`.
2. Start or reuse a named client with an explicit engagement key: `aith engagement list --json`, `aith oob client list`, then `aith oob client start <name> --engagement <engagement-key> --agent <agent-name>`.
3. Use `aith oob client logs <name> --lines 80` to get the unique callback URL and to check correlated hits.
4. Use `aith logs oob --lines 80` only when debugging shared server/FRP health.

If OOB is unavailable, agents should fall back to time-based detection and state that OOB proof was
not available.

## Notes

- DNS uses UDP. The frp DNS proxy must stay UDP port 53.
- HTTP tunnels go through Caddy/TLS and frps HTTP routing.
- TCP/UDP tunnels bypass Caddy and bind direct ports on frps.
- Proxy names must be globally unique across active frpc clients; `aith oob start` prefixes names
  with the runtime container hostname.
- `/data/oob/` persists through the runtime data volume.
