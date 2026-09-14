# Out-of-band routing (frp + interactsh)

Deep reference for per-install relay-slot routing, the edge configuration Vigil renders,
and the frpc conflict scan. The operator-facing setup sequence is in
[the README](../README.md#optional-capabilities).

## Configuration

```bash
vigil config set oob.frp_host oob-relay.example.com
vigil config set oob.frp_port 7000
vigil config set oob.domain oob.example.com
vigil config set oob.frp_token <token>
vigil oob start
vigil oob status --json
```

The FRP token is required. `vigil up` prompts for it on first startup when it is
missing and stores the value in `vigil config`; non-interactive installs should
set it first with `vigil config set oob.frp_token <token>` or `VIGIL_FRP_TOKEN`.

Vigil ships no maintainer-owned fallback infrastructure. Without `oob.frp_host`
and `oob.domain`, install and non-OOB workflows remain available, and
`vigil oob start` stops before Docker and prints every configuration command it
needs in one refusal — host, domain, and token — rather than refusing once for
the pair and again for the token.

## The relay slot

OOB has two levels, and they are scoped differently:

| Level | Scope | What it is | Created by |
|---|---|---|---|
| **Relay slot** | one **install** | A DNS-safe prefix, a subdomain under the OOB base domain, and a two-port FRP block — plus the single `frpc` tunnel and `interactsh` server that run in the shared Kali container | `vigil install` |
| **OOB client** | one **engagement + agent** | A correlation subdomain underneath that slot, polled into its own log and matched against that engagement's probes | `vigil oob client start <name> --engagement <key> --agent <role>` |

So the slot is *not* per engagement. One install runs one tunnel and one interactsh
server; every engagement on that install shares them, and each engagement's agents
get their own client underneath. That is why the slot is allocated at install time
and why it is keyed to the install root.

The slot exists so several Vigil **installs** can point at the same relay without
colliding on ports or callback hostnames — the `frpc` conflict scan below is what
catches it when they do.

(Unrelated to a blue engagement's *tenant*, which is the customer organisation
under investigation. Different concept, deliberately different word.)

A `vigil install` creates `.runtime-data/oob/relay-routing.json` atomically once
an OOB domain is configured. The record pins the slot prefix, its subdomain, and
the port block. Records written before the rename are named `tenant-routing.json`
and spell their keys `tenant_prefix`/`tenant_name`; those are still read.

Allocation is not limited to the install that first creates the root. Configure
`oob.domain` afterwards and the next `vigil install` allocates the slot — the
sequence at the top of this page works in either order. The one root that is not
allocated is an install that was **already running OOB** before relay slots
existed: it is still on the shared base domain and ports 53/8443, and its live
callbacks would stop correlating if those moved, so `vigil install` pins that
legacy route instead. The evidence is the install's own OOB state — the rendered
`frpc.toml`, the frpc/watch logs, the per-client files and the runtime route
marker that `vigil oob start` writes under the container's `/data/oob` (host
side: `.runtime-data/oob`, or wherever `VIGIL_RUNTIME_DATA_DIR` puts it). A root
that has never had OOB started carries none of it.

`vigil oob start`, client metadata, status/doctor, `vigil assess`, and Nuclei
`--oob-mode vigil` all resolve that record, so changing an ambient
`VIGIL_OOB_DOMAIN` cannot silently redirect a persisted Vigil slot to an
external Interactsh service.

Set `oob.slot` when the install-directory name is not the label you want. It
must be set **before** the install that allocates the route — the first
`vigil install` that runs with `oob.domain` configured — because a later install
reconciles the persisted record rather than renaming it. (`oob.tenant` is still
read as the pre-rename spelling.)

## Allocation across hosts

Allocation is serialized through `oob-allocations.json` beside the active Vigil
config. Multi-host deployments must place the config and registry on a shared,
locked filesystem — or distribute one centrally allocated registry — so every
host sees the same occupied FRP blocks.

## Rendering the edge configuration

```bash
vigil oob routing --format all|json|caddy|dns
```

This produces deterministic Caddy, DNS-forwarding, and JSON routing inputs from
the persisted record. Applying them to public DNS, FRP, and Caddy is an explicit
deployment operation — Vigil does not mutate those external services.

**DNS.** The emitted block is a CoreDNS input, not a Route53 record. The public
edge must accept TCP and UDP 53, select the longest matching slot zone, and
forward it to that slot's private FRP UDP port.

**Caddy.** The output includes direct HTTP plus on-demand HTTPS routes for the
apex, client-id, and real `nonce.client-id` callback depths. Its HTTPS block must
be imported under a Caddy global `on_demand_tls` permission/`ask` policy.

## Verifying the edge

```bash
vigil oob status --json   # deep DNS and two-label HTTP edge checks
vigil oob test            # end-to-end against a registered client
```

`vigil oob test` requires a registered client, fires the real client-bound host
shape, rejects redirects, and confirms the interaction reached that client's log.
Both checks intentionally report degraded until the server-side route has been
registered and applied.

## The frpc conflict scan

After spawning the `frpc` tmux session, `start_oob` tails `/data/oob/frpc.log`
for up to ~15s, looking for either success lines for all three rendered slot
proxies (`*-oob-dns`, `*-oob`, and `*-oob-rev`) or one of `port already used` /
`router config conflict` / `proxy name [...] already exists` from frps.

On a reported conflict the tmux sessions are torn down and the command exits with
the offending log lines verbatim. It tears down only the attempted slot's
sessions and names the persisted domain/port block that must be repaired. This
post-flight scan is the final defense against a stale or independently allocated
registry.

The check rides the existing frp control connection — no extra channel (SSH
forward, dashboard tunnel) is required.

If the log shows neither outcome within the timeout, the command prints a
non-fatal hint pointing at:

```bash
docker exec vigil tail -n 200 /data/oob/frpc.log
```

## Clients

```bash
vigil oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
vigil oob client logs example-agent --lines 80
vigil oob client stop example-agent
vigil oob client list
```

Payload and tactic detail: [`frp-tunneling.md`](../agent/references/offensive-tactics/frp-tunneling.md).
