---
description: Opt-in, off-by-default way to give the Kali runtime container a SEPARATE egress IP so the agent fleet's target-facing traffic does not share (and rate-block) the user-browser's NAT/CDN egress IP. Two mechanisms — an HTTP/SOCKS proxy (env-level, misses raw-socket tools) and a named Docker network / VPN sidecar (network-level, captures everything). Backend/orchestrator traffic is always excluded via a mandatory NO_PROXY default.
skill: web-recon
---

# Runtime egress separation — give the runtime its own egress IP

This feature is opt-in and off by default. With neither knob set, the runtime container uses
Docker's default bridge and leaves through the host's default route, which is the same egress IP
as the operator's browser. A sustained agent recon or exploit pass can then use up the shared CDN
rate budget for that IP and get the operator's own browser session rate-blocked mid-engagement.
Separation gives the fleet its own IP of record. Detecting that an IP is already on a reputation
list is a different job (`cdn-ip-blocking.md`, `vigil assess egress-check`).

## The two knobs (set in `<install>/.env` or the shell env)

| Env var | Effect |
| --- | --- |
| `VIGIL_RUNTIME_EGRESS_PROXY` | Upstream proxy URL. Wired into the container as `HTTP(S)_PROXY` + `ALL_PROXY` (both cases). Accepts `http`, `https`, `socks5`, `socks5h`, `socks4`, `socks4a`. Malformed/unknown-scheme/host-less URLs **fail clearly at `vigil runtime start`**. |
| `VIGIL_RUNTIME_EGRESS_NETWORK` | A pre-existing, named Docker network to attach with `--network`. Use this to put the runtime behind a VPN sidecar for a true separate IP (heavier; see below). |
| `VIGIL_RUNTIME_EGRESS_NO_PROXY` | *Optional.* Extra comma-separated `NO_PROXY` entries, appended to the mandatory backend exclusions. |

Both knobs are independent. Set the proxy alone (simplest), the network alone, or
both. Either one being set turns egress separation **on**; both unset = current
behaviour exactly.

Apply at `vigil runtime start` / `vigil runtime restart` — the value is read at
container-create time, so changing it requires a runtime recreate.

## Mandatory NO_PROXY — backend traffic is NEVER proxied

When a proxy is set, the runtime ALWAYS receives a `NO_PROXY`/`no_proxy` that
excludes the orchestrator/backend host-gateway:

```
host.docker.internal,localhost,127.0.0.1,::1
```

plus anything in `VIGIL_RUNTIME_EGRESS_NO_PROXY`. Because `host.docker.internal` is the alias the
runtime uses to reach the orchestrator, excluding the name keeps every `vigil assess` state call off
the target-facing proxy whatever the gateway's IP. `src/vigil_cli/config.py`
(`RUNTIME_EGRESS_NO_PROXY_DEFAULTS`) enforces this, and it can't be turned off.

## The raw-socket caveat (read this before trusting the proxy)

`HTTP(S)_PROXY` / `ALL_PROXY` only cover tools that honour proxy env vars:
curl, httpx, nuclei, ffuf, katana, gau, subfinder. **Raw-socket tools ignore
proxy env entirely** — `nmap`, `naabu`, `masscan`, `ping` build packets directly
and will **still egress the host IP** even with the proxy set. The proxy knob is
therefore a partial separation: HTTP(S)-layer recon/exploit moves to the proxy
IP, but a port scan still goes out the shared IP.

To capture *everything* (including raw-socket tools) you need **network-level**
separation: stand up a VPN/WireGuard sidecar (gluetun-style) on its own Docker
network and point `VIGIL_RUNTIME_EGRESS_NETWORK` at it (or run the sidecar and use
`network_mode: service:<vpn>` in a compose overlay). All container egress then
exits the tunnel IP while the orchestrator loop stays reachable over the
host-gateway. This is the heavier alternative — it needs a provisioned tunnel and
an extra container — but it is the only way to move raw-socket egress off the
host IP. `vigil runtime start` prints this caveat as a WARN whenever the proxy
knob is active.

## Verifying / auditing the active choice

The active egress choice is surfaced in two auditable places:

* **At start** — `vigil runtime start` prints a one-line stderr note
  (`[vigil] runtime egress separation ACTIVE: proxy=… network=… no_proxy=…`,
  the proxy URL exactly as configured) plus the raw-socket WARN when a proxy is
  set. Silent on the default path.
* **On demand** — `vigil runtime resources` (and `--json`) prints an `egress`
  row: `enabled`, the configured `proxy`, the `network`, and the effective
  `no_proxy`. `enabled=false` reads `(shares host/browser egress IP)`.

To confirm the runtime's real egress IP differs from the browser's, exec a check
inside the container and compare to the browser's `api.ipify.org`:

```
vigil runtime shell-exec -- curl -s https://api.ipify.org
```

(Raw-socket tools will still show the host IP — that is the caveat above, not a
bug.)
