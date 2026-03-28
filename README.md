# AI Threat Hunting

The operating model assumes a fully authorized realistic lab environment that mirrors real public and enterprise behavior closely enough for transferable methodology and tooling decisions.

## Repository Layout

- `agent/docker/runtime-full/Dockerfile`
  Primary full Kali MCP image. This is the only supported runtime for target-facing execution.
- `docker/kali-mcp-runtime/`
  MCP wrapper, transform proxy, and patched Kali API server.
- `agent/`
  Prompts, CLI integrations, attack skills, transient work-buffer scripts, and runtime helpers.
- `orchestrator/`
  Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility.
- `tests/`
  Shell/runtime contract tests.

## Quick Start

### Choose one client per install

Keep Claude and Codex in separate installs and separate engagement trees. Do not run both clients against the same `engagements/` directory.

The shared Kali MCP runtime is not per-engagement. Start it once, configure its proxy behavior once, and then attach one or more client installs to the same `docker exec -i security-research mcp-server` endpoint. Within a single install, the repo still tracks one active engagement via `engagements/.active`.

- Codex install:
```bash
# Only needed once, and not again for future engagements
./install.sh codex ~/security-research-codex
cd ~/security-research-codex
```

- Claude install:
```bash
# Only needed once, and not again for future engagements
./install.sh claude ~/security-research-claude
cd ~/security-research-claude
```

To switch clients, stop using the current engagement, install the other client into a different directory, and start a new engagement there.

### 1. Kali MCP proxy

Build the primary full image:

```bash
docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .
```

Edit `mcp-transform-rules.json` for your ordered find/replace rules, then start the shared runtime:

```bash
./agent/scripts/start_kali_mcp_runtime.sh
```

This starts one shared container named `security-research`, mounts durable proxy state at `.runtime-data/`, mounts the install-root `mcp-transform-rules.json` into the runtime, and passes the root `.env` file into the runtime when present.

Attach Claude Code or Codex over stdio after the runtime is up:

```bash
claude mcp add kali -s user -- docker exec -i security-research mcp-server
codex mcp add kali -- docker exec -i security-research mcp-server
```

Then create an engagement inside the chosen install:

```bash
cd agent
./scripts/init_engagement.sh https://target.example
```

Policy:

- All in-scope target-facing work must go through the attached Kali MCP session.
- Do not run target probes, crawlers, fuzzers, scanners, or exploits from host Bash or ad hoc Docker commands.
- Use MCP tool discovery to inspect the currently available Kali tools.
- When you need to run an arbitrary binary or shell pipeline inside the runtime, use the Kali MCP command-execution tool rather than a repo-local wrapper.

Proxy config lives in the install-root [mcp-transform-rules.json](/path/to/vigil). It contains:

- ordered `outbound` replace rules
- ordered `inbound` replace rules
- `public_ip_aliases.enabled`
- `public_ip_aliases.map_path`

Public IPv4 aliasing is automatic on inbound tool output. If `dig`, `whois`, `curl`, or any other Kali MCP tool returns `8.8.8.8`, the client will receive a private RFC1918 address instead, and the same public IP will keep the same private alias on later calls.

Keep `/data` mounted from the host if you want the alias map to survive container restarts, image rebuilds, and host reboots. With the default helper above, the durable host file is `.runtime-data/mcp-public-ip-map.json`.

Quick verification:

```bash
docker exec security-research cat /data/mcp-public-ip-map.json
```

That file is the durable proxy state. It will populate as public IPv4s are seen in MCP tool results.

### 2. Orchestrator backend

The backend is Python 3.11+ and `uv`-first:

```bash
uv sync --directory orchestrator/backend --extra dev
uv run --directory orchestrator/backend uvicorn app.main:app --reload
```

Run the backend tests with `uv`:

```bash
uv run --directory orchestrator/backend pytest
```

### 3. Orchestrator frontend

```bash
cd orchestrator/frontend
npm install
npm run dev
```

## Runtime Model

### Primary runtime

`agent/docker/runtime-full/Dockerfile` is the main full runtime image and now includes:

- Kali MCP server plus the transform proxy
- Katana and Chromium for authenticated crawling
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, nikto, WhatWeb, hydra, john, hashcat
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- an optional callback listener and ngrok bridge for listener-driven testing

An explicitly optional lightweight runtime also exists at
`agent/docker/runtime-lightweight/Dockerfile`. It is only for faster local iteration and
validation. The default workflow, docs, scripts, and agent runtime all target `agent/docker/runtime-full/Dockerfile`.

The MCP entrypoint is the wrapper in [docker/kali-mcp-runtime/mcp-server-wrapper.sh](/path/to/vigil), which starts the Kali API first and then runs the Python transform proxy.

## Using Tools Through Kali MCP

The runtime image still contains a broad toolset, but the supported way to use it is through the attached Kali MCP session.

- Use MCP tool discovery to see the current tool surface instead of relying on a hardcoded tool list in prompts or docs.
- For arbitrary shell commands inside the runtime, use the Kali MCP command-execution tool.
- Treat direct `docker exec ... <tool>` examples as unsupported for in-scope target work, even if they would technically function.

Initialize an engagement in the repo-managed workspace with:

```bash
cd agent
./scripts/init_engagement.sh https://target.example
```

Methodology now lives in:
- [engagement-methodology.md](/path/to/vigil)
- [athena-log-investigation](/path/to/vigil)

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

### Katana

Katana is built into the main runtime. The agent-side container helpers default to the same image for crawling, so there is no separate Katana image requirement anymore.
Use the Kali MCP command-execution tool to run `katana ...` inside the attached runtime when crawling is required.

### MITM proxy

MITM remains optional. Start it through the runtime environment or the attached Kali MCP session when the workflow requires interception. The proxy image still lives under `agent/docker/mitmproxy/`.

### Metasploit

Metasploit is not assumed to be always-on. Start it only when exploit chaining or module validation warrants it.
Start and inspect it through the attached Kali MCP session when needed. Repo-local helper scripts are no longer the supported target-facing path.

## Callback and Listener Handling

Listener-driven testing is handled explicitly rather than ad hoc.

### Local callback capture

The main image includes a simple HTTP callback capture server:

```bash
docker exec -it security-research start-callback
```

By default that starts a local listener on `0.0.0.0:8000` and prints all inbound requests, headers, and bodies.

### Exposing callbacks with ngrok

If you need an external callback URL:

```bash
docker exec -e USE_NGROK=1 \
  -e NGROK_AUTHTOKEN="$NGROK_AUTHTOKEN" \
  -e CALLBACK_PORT=8000 \
  -it security-research start-callback
```

This does two things:

1. starts the local callback listener
2. opens an ngrok HTTP tunnel to it

The ngrok token is no longer baked into the image. Supply it at runtime.

Claude Code and Codex can use this path once the Kali MCP runtime is attached. The listener is not limited to manual shell use. If the token is available in the container environment, the agent can start ngrok-backed callbacks itself during an engagement. If the token is not present, provide it before starting the callback path.

The token is not part of mandatory repo initialization. Treat it as an optional engagement input that you pass only when external callback routing is needed.

### Why this matters

This callback path is meant for:

- blind SSRF validation
- out-of-band webhook or callback checks
- file fetch validation
- application workflows that need a temporary receiver
- exploit chains that need a simple HTTP payload host or hit collector

For reverse shells or richer callback workflows, use the same runtime plus the bundled post-access tools instead of treating callbacks as a special one-off path.

## Multi-Agent Workflow

The combined project keeps the inherited multi-agent phase model, but the state is now durable in the orchestrator:

- `recon`
  network and service enumeration, source inspection, and OSINT enrichment
- `collect`
  target, port, route, and request-variant collection before queue materialization
- `test`
  coverage-driven validation, fuzzing, and retest tracking
- `exploit`
  exploit development, credential/access chaining, pivots, and callback-driven validation
- `athena`
  optional final log-investigation phase to determine whether important findings show prior exploitation in Athena-accessible logs
- `report`
  findings synthesis and coverage review

The run page exposes:

- target count
- service count
- request variant count
- coverage item count
- probe run count
- finding lifecycle and live findings
- exploit attempts and outcomes
- attack chains
- service-level coverage gaps
- unresolved surfaces
- phase worker activity

## Durable Assessment State

The orchestrator stores the canonical assessment state:

- targets and services
- canonical request variants
- raw request observations
- coverage items
- probe runs
- surfaces
- findings, links, and attack chains
- credential inventory, credential tests, access records, pivots, tunnels, and blocked techniques

The queue in `agent/scripts/schema.sql` remains useful as a transient work buffer, but it is no longer part of the operator-facing state contract.

## Development Notes

- Backend Python is `>=3.11`; use `uv`, not ad hoc `pip` installs.
- Frontend uses Vite and React under `orchestrator/frontend/`.
- This repository is Claude/Codex-only. Legacy third-client prompt, command, and runtime paths have been removed.
- The main runtime design is now `agent/docker/runtime-full/Dockerfile`, not the optional lightweight image.
- Repo-local target execution helpers are removed. Use Kali MCP for all in-scope testing.

## Verification Commands

Backend:

```bash
uv run --directory orchestrator/backend pytest orchestrator/backend/tests/test_assessment.py
```

Frontend:

```bash
cd orchestrator/frontend
npm install
npm run build
```

Runtime:

```bash
docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .
docker exec -i security-research mcp-server
```
