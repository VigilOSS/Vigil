# AI Threat Hunting

Hybrid red-team and threat-hunting platform built around:

- a primary Kali MCP runtime with request and response transforms
- RedteamAgent’s multi-agent workflow and attack-content library
- a durable orchestrator ledger for targets, services, request variants, probes, and surfaces
- shared Claude and Codex support, with Claude-friendly teammate workflows layered on top

The operating model assumes a fully authorized realistic lab environment that mirrors real public and enterprise behavior closely enough for transferable methodology and tooling decisions.

This repository is the new home for the combined project. The old `security-research` Docker work is now the runtime foundation, and the RedteamAgent orchestration, prompts, scripts, and UI live here as first-class code.

## Repository Layout

- `Dockerfile`
  Primary Kali MCP image. This is the default runtime for tool execution.
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

- Codex install:
```bash
./install.sh codex ~/security-research-codex
cd ~/security-research-codex
codex mcp add kali -- docker exec -i security-research mcp-server
cd agent && ./scripts/init_engagement.sh https://target.example
```

- Claude install:
```bash
./install.sh claude ~/security-research-claude
cd ~/security-research-claude
claude mcp add kali -s user -- docker exec -i security-research mcp-server
cd agent && ./scripts/init_engagement.sh https://target.example
```

To switch clients, stop using the current engagement, install the other client into a different directory, and start a new engagement there.

### 1. Primary Kali MCP runtime

Build the primary full image:

```bash
docker build -t security-research:latest .
```

Run it with the capabilities needed by raw-packet tooling:

```bash
mkdir -p .runtime-data

docker run -d \
  --name security-research \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$PWD/.runtime-data:/data" \
  security-research:latest
```

Attach Claude Code or Codex over stdio:

```bash
claude mcp add kali -s user -- docker exec -i security-research mcp-server
codex mcp add kali -- docker exec -i security-research mcp-server
```

### 1a. Configure request, response, and IP transforms

The MCP proxy applies configured string replacement on tool inputs and outputs, then aliases any public IPv4 addresses found in tool responses to stable private IPv4 addresses.

Run the container with transform env vars as needed:

```bash
docker run -d \
  --name security-research \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$PWD/.runtime-data:/data" \
  -e MCP_TRANSFORM_OUTBOUND_FIND=researcher.example \
  -e MCP_TRANSFORM_OUTBOUND_REPLACE=internal.test \
  -e MCP_TRANSFORM_INBOUND_FIND=Parameno \
  -e MCP_TRANSFORM_INBOUND_REPLACE=Redacted \
  security-research:latest
```

Relevant env vars:

- `MCP_TRANSFORM_OUTBOUND_FIND` / `MCP_TRANSFORM_OUTBOUND_REPLACE`
  replace strings before the Kali MCP tool call is executed
- `MCP_TRANSFORM_INBOUND_FIND` / `MCP_TRANSFORM_INBOUND_REPLACE`
  replace strings in the returned tool result
- `MCP_TRANSFORM_PUBLIC_IP_MAP_PATH`
  JSON file storing public IPv4 to private IPv4 aliases; defaults to `/data/mcp-public-ip-map.json`

Public IPv4 aliasing is automatic on inbound tool output. If `dig`, `whois`, `curl`, or any other Kali MCP tool returns `8.8.8.8`, the client will receive a private RFC1918 address instead, and the same public IP will keep the same private alias on later calls.

Keep `/data` mounted from the host if you want the alias map to survive container restarts, image rebuilds, and host reboots. With the default example above, the durable host file is `.runtime-data/mcp-public-ip-map.json`.

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

The root `Dockerfile` is the main full runtime image and now includes:

- Kali MCP server plus the transform proxy
- Katana and Chromium for authenticated crawling
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, nikto, WhatWeb, hydra, john, hashcat
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- an optional callback listener and ngrok bridge for listener-driven testing

An explicitly optional lightweight runtime also exists at
`agent/docker/kali-redteam-lightweight/Dockerfile`. It is only for faster local iteration and
validation. The default workflow, docs, scripts, and agent runtime all target the root `Dockerfile`.

The MCP entrypoint is the wrapper in [docker/kali-mcp-runtime/mcp-server-wrapper.sh](/path/to/vigil), which starts the Kali API first and then runs the Python transform proxy.

Initialize an engagement in the repo-managed workspace with:

```bash
cd agent
./scripts/init_engagement.sh https://target.example
```

Methodology now lives in:
- [engagement-methodology.md](/path/to/vigil)
- [athena-log-investigation](/path/to/vigil)

## Optional Tool Activation

These tools are intentionally present but not always started automatically.

### Katana

Katana is built into the main runtime. The agent-side container helpers default to the same image for crawling, so there is no separate Katana image requirement anymore.

Manual example:

```bash
docker exec -it security-research katana \
  -u https://target.example \
  -hl -jc -system-chrome -system-chrome-path /usr/bin/chromium \
  -headless-options --no-sandbox,--disable-dev-shm-usage,--disable-gpu \
  -d 3 -jsonl -silent
```

### MITM proxy

MITM remains optional. Use the agent command path or the helper directly:

```bash
docker compose -f agent/docker/docker-compose.yml up -d mitmproxy
```

The proxy image still lives under `agent/docker/mitmproxy/`.

### Metasploit

Metasploit is not assumed to be always-on. Start it only when exploit chaining or module validation warrants it.

Manual path:

```bash
docker compose -f agent/docker/docker-compose.yml up -d metasploit
```

Readiness helper:

```bash
agent/scripts/check_metasploit_runtime.sh --ensure --probe-port
```

This is the script the agent uses to verify or start the RPC service before trying the optional Metasploit path.

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

The combined project keeps the RedteamAgent phase model, but the state is now durable in the orchestrator:

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
- The main runtime design is now the root `Dockerfile`, not the optional lightweight image.

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
docker build -t security-research:latest .
docker exec -i security-research mcp-server
```
