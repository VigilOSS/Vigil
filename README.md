# AI Threat Hunting

Hybrid red-team and threat-hunting platform built around:

- a primary Kali MCP runtime with request and response transforms
- RedteamAgent’s multi-agent workflow and attack-content library
- a durable orchestrator ledger for targets, services, request variants, probes, and surfaces
- shared Claude and Codex support, with Claude-friendly teammate workflows layered on top

This repository is the new home for the combined project. The old `security-research` Docker work is now the runtime foundation, and the RedteamAgent orchestration, prompts, scripts, and UI live here as first-class code.

## Repository Layout

- `Dockerfile`
  Primary Kali MCP image. This is the default runtime for tool execution.
- `docker/kali-mcp-runtime/`
  MCP wrapper, transform proxy, and patched Kali API server.
- `docker/redteam-allinone/`
  Optional all-in-one CLI runtime with OpenCode and the bundled toolchain.
- `agent/`
  Prompts, CLI integrations, attack skills, queueing scripts, and runtime helpers.
- `orchestrator/`
  Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility.
- `tests/`
  Shell/runtime contract tests.

## Quick Start

### 1. Primary Kali MCP runtime

Build the main image:

```bash
docker build -t security-research .
```

Run it with the capabilities needed by raw-packet tooling:

```bash
docker run -d \
  --name security-research \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  security-research
```

Attach your agent over stdio:

```bash
docker exec -i security-research mcp-server
```

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

The root `Dockerfile` is the main runtime image and now includes:

- Kali MCP server plus the transform proxy
- Katana and Chromium for authenticated crawling
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, nikto, WhatWeb, hydra, john, hashcat
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- an optional callback listener and ngrok bridge for listener-driven testing

The MCP entrypoint is the wrapper in [docker/kali-mcp-runtime/mcp-server-wrapper.sh](/path/to/vigil), which starts the Kali API first and then runs the Python transform proxy.

### Optional all-in-one CLI runtime

If you want the CLI tools, prompts, and bundled workspace in one container, use:

```bash
docker build -t redteam-allinone -f docker/redteam-allinone/Dockerfile .
```

Then run:

```bash
docker run --rm -it \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$PWD/workspace:/workspace" \
  redteam-allinone
```

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
cd agent
./scripts/lib/container.sh
```

From the CLI workflow:

- `/proxy start` starts mitmproxy
- `/proxy stop` stops it

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
- `report`
  findings synthesis and coverage review

The run page exposes:

- target count
- service count
- request variant count
- coverage item count
- probe run count
- unresolved surfaces
- phase worker activity

## Durable Assessment State

The orchestrator stores:

- targets and services
- canonical request variants
- raw request observations
- coverage items
- probe runs
- surfaces
- findings

The queue in `agent/scripts/schema.sql` remains useful as a transient work buffer, but it is no longer the only memory for coverage.

## Development Notes

- Backend Python is `>=3.11`; use `uv`, not ad hoc `pip` installs.
- Frontend uses Vite and React under `orchestrator/frontend/`.
- The `agent/` directory still contains the Claude, Codex, and OpenCode prompt/install paths.
- The main runtime design is now the root `Dockerfile`, not a separate sidecar-only experiment.

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
docker build -t security-research .
docker exec -i security-research mcp-server
```
