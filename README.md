# AI Threat Hunting

The operating model assumes a fully authorized realistic lab environment that mirrors real public and enterprise behavior closely enough for transferable methodology and tooling decisions.

This repository contains the operator prompts, Kali MCP runtime, engagement scaffolding, and orchestrator services used to run those engagements.

## Repository Layout

- `agent/docker/runtime-full/Dockerfile`
  Primary full Kali MCP image. This is the only supported runtime for target-facing execution.
- `docker/kali-mcp-runtime/`
  MCP wrapper and patched Kali API server.
- `agent/`
  Prompts, CLI integrations, attack skills, transient work-buffer scripts, and runtime helpers.
- `orchestrator/`
  Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility.
- `tests/`
  Shell/runtime contract tests.

## Quick Start

### Choose one client per install

Keep Claude and Codex in separate installs and separate engagement trees. Do not run both clients against the same `engagements/` directory.

The shared Kali MCP runtime is not per-engagement. Start it once and then attach one or more client installs to the same `docker exec -i security-research mcp-server` endpoint. Within a single install, the repo tracks one active engagement via `engagements/.active`.

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

### 1. Kali MCP runtime

Build the primary full image:

```bash
docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .
```

Start the shared runtime:

```bash
./agent/scripts/start_kali_mcp_runtime.sh
```

This starts one shared container named `security-research`, mounts shared runtime data at `.runtime-data/`, and passes the root `.env` file into the runtime when present.

Attach Claude Code or Codex over stdio after the runtime is up:

```bash
claude mcp add kali -s user -- docker exec -i security-research mcp-server
codex mcp add kali -- docker exec -i security-research mcp-server
```

Then create an engagement inside the chosen install:

```bash
cd agent
./scripts/init_engagement.sh https://target.example \
  --scope-mode host_only \
  --auth-mode none \
  --exploit-policy pause
```

If you omit those flags and run in a TTY, `init_engagement.sh` prompts for scope, auth mode, and exploit policy. In non-interactive runs, the safe defaults are `host_only`, `none`, and `pause`.


### Starting an engagement

After `init_engagement.sh` finishes, it prints the full path to the new engagement directory and updates `engagements/.active`.

1. `cd` into that printed engagement directory, run `export ENG_DIR="$PWD"`, confirm the seeded files are present, and start `codex`.
2. Switch Codex to `high`, then tell it: `Run this engagement using the operator workflow. Start by reading scope.json and log.md, tell me the current phase, and show the next numbered actions.`
3. Expect Codex to assess the current state, usually start in `recon` for a new run, route target-facing work through the attached Kali MCP runtime, and keep `log.md`, `findings.md`, `auth.json`, `downloads/`, `scans/`, and `tools/` updated as the engagement progresses.

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

When an engagement reaches exploit review with `--exploit-policy pause` or `selected`, the operator reviews and approves exploit work manually:

```bash
./scripts/review_exploit_candidates.sh "$ENG_DIR"
./scripts/approve_exploitation.sh "$ENG_DIR" selected FINDING-VA-001 FINDING-EX-003
./scripts/launch_exploit_session.sh "$ENG_DIR" session-a FINDING-VA-001
./scripts/merge_exploit_session.sh "$ENG_DIR" session-a
```

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state.

Methodology references:
- [engagement-methodology.md](/path/to/vigil)
- [athena-log-investigation](/path/to/vigil)

## Runtime Model

### Primary runtime

`agent/docker/runtime-full/Dockerfile` is the main full runtime image and includes:

- Kali MCP server
- Katana and Chromium for authenticated crawling
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, nikto, WhatWeb, hydra, john, hashcat
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- an optional callback listener and ngrok bridge for listener-driven testing

A lightweight runtime also exists at `agent/docker/runtime-lightweight/Dockerfile`. It is only for faster local iteration and validation. The default workflow, docs, scripts, and agent runtime all target `agent/docker/runtime-full/Dockerfile`.

The MCP entrypoint is the wrapper in [docker/kali-mcp-runtime/mcp-server-wrapper.sh](/path/to/vigil), which starts the Kali API first and then runs the upstream Kali MCP client.


### Authentication

`auth.json` supports:

- `mode`: `none`, `manual`, `auth_json`, or `proxy_capture`
- `use_for_requests`: whether crawling/recollection should apply the stored auth
- `auth_context`: the label used for authenticated request variants
- `expires_at`: optional ISO8601 expiry timestamp
- `cookies` and `headers`

If auth is expired or missing, the workflow warns and continues anonymously. The human can refresh `auth.json` directly or let mitmproxy capture a fresh login and update it.

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

### MITM proxy

MITM remains optional. Use it when the engagement needs login capture, authenticated browsing through a live session, or a refresh of expired auth material.

From the install root, you can recover the active engagement directory at any time with `ENG_DIR="$(cat agent/engagements/.active)"`.

1. Build the proxy image once if needed: `docker compose -f agent/docker/docker-compose.yml build mitmproxy`
2. Start the proxy against the active engagement: `docker run --rm -it -p 8080:8080 -v "$ENG_DIR:/engagement" security-research-proxy:latest`
3. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow, then confirm that `auth.json` was refreshed and continue the engagement with authenticated recollection and testing.

If you need HTTPS interception, install the mitmproxy CA certificate in the browser or device before logging in.

In the engagement flow, this usually happens during `recon` or `collect` when anonymous coverage is insufficient, or later when a previously working authenticated session has expired.

### Metasploit

Metasploit is not assumed to be always-on. Start it only when exploit chaining or module validation warrants it.
Start and inspect it through the attached Kali MCP session when needed. Repo-local helper scripts are not the supported target-facing path.

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

The ngrok token is not baked into the image. Supply it at runtime.

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

The project uses a multi-agent phase model, with durable state stored in the orchestrator:

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

The queue in `agent/scripts/schema.sql` is a transient work buffer and is not part of the operator-facing state contract.

## Development

For repo-local development conventions used by Codex, see the root `AGENTS.md`.

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
