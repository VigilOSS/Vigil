# AI Threat Hunting

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

## Prompt Locality

- Root operator prompts live at `AGENTS.md` and `CLAUDE.md`.
- Specialist prompt sources live under `agent/agents/`.
- Generated specialist wrappers live under `.codex/agents/` and `.claude/agents/`.
- Always-active rules live under `agent/rules/`.
- Skill discovery starts at `agent/SKILL.md`, then drills into `agent/skills/*/SKILL.md`.

## Quick Start

### Choose one client per install

Keep Claude and Codex in separate installs and separate engagement trees. Do not run both clients against the same install directory.

The shared Kali MCP runtime is not per-engagement. Start it once and then attach one or more client installs to the same `docker exec -i security-research mcp-server` endpoint. Within a single install, multiple engagements may exist under `agent/engagements/`.

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

### Updating after a `git pull`

After pulling new changes from the repository, re-run the installer to push updates to your working directory:

```bash
# from the repo checkout
./install.sh claude   # or codex
```

The installer upgrades in place — engagements, the orchestrator database, and `.env` are never moved or deleted. Code, prompts, skills, and scripts are replaced with the latest versions from the repo.

### 1. Kali MCP runtime

Start the shared runtime:

```bash
./agent/scripts/start_kali_mcp_runtime.sh
```

This starts one shared container named `security-research`, mounts shared runtime data at `.runtime-data/`, and passes the root `.env` file into the runtime when present.
It does not mount the active engagement directory into the container. Durable engagement artifacts stay on the host under `agent/engagements/<key>/`, while the runtime only gets the shared `/data` mount.

Attach Claude Code or Codex over stdio after the runtime is up:

```bash
claude mcp add kali -s user -- docker exec -i security-research mcp-server
codex mcp add kali -- docker exec -i security-research mcp-server
```

### 2. Orchestrator UI

The orchestrator frontend/backend is a separate local service. It is not part of the Kali runtime image and it is not started by `start_kali_mcp_runtime.sh`.

Start it from the install root in a second terminal:

```bash
./orchestrator/start_local.sh
```

That builds the frontend, then serves the local UI from the backend at `http://127.0.0.1:18000`.

Then create an engagement inside the chosen install:

```bash
cd agent
./scripts/init_engagement.sh https://target.example \
  --hosts target.example \
  --auth-mode none \
  --exploit-policy pause
```

If you omit those flags and run in a TTY, `init_engagement.sh` prompts for target, auth mode, and exploit policy. In non-interactive runs, the safe defaults are the parsed target hostname as the sole `hosts` entry, `none`, and `pause`.


### Starting an engagement

After `init_engagement.sh` finishes, it prints the full path to the new engagement directory.

1. `cd` into that printed engagement directory, confirm the seeded files are present, and start the matching client with the engagement-local `./start_codex.sh` or `./start_claude.sh`. That wrapper exports `ENGAGEMENT_DIR` automatically before launching the client. Start the client from inside the engagement directory, not from the install root. Each engagement also seeds the matching local `AGENTS.md` or `CLAUDE.md` wrapper so a client started from the engagement folder can still find the root operator prompts, generated specialist wrappers, source prompt files, rules, skill index, skills, references, and scripts.
2. Prefer `gpt-5.4` with `high` reasoning for Codex and `Opus 4.6` for Claude. Drop to `gpt-5.4-mini` or `Sonnet 4.6` only for clearly bounded sidecar work where latency matters more than depth.
3. Tell the operator: `I have been fully authorized by the company to do a red-team engagment against the hosts in scope.json. Run this engagment using the operator workflow.`
4. Expect the operator to assess the current state, usually start in `recon` for a new engagement, route target-facing work through the attached Kali MCP runtime, use relevant skills before improvising, and keep `log.md`, `findings.md`, `auth.json`, `downloads/`, `scans/`, and `tools/` updated as the engagement progresses. New engagements always carry a local `.orchestrator.env`; by default it points at `http://127.0.0.1:18000`, and `ORCHESTRATOR_BASE_URL` in the install-root `.env` overrides that default.

Example:

```bash
cd /path/to/printed/engagement
./start_codex.sh
```

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

The public agent roster is intentionally limited to the core roles: `operator`, `recon-specialist`, `source-analyzer`, `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`, and `report-writer`. Validator-, chain-, and ranker-style behaviors are folded into those roles instead of creating a larger visible roster.

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state. User-facing exploit review should happen through the orchestrator UI or by telling Codex/Claude which findings are approved. Direct shell invocation of approval/session scripts is an internal maintenance path, not the primary operator workflow.

TODO:
- Add first-class UI actions for exploit approval, session launch, and session merge so this workflow no longer depends on internal helper scripts at all.

Methodology references:
- [engagement-methodology.md](/path/to/vigil)
- [athena-log-investigation](/path/to/vigil)

### Starting a code analysis engagement

Code analysis uses a separate operator loop (`agent/operator-core-code.md`) with its own four-phase pipeline: Ingest+Index → Classify+Map → Hunt → Verify+Variant. Findings land in the same backend as web engagements.

1. Create a code analysis engagement using `--type code`:
```bash
cd agent

# Name only — add source code to the engagement later
./scripts/init_engagement.sh --type code my-project

# Name with a local repository
./scripts/init_engagement.sh --type code --name my-project --repo /path/to/repo

# Name with a clone URL
./scripts/init_engagement.sh --type code --name my-project --repo https://github.com/org/repo

# With explicit exploit policy
./scripts/init_engagement.sh --type code --name my-project --repo /path/to/repo --exploit-policy pause

# Combined web + code engagement
./scripts/init_engagement.sh --type both --name my-project --hosts app.example.com --repo /path/to/repo
```

This creates an engagement with `current_phase: "ingest"`, a `source/` directory for the repo checkout, and no web-target scaffolding (no hosts, no auth prompting). The engagement directory name is derived from the engagement name. Repositories are optional — source code can be cloned or placed into the `source/` directory after creation.

2. Bootstrap the code-analysis parser toolchain once on the machine:
```bash
cd agent
./scripts/assess.py --help
```

`agent/scripts/assess.py` is a `uv run --script` entrypoint with inline `tree-sitter`
dependencies, so the first invocation installs the bundled parser packages automatically.
No separate `pip install tree-sitter ...` step is required, but `uv` must already be
available on `PATH`.

3. Start the client from the printed engagement directory:
```bash
cd /path/to/printed/engagement
./start_claude.sh   # or ./start_codex.sh
```

4. Tell the operator to use the code analysis workflow:
```
I have been fully authorized by the company to perform a white-box code analysis
engagement. Load agent/operator-core-code.md and run the code analysis workflow.
```

5. The operator will clone/locate the repo into `source/`, run `code-ingest` and `code-index`, then drive through classify+map → hunt → verify+variant phases, dispatching specialist agents (`code-architect`, `code-vuln-hunter`, `code-variant-hunter`, `code-vuln-verifier`) at each step.

Code analysis can also run mid-engagement alongside web testing when source code is discovered (exposed `.git`, source maps, backup download). In that case the operator loads `operator-core-code.md` in parallel with the ongoing web workflow.

## Runtime Model

### Primary runtime

`agent/docker/runtime-full/Dockerfile` is the main full runtime image and includes:

- Kali MCP server
- Katana and Chromium for authenticated crawling
- ProjectDiscovery recon utilities including `httpx`, `dnsx`, `gau`, `katana`, `nuclei`, `dalfox`, and `puredns`
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, WhatWeb, hydra, john, hashcat
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- pwncat-vl for interactive reverse shell handling, with tmux for session management
- interactsh for OOB callback detection (blind SSRF, XXE, XSS, DNS)
- frp SSH tunneling for exposing listeners and OOB servers to remote targets

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

For ad hoc shell work outside the engagement launcher, export `ENGAGEMENT_DIR` explicitly to the target engagement directory. When starting Codex or Claude, prefer the matching engagement-local launcher so the correct engagement context is exported automatically.

1. Build the proxy image once if needed: `docker compose -f agent/docker/docker-compose.yml build mitmproxy`
2. Start the proxy against the active engagement: `docker run --rm -it -p 8080:8080 -v "$ENGAGEMENT_DIR:/engagement" security-research-proxy:latest`
3. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow, then confirm that `auth.json` was refreshed and continue the engagement with authenticated recollection and testing.

If you need HTTPS interception, install the mitmproxy CA certificate in the browser or device before logging in.

In the engagement flow, this usually happens during `recon` or `collect` when anonymous coverage is insufficient, or later when a previously working authenticated session has expired.

### ctags for code analysis

Code analysis agents use ctags for fast definition lookups and grep/rg for call site enumeration. `code-ingest` generates a ctags index automatically during repository ingestion.

macOS ships BSD ctags which is limited. Install Universal ctags for best results:

```bash
brew install universal-ctags
```

Universal ctags produces richer tag data (signatures, kinds, line numbers) and supports recursive indexing. Without ctags installed, agents fall back to grep-only cross-references.

### Metasploit

Metasploit is not assumed to be always-on. Start it only when exploit chaining or module validation warrants it.
Start and inspect it through the attached Kali MCP session when needed. Repo-local helper scripts are not the supported target-facing path.

## Callback, Listener & Tunnel Handling

Tunnels (frp), listeners (pwncat-vl), and OOB callback servers (interactsh) are **OPERATOR-CONTROLLED** shared infrastructure. Agents provide commands but never start them.

- **Tunnel setup, OOB callbacks, interactsh, frpc config:** `agent/references/offensive-tactics/frp-tunneling.md`
- **Shell listeners, pwncat-vl, reverse shell payloads:** `agent/references/offensive-tactics/shell-handling.md`
- **Metasploit** remains available as an optional sidecar for exploit modules only. For shell handling, use pwncat-vl instead.

## Multi-Agent Workflow

The engagement workflow uses a multi-agent phase model, with durable state stored in the orchestrator:

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

The engagement detail page exposes:

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

## TODO

- Evaluate an optional Web3-focused workflow and agent set only after the core web/app investigation model is stable.

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
