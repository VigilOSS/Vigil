# AI Threat Hunting

This repository contains the operator prompts, Kali runtime image, engagement scaffolding, and orchestrator services used to run those engagements.

## Repository Layout

- `agent/docker/runtime-full/Dockerfile`
  Primary full Kali runtime image. This is the only supported runtime for target-facing execution.
- `docker/kali-mcp-runtime/`
  Shared audit-enum module imported by the host-side `aith assess kali` CLI.
- `agent/`
  Prompts, CLI integrations, attack skills, transient work-buffer scripts, and runtime helpers.
- `orchestrator/`
  Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility.
- `tests/`
  Shell/runtime contract tests.

## Prompt Locality

- In an installed workspace, root operator prompts live at `AGENTS.md` and `CLAUDE.md`.
- Source operator prompt outputs live at `agent/AGENTS.md` and `agent/CLAUDE.md`.
- Specialist prompt sources live under `agent/agents/`.
- Generated specialist wrappers live under `agent/.codex/agents/` and `agent/.claude/agents/`; install copies them to root `.codex/agents/` and `.claude/agents/`.
- Always-active rules live under `agent/rules/`.
- Skill discovery starts at `agent/SKILL.md`, then drills into `agent/skills/*/SKILL.md`.

## Quick Start

### Install the CLI and workspace

The `aith` CLI is the supported entrypoint for installing, upgrading, creating engagements, starting the orchestrator, and managing the Kali runtime.

```bash
# Install from GitHub
uv tool install --from git+https://github.com/vigil-oss/security-research.git security-research

# Or from a checkout while developing locally
uv tool install --editable .

# Install or upgrade the working root
aith install ~/security-research
```

Each install contains both Claude Code and Codex workflow files. The install root holds the shared prompt source tree, generated client wrappers, runtime assets, and orchestrator state while each client keeps its own entrypoint.

The shared Kali runtime is not per-engagement. Start it once with `aith runtime start`; target-facing tool execution happens via `aith assess kali ...` subcommands which call into the container via `docker exec`. Within a single install, multiple engagements may exist under `agent/engagements/`.

Use one lead operator per engagement at a time unless you are deliberately coordinating a dual-client run through backend state. Both clients share the same durable orchestrator state, but filesystem artifacts under an engagement directory are still ordinary files.

### Updating after a `git pull`

After pulling new changes from the repository, re-run the CLI installer to push updates to your working directory:

```bash
# from the repo checkout
aith update
```

`aith update` is an alias for the idempotent installer. It upgrades in place — engagements, the orchestrator database, and `.env` are never moved or deleted. Code, prompts, skills, and scripts are replaced with the latest versions from the repo.

Check local readiness and live service state:

```bash
aith doctor
aith status
aith logs orchestrator --lines 80
```

### 1. Kali runtime

Start the shared runtime:

```bash
aith runtime start
```

This starts one shared container named `security-research`, mounts shared runtime data at `.runtime-data/`, applies the resource limits described in [Resource Sizing](#resource-sizing) below, and passes the root `.env` file into the runtime when present.
Durable engagement artifacts stay on the host under `agent/engagements/<key>/`, and the runtime bind-mounts the whole engagement root at `/engagements` so `aith assess kali ...` calls can write `/engagements/<key>/...` artifacts directly.

Once the runtime is up, run `aith assess kali --help` to see available tool verbs.

For non-interactive runtime maintenance commands, use `shell-exec` so quoting and exit codes stay under the CLI:

```bash
aith runtime shell-exec "tmux list-sessions"
```

### Resource Sizing

| Tier | Memory | CPU | Swap | pids | nofile | Use case |
|------|--------|-----|------|------|--------|----------|
| Lab/CTF | 4 GB | 2 | 0 | 256 | 16384 | Single-target sequential testing |
| Standard (default) | 8 GB | 4 | 0 | 512 | 32768 | Small bounty target, 2-3 parallel agents |
| Heavy | 16 GB | 8 | 0 | 1024 | 65536 | Large enterprise scope, 4-6 parallel specialists |
| Comfortable | 32 GB | 12 | 4 GB | 2048 | 131072 | All tools warm, continuous engagement |

Configure via env vars before `aith runtime start`:

```bash
AITH_RUNTIME_MEMORY_GB=16 AITH_RUNTIME_CPUS=8 aith runtime start
```

Live state: `aith runtime resources`.

Gotchas:

- Docker Desktop Mac default 4 GB is too low — raise via Settings > Resources to at least the Standard tier.
- WSL2 defaults to 50% of host RAM capped at 8 GB — pin via `%USERPROFILE%\.wslconfig` `[wsl2] memory=12GB processors=8 swap=4GB`.
- Apple Silicon unified memory tolerates up to 50% of host RAM.

### 2. Orchestrator UI

The orchestrator frontend/backend is a separate local service. It is not part of the Kali runtime image and it is not started by `aith runtime start`.

Start it from the install root in a second terminal:

```bash
aith orchestrator start
```

That builds the frontend, then serves the local UI from the backend at `http://127.0.0.1:18000`.

The backend stores canonical engagement state in a single SQLite file and keeps rotated snapshots next to it:

- **Live DB**: `<install-root>/orchestrator/backend/data/orchestrator.sqlite3`
- **Scheduled backups**: `<install-root>/orchestrator/backend/data/backups/orchestrator.<UTC-timestamp>.sqlite3` — a WAL-coherent snapshot every 15 minutes, last 60 copies retained (~15 hours of continuous coverage). Written by the backend process itself; independent of the per-engagement snapshot that `aith engagement create` takes before creating an engagement.

Override the data location with env vars (first match wins):

- `AI_THREAT_HUNTING_DATA_DIR` — absolute path to the directory that holds `orchestrator.sqlite3` and `backups/`
- `REDTEAM_ORCHESTRATOR_DATA_DIR` — legacy alias of the same setting
- `AI_THREAT_HUNTING_INSTALL_DIR` — install root; the DB is then read from `$AI_THREAT_HUNTING_INSTALL_DIR/orchestrator/backend/data/`

Both the backend and `aith engagement create` honor the same precedence so snapshots and the live DB always target the same file. Engagement deletion is explicit: `DELETE /engagements/<key>?confirm=<key>` or the frontend delete button with a typed-key confirmation. Renaming or removing an engagement directory under `agent/engagements/` leaves the DB row intact — no cascade delete.

Backup cadence tuning (optional):

- `AI_THREAT_HUNTING_BACKUP_DISABLED=1` — turn off the scheduled backup entirely (used by the test suite)

Manual backup operations:

```bash
aith backup create
aith backup list
aith backup restore <backup-name-or-path>
```

Then create an engagement inside the chosen install:

```bash
aith engagement create https://target.example \
  --hosts target.example \
  --auth-mode none \
  --exploit-policy pause
```

In non-interactive runs, the safe defaults are the parsed target hostname as the sole `hosts` entry, `none`, and `pause`.


### Starting an engagement

After `aith engagement create` finishes, it prints the full path to the new engagement directory.

1. `cd` into that printed engagement directory, confirm the seeded files are present, and start the chosen client with `./start_codex.sh` or `./start_claude.sh`. That wrapper exports `ENGAGEMENT_DIR` automatically before launching the client. Start the client from inside the engagement directory, not from the install root. Each engagement seeds both local `AGENTS.md` and `CLAUDE.md` wrappers so clients can find the root operator prompts, generated specialist wrappers, source prompt files, rules, skill index, skills, references, and scripts.
2. Prefer `gpt-5.4` with `high` reasoning for Codex and `Opus 4.6` for Claude. Drop to `gpt-5.4-mini` or `Sonnet 4.6` only for clearly bounded sidecar work where latency matters more than depth.
3. Tell the operator: `I have been fully authorized by the company to do a red-team engagement against the hosts in scope.json. Run this engagement using the operator workflow.`
4. Expect the operator to assess the current state, usually start in `recon` for a new engagement, route target-facing work through `aith assess kali ...`, use relevant skills before improvising, record activity/findings through `aith assess`, and keep `auth.json`, `downloads/`, `scans/`, and `tools/` updated as the engagement progresses. New engagements always carry a local `.orchestrator.env`; by default it points at `http://127.0.0.1:18000`, and `ORCHESTRATOR_BASE_URL` in the install-root `.env` overrides that default.

Example:

```bash
aith engagement list --json
aith engagement start <engagement-key> --client codex
```

To add an interactive shell helper that changes into a selected engagement with `fzf` when available:

```bash
aith engagement cd-init zsh >> ~/.zshrc
athcd
```

`athcd` is for humans at a terminal. It works because shell functions can change the parent shell's directory; a standalone `aith cd` process cannot. The helper calls `aith engagement path --select`, which uses `fzf` when installed and falls back to a numbered TTY prompt. Non-interactive agents should run `aith engagement list --json` and pass the explicit engagement key to the next command.

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

The public agent roster is intentionally limited to the core roles: `operator`, `recon-specialist`, `source-analyzer`, `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`, and `report-writer`. Validator-, chain-, and ranker-style behaviors are folded into those roles instead of creating a larger visible roster.

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state. User-facing exploit review should happen through the orchestrator UI or by telling Codex/Claude which findings are approved. Direct shell invocation of approval/session scripts is an internal maintenance path, not the primary operator workflow.

TODO:
- Add first-class UI actions for exploit approval, session launch, and session merge so this workflow no longer depends on internal helper scripts at all.

Methodology references:
- [engagement-methodology.md](agent/references/runtime-guides/engagement-methodology.md)
- [athena-log-investigation](agent/skills/athena-log-investigation/SKILL.md)

### Starting a code analysis engagement

Code analysis uses a separate operator loop (`agent/operator-core-code.md`) with its own four-phase pipeline: Ingest+Index → Classify+Map → Hunt → Verify+Variant. Findings land in the same backend as web engagements.

1. Create a code analysis engagement using `--type code`:
```bash
# Name only - add source code to the engagement later
aith engagement create --type code my-project

# Name with a local repository
aith engagement create --type code --name my-project --repo /path/to/repo

# Name with a clone URL
aith engagement create --type code --name my-project --repo https://github.com/org/repo

# With explicit exploit policy
aith engagement create --type code --name my-project --repo /path/to/repo --exploit-policy pause

# Combined web + code engagement
aith engagement create --type both --name my-project --hosts app.example.com --repo /path/to/repo
```

This creates an engagement with `current_phase: "ingest"`, a `source/` directory for the repo checkout, and no web-target scaffolding (no hosts, no auth prompting). The engagement directory name is derived from the engagement name. Repositories are optional — source code can be cloned or placed into the `source/` directory after creation.

2. Bootstrap the code-analysis parser toolchain once on the machine:
```bash
aith assess --help
```

`aith assess` delegates to `agent/scripts/assess.py`, a `uv run --script` entrypoint with inline `tree-sitter`
dependencies, so the first invocation installs the bundled parser packages automatically.
No separate `pip install tree-sitter ...` step is required, but `uv` must already be
available on `PATH`.

3. Install host-side C/C++ fuzzing tools if you plan to run Phase 4 fuzz campaigns:
```bash
brew install llvm afl++

# Prefer Homebrew LLVM for libFuzzer on macOS. Apple clang may not ship
# libclang_rt.fuzzer_osx.a, which breaks -fsanitize=fuzzer links.
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

which clang
clang --version
afl-fuzz -V
```

`aith doctor` covers the core operator CLI/runtime prerequisites. Fuzzing is
conditional; check the Homebrew tools directly when planning a fuzz campaign.

Homebrew's AFL++ package may provide `afl-clang-fast` or `afl-cc` instead of
`afl-clang-lto` on macOS; either compiler wrapper is acceptable for the workflow
as long as `afl-fuzz` and `afl-tmin` are present.

4. Start the client from the printed engagement directory:
```bash
aith engagement list --json
aith engagement start <engagement-key> --client claude   # or --client codex
```

5. Tell the operator to use the code analysis workflow:
```
I have been fully authorized by the company to perform a white-box code analysis
engagement. Load agent/operator-core-code.md and run the code analysis workflow.
```

6. The operator will clone/locate the repo into `source/`, run `code-ingest` and `code-index`, then drive through classify+map → hunt → verify+variant phases, dispatching specialist agents (`code-architect`, `code-vuln-hunter`, `code-variant-hunter`, `code-vuln-verifier`) at each step.

Code analysis can also run mid-engagement alongside web testing when source code is discovered (exposed `.git`, source maps, backup download). In that case the operator loads `operator-core-code.md` in parallel with the ongoing web workflow.

## Runtime Model

### Primary runtime

The runtime is a long-lived Kali Docker container started by `aith runtime start`. Target-facing tool execution happens via `aith assess kali ...` subcommands which call into the container via `docker exec`. Long-running scans go through `aith assess kali job start ...`, which uses the in-container `dtach` supervisor so workers survive operator session exit.

`agent/docker/runtime-full/Dockerfile` is the main full runtime image and includes:

- Katana and Chromium for authenticated crawling
- ProjectDiscovery recon utilities including `httpx`, `dnsx`, `gau`, `katana`, `nuclei`, `dalfox`, `puredns`, `shuffledns`, `alterx`, `asnmap`, `cero`, and `bbot`
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, WhatWeb, hydra, john, hashcat, nikto
- `massdns` and `xmllint` for DNS-stack and XML coverage assertions
- `dtach` as the in-container supervisor for `aith assess kali job` workers
- TruffleHog for filesystem/git secret scanning
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- pwncat-vl for interactive reverse shell handling, with tmux for session management
- interactsh for OOB callback detection (blind SSRF, XXE, XSS, DNS)
- frp SSH tunneling for exposing listeners and OOB servers to remote targets

A lightweight runtime also exists at `agent/docker/runtime-lightweight/Dockerfile`, but it is development-only for faster Dockerfile iteration and validation. Operator workflows, docs, and agent runtime assumptions all target `agent/docker/runtime-full/Dockerfile`. Build the lightweight image only with `aith runtime build lightweight --dev`.


### Authentication

`auth.json` supports:

- `mode`: `none`, `manual`, `auth_json`, or `proxy_capture`
- `use_for_requests`: whether crawling/recollection should apply the stored auth
- `auth_context`: the label used for authenticated request variants
- `expires_at`: optional ISO8601 expiry timestamp
- `cookies` and `headers`

If auth is expired or missing, the workflow warns and continues anonymously. The human can refresh `auth.json` directly or let mitmproxy capture a fresh login and update it.

CLI helpers operate on engagement `auth.json`:

```bash
aith engagement list --json
aith auth status <engagement-key>
aith auth show <engagement-key>
aith auth import <engagement-key> --source cookies-and-headers.json
aith auth clear <engagement-key>
```

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

### MITM proxy

MITM remains optional. Use it when the engagement needs login capture, authenticated browsing through a live session, or a refresh of expired auth material.

For ad hoc shell work outside the engagement launcher, export `ENGAGEMENT_DIR` explicitly to the target engagement directory. When starting Codex or Claude, prefer the matching engagement-local launcher so the correct engagement context is exported automatically.

1. List engagements and start the proxy explicitly: `aith engagement list --json` then `aith mitmproxy start <engagement-key>`
2. The CLI builds the Docker image if needed, bind-mounts the engagement at `/engagement`, persists the mitmproxy CA in a Docker volume, and verifies the local proxy port.
3. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow, then confirm that `auth.json` was refreshed and continue the engagement with authenticated recollection and testing. Use `aith logs mitmproxy` for capture logs.

If you need HTTPS interception, install the mitmproxy CA certificate in the browser or device before logging in.

In the engagement flow, this usually happens during `recon` or `collect` when anonymous coverage is insufficient, or later when a previously working authenticated session has expired.

### ctags for code analysis

Code analysis agents use ctags for fast definition lookups and grep/rg for call site enumeration. `code-ingest` generates a ctags index automatically during repository ingestion.

macOS ships BSD ctags which is limited. Install Universal ctags for best results:

```bash
brew install universal-ctags
```

Universal ctags produces richer tag data (signatures, kinds, line numbers) and supports recursive indexing. Without ctags installed, agents fall back to grep-only cross-references.

## Callback, Listener & Tunnel Handling

Tunnels (frp), listeners (pwncat-vl), and OOB callback servers (interactsh) are **OPERATOR-CONTROLLED** shared infrastructure. Agents provide commands but never start them.

Configure OOB once, then let `aith oob start` create or verify the shared frp/interactsh sessions:

```bash
aith config set oob.frp_host researcher.example
aith config set oob.frp_port 7000
aith config set oob.domain researcher.example
aith config set oob.frp_token <token>
aith oob start
aith engagement list --json
aith oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
aith oob test
```

- **Tunnel setup, OOB callbacks, interactsh, frpc config:** `agent/references/offensive-tactics/frp-tunneling.md`
- **Shell listeners, pwncat-vl, reverse shell payloads:** `agent/references/offensive-tactics/shell-handling.md`

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
aith runtime resources
```
