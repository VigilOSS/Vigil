<div align="center">

# Vigil

**AI-driven offensive and incident-response engagements — operator prompts, a full Kali runtime, and durable orchestrator state in one CLI.**

[![License](https://img.shields.io/badge/license-proprietary-blue.svg)](LICENSE)
[![CI](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/vigil-oss/vigil)

</div>

This repository contains the operator prompts, Kali runtime image, engagement scaffolding, and orchestrator services used to run those engagements.

## Screenshots

> Image assets are not committed yet. Drop captures into `docs/images/` and uncomment the rows below.

| Engagement page | Findings drawer |
|-----------------|-----------------|
| <!-- ![Engagement page](docs/images/engagement-page.png) --> | <!-- ![Findings drawer](docs/images/findings-drawer.png) --> |
| **Dashboard** | **CLI** |
| <!-- ![Dashboard](docs/images/dashboard.png) --> | <!-- ![CLI](docs/images/cli.png) --> |

## Table of Contents

- [Documentation](#documentation)
- [Quick Start](#quick-start)
- [Key Capabilities](#key-capabilities)
- [Repository Layout](#repository-layout)
- [Prompt Locality](#prompt-locality)
- [Usage](#usage)
- [Runtime Model](#runtime-model)
- [Optional Tool Activation](#optional-tool-activation)
- [Callback, Listener & Tunnel Handling](#callback-listener--tunnel-handling)
- [Command Reference](#command-reference)
- [Operations](#operations)
- [Security](#security)
- [Multi-Agent Workflow](#multi-agent-workflow)
- [Durable Assessment State](#durable-assessment-state)
- [Development](#development)
- [Verification Commands](#verification-commands)
- [Roadmap & TODO](#roadmap--todo)

## Documentation

Vigil's docs are spread across operator prompts, a code map, and a deep reference tree. Start here:

| Document | What it covers |
|----------|----------------|
| [`agent/AGENTS.md`](agent/AGENTS.md) | The operator prompt — the workflow every engagement runs. |
| [`docs/engagement-prompt-playbook.md`](docs/engagement-prompt-playbook.md) | Operator steering playbook — the human-side prompts for pushing an engagement when the model goes shallow, overclaims severity, or forgets the core loop. |
| [`docs/benchmarking.md`](docs/benchmarking.md) | The `vigil bench` harness — measure the unmodified agent against the XBEN and procedural-generated suites, launch modes, run flags, cost accounting, and anti-cheat. |
| [`AGENTS.md`](AGENTS.md) | Maintainer/contributor workflow: clone-to-first-dispatch walkthrough and recipes for adding a skill, an `vigil assess` verb, an oracle, or an eval case. |
| [`CODE-MAP.md`](CODE-MAP.md) | Map of the codebase — where each subsystem lives. |
| [`agent/references/`](agent/references/) | Reference library (payloads, tactics, recon, tenants, tools) — discover with `vigil assess list-references` (self-registering; `--skill <name>` filters to a skill's paired refs). |
| [`agent/references/runtime-guides/engagement-methodology.md`](agent/references/runtime-guides/engagement-methodology.md) | End-to-end engagement methodology. |
| [`agent/references/offensive-tactics/frp-tunneling.md`](agent/references/offensive-tactics/frp-tunneling.md) | Tunnel setup, OOB callbacks, interactsh, frpc config. |
| [`agent/references/offensive-tactics/shell-handling.md`](agent/references/offensive-tactics/shell-handling.md) | Shell listeners, pwncat-vl, reverse-shell payloads. |

## Quick Start

```bash
# 1. Install the CLI
uv tool install --from git+https://github.com/vigil-oss/vigil.git vigil

# 2. Install a working root and bring the local stack up (Kali runtime + orchestrator)
vigil install ~/vigil && vigil up

# 3. Create an engagement against an authorized target
vigil engagement create https://target.example --hosts target.example

# 4. Start the operator on it
vigil engagement start <engagement-key> --client codex   # or --client claude
```

The full install / update / stack walkthrough is below; heavier operational tuning lives under [Operations](#operations).

### Install the CLI and workspace

The `vigil` CLI is the supported entrypoint for installing, upgrading, creating engagements, starting the orchestrator, and managing the Kali runtime.

```bash
# Install from GitHub
uv tool install --from git+https://github.com/vigil-oss/vigil.git vigil

# Or from a checkout while developing locally
uv tool install --editable .

# Install or upgrade the working root
vigil install ~/vigil

# Sync source, build stale images, and start the local stack.
# Prompts for FRP token on first run if not configured.
vigil up
```

Each install contains both Claude Code and Codex workflow files. The install root holds the shared prompt source tree, generated client wrappers, runtime assets, and orchestrator state while each client keeps its own entrypoint.

The shared Kali runtime is not per-engagement. Start the local stack once with
`vigil up`; target-facing tool execution happens via `vigil assess kali ...`
subcommands which call into the container via `docker exec`. Within a single
install, multiple engagements may exist under `agent/engagements/`.

Use one lead operator per engagement at a time unless you are deliberately coordinating a dual-client run through backend state. Both clients share the same durable orchestrator state, but filesystem artifacts under an engagement directory are still ordinary files.

### Updating after a `git pull`

`vigil up` automatically syncs source files into the install root before checking images and starting services. After pulling changes, just run `vigil up` again — no separate update step is needed.

For a source-only sync without starting services:

```bash
vigil install
```

`vigil install` (and its alias `vigil update`) upgrades in place — engagements, the orchestrator database, and `.env` are never moved or deleted. Code, prompts, skills, and scripts are replaced with the latest versions from the repo.

Check local readiness and live service state:

```bash
vigil doctor
vigil status
vigil logs orchestrator --lines 80
```

### Stack details

`vigil up` is the supported all-up path. It starts the Kali runtime container, the orchestrator backend (which builds the frontend when needed), and the optional mitmproxy and OOB services if they are configured. For partial restarts the individual `vigil runtime start` and `vigil orchestrator start` subcommands still exist and are documented under their respective `--help`. `vigil status` / `vigil logs <target>` report live state.

The Kali runtime is one shared container named `vigil`. It mounts shared runtime data at `.runtime-data/`, applies the resource limits described in [Resource Sizing](#resource-sizing) below, and passes the root `.env` file into the runtime when present. Durable engagement artifacts stay on the host under `agent/engagements/<key>/`, and the runtime bind-mounts the whole engagement root at `/engagements` so `vigil assess kali ...` calls can write `/engagements/<key>/...` artifacts directly. Run `vigil assess kali --help` for the available tool verbs.

For non-interactive runtime maintenance commands, use `shell-exec` so quoting and exit codes stay under the CLI:

```bash
vigil runtime shell-exec "tmux list-sessions"
```

> **Operational tuning** — resource sizing tiers, container rlimits/ulimits, and orchestrator data/backups are documented under [Operations](#operations).

### Creating an engagement

Create an engagement inside the chosen install:

```bash
vigil engagement create https://target.example --hosts target.example
```

In non-interactive runs the safe default is the parsed target hostname as the sole `hosts` entry. The default exploit policy is `pause` (human approval required before any exploit work); change it later via the orchestrator UI or by editing the engagement's `scope.json`. Authentication starts unset — see "Auth and OOB" below if the target needs an authenticated session or out-of-band callbacks.

When `--type` is omitted it is inferred from the inputs (URL/host → `web`, `--repo` → `code`, both kinds of evidence → `both`, APK or `--package-name` → `android`) and the inferred type is echoed on stderr so it can be overridden. Ambiguous inputs (a bare name with no corroborating flag) prompt on a terminal and fail fast with `--no-prompt` instead of silently defaulting. On a terminal, missing required fields are asked for interactively, ending with a summary and a confirmation; pass `--no-prompt` for strictly non-interactive behavior.

Scope hosts can be supplied as `--hosts a,b` (comma-separated), repeated `--host` flags, a `--hosts-file` (one host per line, `#` comments allowed), or any mix — entries merge in order and deduplicate. `--dry-run` validates the inputs and shows exactly what would be created without writing anything, and `--json` replaces the bare-path stdout line with a JSON object (`key`, `path`, `engagement_type`, `scope`).

`vigil engagement create` finishes by printing the engagement directory path on stdout and a short status footer on stderr: the current state of mitmproxy and OOB plus the exact start command. There is no need to `cd` into the directory by hand. All interactive prompts also write to stderr, so `eng=$(vigil engagement create ...)` works even when the wizard engages.

### Auth and OOB (optional, before starting)

If the engagement needs authenticated coverage or out-of-band callbacks, set those up before launching the client:

```bash
vigil mitmproxy start                    # one proxy serves all active engagements; browse 127.0.0.1:8080
vigil oob start                          # shared frp/interactsh; see "Callback, Listener & Tunnel Handling"
```

The post-create footer prints whichever of these is not running and the exact command to start it; this section is the deeper reference (see [MITM proxy](#mitm-proxy) and [Callback, Listener & Tunnel Handling](#callback-listener--tunnel-handling) below).

## Key Capabilities

- **One CLI, full lifecycle.** `vigil` installs the workspace, builds and runs the shared Kali runtime, starts the orchestrator, and creates/drives engagements.
- **Full Kali runtime.** A long-lived container with ProjectDiscovery recon tooling, fuzzers, post-access tooling, OOB callback detection, and tunneling — see [Runtime Model](#runtime-model).
- **Durable orchestrator state.** Canonical engagement state (targets, services, request variants, coverage, probe runs, findings, attack chains, credentials) lives in SQLite with rotated backups — see [Durable Assessment State](#durable-assessment-state).
- **Multi-agent phase model.** Operator + specialist roles work a phased workflow (`recon → collect → test → exploit → athena → report`) — see [Multi-Agent Workflow](#multi-agent-workflow).
- **Red, blue, and code-analysis modes.** The same backend drives web red-team engagements, blue incident-response engagements, and white-box code-analysis engagements — see [Usage](#usage).
- **Skill- and tool-first.** Specialists pick named skills (`vigil assess list-skills`) and prefer real tools over hand-rolled loops before improvising.

## Repository Layout

- `agent/docker/runtime-full/Dockerfile`
  Primary full Kali runtime image. This is the only supported runtime for target-facing execution.
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
- Skill discovery is driven by `vigil assess list-skills`, which walks `agent/skills/*/SKILL.md` frontmatter; the operator picks a skill by name and the dispatched specialist reads the full file.

## Usage

This section covers how to drive an engagement once the stack is up: starting red engagements, the operator start prompts, resume/dispatch closure, blue incident engagements, and code-analysis engagements.

### Starting an engagement

Use the CLI verb — it changes into the engagement directory and execs the launcher (which exports `ENGAGEMENT_DIR`, mounts the `.codex/agents` / `.claude/agents` symlinks to the canonical prompts, and starts the client):

```bash
vigil engagement list --json                              # find the key
vigil engagement start <engagement-key> --client codex    # or --client claude
```

For humans at a terminal, the optional `athcd` shell helper (see below) jumps your shell into a selected engagement directory; the per-engagement `start_codex.sh` / `start_claude.sh` files exist but are an implementation detail of `vigil engagement start`.

1. Prefer `gpt-5.4` with `high` reasoning for Codex and `Opus 4.6` for Claude. Drop to `gpt-5.4-mini` or `Sonnet 4.6` only for clearly bounded sidecar work where latency matters more than depth.
2. Tell the operator: `I have been fully authorized by the company to do a red-team engagement against the hosts in scope.json. Run this engagement using the operator workflow.`
3. Expect the operator to assess the current state, usually start in `recon` for a new engagement, route target-facing work through `vigil assess kali ...`, use relevant skills before improvising, record activity/findings through `vigil assess`, and keep `auth.json`, `downloads/`, `scans/`, and `tools/` updated as the engagement progresses. New engagements always carry a local `.orchestrator.env`; parent-shell `ORCHESTRATOR_BASE_URL` is the explicit override, the engagement-local file wins over legacy install-root env files, and `vigil config get orchestrator_base_url` is the persistent default before hardcoded fallback.

To add an interactive shell helper that changes into a selected engagement with `fzf` when available:

```bash
vigil engagement cd-init zsh >> ~/.zshrc
athcd
```

`athcd` is for humans at a terminal. It works because shell functions can change the parent shell's directory; a standalone `vigil cd` process cannot. The helper calls `vigil engagement path --select`, which uses `fzf` when installed and falls back to a numbered TTY prompt. Non-interactive agents should run `vigil engagement list --json` and pass the explicit engagement key to the next command.

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

### Engagement operator start prompts

Two forms. Use the **generic** form to start a fresh engagement after `cd`-ing into the engagement directory. Use the **resume** form when handing off between sessions or picking up where a previous agent left off.

#### Generic — new or resumed engagement (simple form)

After `vigil engagement start <key>`:

```
Read AGENTS.md and assume Operator role.

Authorized bug-bounty engagement: https://bugcrowd.com/engagements/<slug>
Full authorization confirmed. Run the operator workflow. Take full advantage of specialist agents
to delegate all target-facing work — dispatch in parallel where phases permit. Prefer
claude-opus-4-7 / gpt-5.5 xhigh reasoning for operator-level and substantial specialist work;
use sonnet / medium only for clearly bounded sidecar tasks. Exploitation policy is pause —
explicit human approval required before any exploit-developer dispatch.
```

#### Refined — resume with prior context

Use this when continuing across sessions. The operator's first action is `vigil assess
resume-brief` for a bounded backend snapshot; paste the rendered handoff blob from the prior
agent (run `vigil assess agent render-handoff <agent-id>` before closing the previous session)
when the new session continues a specific dispatch.

```
Read AGENTS.md and assume Operator role. Run agent/rules/resume.md hydration before
planning anything — start with `vigil assess resume-brief` (narrow with --finding, --q,
or --agent-id for targeted continuation).

Authorized engagement: https://bugcrowd.com/engagements/<slug>
Continue phases <X, Y, Z> to completion. Use specialist agents for all dispatched work;
you are the orchestrator brain. Track orchestration, prompt, and backend issues to ISSUES.md.
Keep dispatching agents until [specify tools / objectives] have completed.

Depth is the default. "Quick" is not desired — thorough and deep coverage is.
Prefer claude-opus-4-7 / gpt-5.5 xhigh for substantial work; medium only for bounded sidecar tasks.
Exploitation policy: <pause|selected|full_send> per scope.json.

Previous agent context (paste only when continuing a specific dispatch):
<paste vigil assess agent render-handoff <agent-id> output here>
```

### Resume, artifacts, and dispatch closure (operator CLI surface)

The orchestrator backend is the canonical store for engagement state. Use these CLI
commands to read and close that state — they replace ad-hoc file scraping and
transcript pasting:

- `vigil assess resume-brief [--finding <slug>] [--q <text>] [--agent-id <id>] [--max-age-hours N]`
  — bounded JSON+markdown operating picture (finding queues, recent decisions, stale
  dispatches, handoff gaps, top command-history matches, indexed artifacts, and
  one-shot drill-down commands keyed by id).
- `vigil assess artifact search|get|register|refresh|mark-scratch`
  — engagement-local file index. Agents/operators register heavy raw files
  explicitly with `register <path> [--finding <slug>] [--agent-id <id>]
  [--command-run-id <n>]`; the backend computes SHA-256, indexes preview text
  for FTS, and links to a finding/chain/surface/request-variant/command-run.
  `search` is FTS over previews + paths + linked finding slugs.
  `mark-scratch <path-or-id>` dismisses a registered note as scratch so
  `check-phase-readiness --phase report` no longer blocks on it (the escape valve for operator or
  specialist working notes that are not durable engagement memory).
- `vigil assess agent close <agent-id>`
  — close an in-progress dispatch when its handoff is `ready` or `blocked`. Records a
  `dispatch_closed_from_handoff` decision row.
- `vigil assess agent reconcile-stale [--dry-run] [--max-age-hours N]`
  — list in-progress dispatches older than the threshold; close ones whose handoff is
  `ready`/`blocked` automatically. Always prints every candidate with `closed=true|false`
  and a `skip_reason`.

### Blue incident engagements

Blue mode uses the same backend and artifact index, but starts from an alert
and tenant reference instead of a web host:

```bash
vigil blue customers
# If the customer/platform is missing:
# vigil blue tenant init --customer <customer-slug> --platform <gws|m365|aws|okta|edr|network|generic>
# Fill the generated tenant ref before starting the engagement.

vigil blue engage --customer <customer-slug> --platform gws --severity high
cd <engagement-dir>
vigil engagement start <engagement-key> --client codex
```

Tell the operator: `I have been fully authorized by the company to run a blue-team incident-response engagement for the tenant in scope.json. Run this engagement using the blue operator workflow.` Then paste the alert into the operator chat. The operator records intake with `vigil blue alert record --body-file <path>` and finishes every engagement with either `vigil blue closeout` or `vigil blue report`.

Blue specialists use `vigil blue dispatch` for L1/L2/L3/L4 work, run tenant-facing tools through `vigil assess host-exec` (`--require-audit` for WRITE/respond actions), record findings/artifacts through `vigil assess`, and split containment into proposal approval, audited execution, and `vigil blue contain` recording with a command-run id or proof artifact.

The public red/web roster is intentionally limited to the core roles: `operator`, `recon-specialist`, `source-analyzer`, `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`, and `report-writer`. Blue engagements expose `alert-triage-specialist`, `investigator`, `incident-verifier`, `ir-lead`, plus shared `osint-analyst` and `report-writer`. Validator-, chain-, and ranker-style behaviors are folded into those roles instead of creating a larger visible roster.

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state. User-facing exploit review should happen through the orchestrator UI or by telling Codex/Claude which findings are approved. Direct shell invocation of approval/session scripts is an internal maintenance path, not the primary operator workflow.

> **TODO** — first-class UI actions for exploit approval, session launch, and session merge are tracked as **R1** in [TODOv2.md](TODOv2.md#readme-extracted-todos-2026-06-02).

Methodology references:
- [engagement-methodology.md](agent/references/runtime-guides/engagement-methodology.md)
- [athena-log-investigation](agent/skills/athena-log-investigation/SKILL.md)

### Starting a code analysis engagement

Code analysis uses a separate operator loop (`agent/operator-core-code.md`) with its own four-phase pipeline: Ingest+Index → Classify+Map → Hunt → Verify+Variant. Findings land in the same backend as web engagements.

1. Create a code analysis engagement using `--type code`:
```bash
# Name only - add source code to the engagement later
vigil engagement create --type code my-project

# Name with a local repository
vigil engagement create --type code --name my-project --repo /path/to/repo

# Name with a clone URL
vigil engagement create --type code --name my-project --repo https://github.com/org/repo

# Combined web + code engagement
vigil engagement create --type both --name my-project --hosts app.example.com --repo /path/to/repo
```

This creates an engagement with `current_phase: "ingest"`, a `source/` directory for the repo checkout, and no web-target scaffolding (no hosts, no auth prompting). The engagement directory name is derived from the engagement name. Repositories are optional — source code can be cloned or placed into the `source/` directory after creation.

2. Bootstrap the code-analysis parser toolchain once on the machine:
```bash
vigil assess --help
```

`vigil assess` delegates to `agent/scripts/assess.py`, a `uv run --script` entrypoint with inline `tree-sitter`
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

`vigil doctor` covers the core operator CLI/runtime prerequisites. Fuzzing is
conditional; check the Homebrew tools directly when planning a fuzz campaign.

Homebrew's AFL++ package may provide `afl-clang-fast` or `afl-cc` instead of
`afl-clang-lto` on macOS; either compiler wrapper is acceptable for the workflow
as long as `afl-fuzz` and `afl-tmin` are present.

4. Start the client:
```bash
vigil engagement list --json
vigil engagement start <engagement-key> --client claude   # or --client codex
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

The runtime is a long-lived Kali Docker container started by `vigil runtime start`. Target-facing tool execution happens via `vigil assess kali ...` subcommands which call into the container via `docker exec`. Long-running scans go through `vigil assess kali job start ...`, which uses the in-container `dtach` supervisor so workers survive operator session exit.

`agent/docker/runtime-full/Dockerfile` is the main full runtime image and includes:

- Katana and Chromium for authenticated crawling
- ProjectDiscovery recon utilities including `httpx`, `dnsx`, `gau`, `katana`, `nuclei`, `dalfox`, `puredns`, `shuffledns`, `alterx`, `asnmap`, `cero`, and `bbot`
- nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, WhatWeb, hydra, john, hashcat, nikto
- `massdns` and `xmllint` for DNS-stack and XML coverage assertions
- `dtach` as the in-container supervisor for `vigil assess kali job` workers
- TruffleHog for filesystem/git secret scanning
- post-access tooling such as evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder
- pwncat-vl for interactive reverse shell handling, with tmux for session management
- interactsh for OOB callback detection (blind SSRF, XXE, XSS, DNS)
- frp SSH tunneling for exposing listeners and OOB servers to remote targets

A lightweight runtime also exists at `agent/docker/runtime-lightweight/Dockerfile`, but it is development-only for faster Dockerfile iteration and validation. Operator workflows, docs, and agent runtime assumptions all target `agent/docker/runtime-full/Dockerfile`. Build the lightweight image only with `vigil runtime build lightweight --dev`.


### Authentication

`vigil engagement create` seeds an anonymous `auth.json` (`mode: none`). Three ways to add an authenticated session later:

- Run `vigil mitmproxy start` (one proxy serves every active engagement) and browse through `127.0.0.1:8080` — `proxy_addon.py` matches the captured host against each engagement's `scope.json` and writes the cookies/headers to THAT engagement's `auth.json`. No engagement context is required at proxy-start time; multiple engagements can be authenticated in parallel without restarting the proxy.
- Run `vigil auth import <key> --source cookies-and-headers.json`.
- Edit `auth.json` directly.

`auth.json` carries:

- `mode`: `none`, `manual`, `auth_json`, or `proxy_capture` (set by whichever path populated the file)
- `use_for_requests`: whether crawling/recollection should apply the stored auth
- `auth_context`: the label used for authenticated request variants
- `expires_at`: optional ISO8601 expiry timestamp
- `cookies` and `headers`

If auth is expired or missing, the workflow warns and continues anonymously.

CLI helpers operate on engagement `auth.json`:

```bash
vigil engagement list --json
vigil auth status <engagement-key>
vigil auth show <engagement-key>
vigil auth import <engagement-key> --source cookies-and-headers.json
vigil auth clear <engagement-key>
```

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

| Capability | Default | Start command | Purpose |
|------------|---------|---------------|---------|
| MITM proxy | off | `vigil mitmproxy start` | Authenticated capture into per-engagement `auth.json`. |
| OOB (frp + interactsh) | off | `vigil oob start` | Out-of-band callback detection over shared frp/interactsh. |
| Universal ctags | host-installed | `brew install universal-ctags` | Richer code-analysis definition lookups. |

### MITM proxy

`vigil engagement create` prints whether mitmproxy is running and the start command if it is not. This subsection is the deep reference.

1. `vigil mitmproxy start` — the CLI builds the Docker image if needed, bind-mounts the install's `agent/engagements/` directory at `/engagements` (so the addon sees every engagement at once), persists the mitmproxy CA in a Docker volume, and verifies the local proxy port. No engagement context is required.
2. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow against any scoped host, then confirm that the matching engagement's `auth.json` was refreshed. Continue with authenticated recollection and testing. Use `vigil logs mitmproxy` for capture logs.

The addon routes each captured response to the engagement whose `scope.json` best matches the hostname (precedence: literal host > narrower wildcard > engagement `scope_priority` > most-recently-updated). After creating or scope-editing an engagement, `vigil mitmproxy reload` forces the addon to refresh its registry; `vigil mitmproxy routes` prints the current mapping for verification.

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

Configure OOB once, then let `vigil oob start` create or verify the shared frp/interactsh sessions.
The FRP token is required for OOB. `vigil up` prompts for it on first startup when it is missing
and stores the value in `vigil config`; non-interactive installs should set it first with
`vigil config set oob.frp_token <token>` or `VIGIL_FRP_TOKEN`.

```bash
vigil config set oob.frp_host researcher.example
vigil config set oob.frp_port 7000
vigil config set oob.domain researcher.example
vigil config set oob.frp_token <token>
vigil oob start
vigil oob status --json
vigil engagement list --json
vigil oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
vigil oob client logs example-agent --lines 80
vigil oob test
```

- **Tunnel setup, OOB callbacks, interactsh, frpc config:** `agent/references/offensive-tactics/frp-tunneling.md`
- **Shell listeners, pwncat-vl, reverse shell payloads:** `agent/references/offensive-tactics/shell-handling.md`

### OOB is single-tenant by design (post-flight conflict check)

`vigil oob start` registers proxies on frps with hardcoded server-side resources:
`remotePort = 53` (UDP), `remotePort = 8443` (TCP), and
`customDomains = researcher.example`. These are globally unique on frps, so
only one client at a time can own the OOB profile. The hostname-derived prefix
(`<container-id>-oob-*`) only avoids proxy *name* collisions; it does not
namespace the underlying ports/domains.

After spawning the `frpc` tmux session, `start_oob` tails
`/data/oob/frpc.log` for up to ~15s looking for success lines for all three
rendered proxies (`*-oob-dns`, `*-oob`, and `*-oob-rev`) or `port already
used` / `router config conflict` / `proxy name [...] already exists` from
frps. If a conflict is reported, the tmux sessions are torn down and the
command exits with the offending log lines verbatim. The check rides the
existing frp control connection — no extra channel (SSH forward, dashboard
tunnel, etc.) is required.

If the log shows neither outcome within the timeout, the command prints a
non-fatal hint pointing at `docker exec vigil tail -n 200
/data/oob/frpc.log` so the operator can inspect what frpc and frps are
actually saying. Override the wait via the `frpc_ready_timeout` argument to
`start_oob` (pass `0` to skip the scan entirely; tests do this).

> **TODO** — per-tenant OOB (multi-host concurrency) design is tracked as **R2** in [TODOv2.md](TODOv2.md#readme-extracted-todos-2026-06-02). Once it lands, the post-flight conflict scan above becomes a no-op and can be deleted.

## Command Reference

### `vigil` top-level commands

| Command | Purpose |
|---------|---------|
| `vigil install [path]` (alias `vigil update`) | Install/upgrade the working root in place; sync code, prompts, skills, scripts. Engagements, DB, and `.env` are preserved. |
| `vigil up` | Sync source, build stale images, start the local stack (runtime + orchestrator + optional mitmproxy/OOB). |
| `vigil doctor` | Check local readiness and prerequisites. |
| `vigil status` | Report live service state. |
| `vigil logs <target> [--lines N]` | Tail logs for `orchestrator`, `mitmproxy`, etc. |
| `vigil runtime start \| resources \| shell-exec \| build` | Manage the shared Kali runtime container. |
| `vigil orchestrator start` | Targeted start of the orchestrator backend/UI. |
| `vigil engagement create \| list \| start \| path \| cd-init` | Create and drive engagements. |
| `vigil assess ...` | Operator assessment surface (recon/findings/artifacts/kali tool verbs/resume). |
| `vigil blue ...` | Blue incident-response surface (customers, tenant init, engage, dispatch, contain, closeout, report). |
| `vigil auth status \| show \| import \| clear` | Manage engagement `auth.json`. |
| `vigil mitmproxy start \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| status \| client \| test` | Manage shared OOB (frp + interactsh). |
| `vigil config get \| set` | Read/write persistent CLI config (including OOB/FRP settings). |
| `vigil backup create \| list \| restore` | Manual orchestrator DB backup operations. |

> Each command documents its full flag set under `--help`. The runtime tool verbs live under `vigil assess kali --help`.

### Runtime tooling

The full Kali runtime image (`agent/docker/runtime-full/Dockerfile`) bundles, among others:

| Category | Tools |
|----------|-------|
| Authenticated crawling | Katana, Chromium |
| ProjectDiscovery recon | `httpx`, `dnsx`, `gau`, `katana`, `nuclei`, `dalfox`, `puredns`, `shuffledns`, `alterx`, `asnmap`, `cero`, `bbot` |
| Web scanning / fuzzing | nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, WhatWeb, hydra, john, hashcat, nikto |
| DNS / XML coverage | `massdns`, `xmllint` |
| Job supervision | `dtach` (in-container supervisor for `vigil assess kali job` workers) |
| Secret scanning | TruffleHog (filesystem/git) |
| Post-access | evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder |
| Shell handling | pwncat-vl, tmux |
| OOB / tunneling | interactsh (callback detection), frp (SSH tunneling) |

See [Runtime Model](#runtime-model) for the authoritative list and details.

## Operations

Heavier operational tuning: resource sizing tiers, container rlimits/ulimits, and orchestrator data/backups.

### Resource Sizing

| Tier | Memory | CPU | Swap | pids | nofile | Use case |
|------|--------|-----|------|------|--------|----------|
| Lab/CTF | 4 GB | 2 | 0 | 256 | 16384 | Single-target sequential testing |
| Standard (default) | 8 GB | 4 | 0 | 512 | 32768 | Small bounty target, 2-3 parallel agents |
| Heavy | 16 GB | 8 | 0 | 1024 | 65536 | Large enterprise scope, 4-6 parallel specialists |
| Comfortable | 32 GB | 12 | 4 GB | 2048 | 131072 | All tools warm, continuous engagement |

Configure via env vars before `vigil runtime start`:

```bash
VIGIL_RUNTIME_MEMORY_GB=16 VIGIL_RUNTIME_CPUS=8 vigil runtime start
```

Live state: `vigil runtime resources`.

Gotchas:

- Docker Desktop Mac default 4 GB is too low — raise via Settings > Resources to at least the Standard tier.
- WSL2 defaults to 50% of host RAM capped at 8 GB — pin via `%USERPROFILE%\.wslconfig` `[wsl2] memory=12GB processors=8 swap=4GB`.
- Apple Silicon unified memory tolerates up to 50% of host RAM.

### Container resource limits (optional)

The runtime image does not pin process or file-descriptor rlimits. `docker exec`-launched tools inherit dockerd's daemon defaults — generous on Linux hosts (`nofile=1048576`, `nproc=unlimited`) but tighter on Docker Desktop (`nofile=8192`, `nproc=4096`). `vigil runtime start` probes the live limits and prints a stderr WARN when they fall below recommended thresholds.

To raise the daemon defaults so they apply to every container (including `docker exec`-launched specialists), edit `/etc/docker/daemon.json` (Linux) or Docker Desktop → Settings → Docker Engine, then restart dockerd:

```json
{
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 131072, "Soft": 131072 },
    "nproc":  { "Name": "nproc",  "Hard": 16384,  "Soft": 16384 }
  }
}
```

Container-side `/etc/security/limits.conf` is not used because `docker exec` does not invoke a PAM session.

### Orchestrator data and backups

The orchestrator UI is served from the backend at `http://127.0.0.1:18000` once `vigil up` (or `vigil orchestrator start` for a targeted start) is running.

The backend stores canonical engagement state in a single SQLite file and keeps rotated snapshots next to it:

- **Live DB**: `<install-root>/orchestrator/backend/data/orchestrator.sqlite3`
- **Scheduled backups**: `<install-root>/orchestrator/backend/data/backups/orchestrator.<UTC-timestamp>.sqlite3` — a WAL-coherent snapshot every 15 minutes, last 12 copies retained by default (~3 hours of continuous coverage; override with `VIGIL_BACKUP_MAX_COPIES`). Written by the backend process itself; independent of the per-engagement snapshot that `vigil engagement create` takes before creating an engagement.

Override the data location with env vars (first match wins):

- `VIGIL_DATA_DIR` — absolute path to the directory that holds `orchestrator.sqlite3` and `backups/`
- `REDTEAM_ORCHESTRATOR_DATA_DIR` — legacy alias of the same setting
- `VIGIL_INSTALL_DIR` — install root; the DB is then read from `$VIGIL_INSTALL_DIR/orchestrator/backend/data/`

Both the backend and `vigil engagement create` honor the same precedence so snapshots and the live DB always target the same file. Engagement deletion is explicit: `DELETE /engagements/<key>?confirm=<key>` or the frontend delete button with a typed-key confirmation. Renaming or removing an engagement directory under `agent/engagements/` leaves the DB row intact — no cascade delete.

Backup cadence tuning (optional):

- `VIGIL_BACKUP_DISABLED=1` — turn off the scheduled backup entirely (used by the test suite)

Manual backup operations:

```bash
vigil backup create
vigil backup list
vigil backup restore <backup-name-or-path>
```

## Security

Vigil ships a **full offensive Kali runtime** and drives autonomous specialist agents against live targets. Treat it accordingly:

- **Authorized targets only.** Every operator start prompt begins with an explicit authorization statement, and engagement scope is pinned in `scope.json`. Only run against hosts/tenants you are contractually authorized to test.
- **Exploit work is gated.** The default exploit policy is `pause` — explicit human approval is required before any exploit-developer dispatch. Policies (`pause` / `selected` / `full_send`) are set per engagement in `scope.json` and enforced through the operator workflow.
- **Operator-controlled infrastructure.** Tunnels (frp), listeners (pwncat-vl), and OOB callback servers (interactsh) are operator-controlled shared infrastructure — agents provide commands but never start them. See [Callback, Listener & Tunnel Handling](#callback-listener--tunnel-handling).
- **Blue write-actions are audited.** Tenant-facing WRITE/respond actions run with `--require-audit`, and containment is split into proposal approval, audited execution, and explicit recording.

Deeper guidance lives in [`agent/AGENTS.md`](agent/AGENTS.md) (operator workflow), the reference library under [`agent/references/`](agent/references/) (browse with `vigil assess list-references`), and the per-engagement `scope.json`.

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

For repo-local development conventions used by Codex, see the root `AGENTS.md` — it carries the
clone-to-first-dispatch newcomer walkthrough and step-by-step recipes for adding a skill, an
`vigil assess` verb, a deterministic oracle, or an eval case.

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
docker build -t vigil:latest -f agent/docker/runtime-full/Dockerfile .
vigil runtime resources
```

## Roadmap & TODO

The framework backlog lives in [TODOv2.md](TODOv2.md) (canonical `C#` IDs, Done ledger, and active backlog). README-extracted design items are tracked under [README-extracted TODOs](TODOv2.md#readme-extracted-todos-2026-06-02):

- **R3 — Web3-focused workflow** (deferred): evaluate an optional Web3-focused workflow and agent set only after the core web/app investigation model is stable.
- **R4 — Rate-limit policy and aggregate enforcement**: programs commonly cap aggregate request rate (LastPass requested 5 req/s; many enterprise VDPs sit in the 5–20 range). Per-verb flags exist but nothing enforces an engagement-wide aggregate across parallel dispatches; the design space is captured in TODOv2.md.
