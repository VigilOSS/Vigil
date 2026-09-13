<div align="center">

# Vigil

**AI-driven offensive and incident-response engagements — operator prompts, a full Kali runtime, and durable orchestrator state in one CLI.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/vigil-oss/vigil)

</div>

This repository contains the operator prompts, Kali runtime image, engagement scaffolding, and orchestrator services used to run those engagements.

> **Authorized use only.** Vigil can autonomously drive offensive tooling against live systems.
> Use it only where you have explicit authorization and a reviewed scope. It is provided without
> warranty under the [Apache License 2.0](LICENSE); you are responsible for commands, credentials,
> infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private vulnerability
> reporting and the operator-data boundary.

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
- [Implementation Plans](#implementation-plans)

## Documentation

Vigil's docs are spread across operator prompts, a code map, and a deep reference tree. Start here:

| Document | What it covers |
|----------|----------------|
| [`agent/AGENTS.md`](agent/AGENTS.md) | The operator prompt — the workflow every engagement runs. |
| [`docs/engagement-prompt-playbook.md`](docs/engagement-prompt-playbook.md) | Operator steering playbook — the human-side prompts for pushing an engagement when the model goes shallow, overclaims severity, or forgets the core loop. |
| [`docs/benchmarking.md`](docs/benchmarking.md) | The `vigil bench` harness — generated-suite diagnostics, launch modes, scoring, cost accounting, and the participant-isolation work still required before a live result qualifies as a clean capability measurement. |
| [`docs/goose-bench.md`](docs/goose-bench.md) | Running Vigil on **Goose** (`--client goose`) — the primary open-model client (headless multi-agent on DeepSeek). Setup, architecture, and the thinking-mode caveat. |
| [`docs/deepseek-openrouter.md`](docs/deepseek-openrouter.md) | Running Vigil on **OpenCode** (`--client opencode`) against DeepSeek (direct or via OpenRouter). |
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

# 2. Run the onboarding wizard: it checks host prerequisites, reports missing
#    recon tools, and prints the ordered setup checklist for your install root.
vigil quickstart

# Pass --install-host-tools to actually run the host-tool install commands
# (default is plan/print only); --json for a machine-readable readiness report.
```

`vigil quickstart` is the front door — it never mutates the host unless you pass
`--install-host-tools`, so it is safe to run first to see exactly what is missing.
It then hands you the ordered commands to finish setup:

```bash
# 3. Install a working root and bring the local stack up (Kali runtime + orchestrator)
vigil install ~/vigil && vigil up

# 4. Create an engagement against an authorized target
vigil engagement create https://target.example --hosts target.example

# 5. Start the operator on it
vigil engagement start <engagement-key> --client codex   # or --client claude
```

Steps 3-5 are the manual/recovery path — run them directly at any time. The full
install / update / stack walkthrough is below; heavier operational tuning lives under
[Operations](#operations).

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

Vigil is currently distributed from source; no PyPI release is published or supported. Pin a Git
revision for reproducible installs, or use the editable checkout command for development.

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

The installer also refreshes generated client launchers in existing engagements when their original client and permission mode can be proven from installed state. Ambiguous legacy engagements are preserved and reported as skips by default. After reviewing those named engagements and explicitly approving autonomous permissions, reconcile only the recognized/configured ambiguous cases with:

```bash
vigil install ~/vigil --repair-ambiguous-client-permissions-as-skip
```

This exceptional override normalizes recognized generated conflicts and config-only legacy engagements to Codex `--dangerously-bypass-approvals-and-sandbox`, Claude/OpenCode `--dangerously-skip-permissions`, and Kimi `--auto`. It does not modify clientless engagements or unrecognized/custom launchers.

Legacy engagements may also contain physical client-roster directories instead of links to the current generated roster. The installer reports and preserves those directories by default. After backing them up, explicitly refresh only their canonical generated files in place with:

```bash
vigil install ~/vigil --refresh-physical-client-rosters
```

This additive repair covers `.codex/agents`, `.claude/agents`, both OpenCode roster spellings, and `.goose/recipes`. It retains every unknown or extra file, never deletes roster content, and stops before writing if a roster contains a symlink, incompatible file type, or path escape. The flag can be combined with `--repair-ambiguous-client-permissions-as-skip` when both reviewed legacy repairs are authorized.

#### Two layers: the CLI binary vs. the working root

Vigil has two layers that upgrade independently:

- **The CLI binary** (`vigil` itself) — installed and upgraded with `uv tool install` / `uv tool upgrade vigil`. This is only the operator command-line tool.
- **The working root** (`~/vigil` — the `agent/` tree of code, prompts, skills, and scripts, plus the orchestrator) — installed and upgraded with `vigil install` / `vigil update` (or `vigil up`, which syncs first).

Upgrading one does **not** upgrade the other. The common failure mode (issue I-5) is upgrading the CLI binary while leaving the working root behind: the newer CLI expects prompts/skills/scripts that the stale working root does not yet have, so the affected features are silently inert.

To guard against this, every sync path — `vigil install`, `vigil update`, and `vigil up` — stamps a SHA-256 manifest of the managed tree actually copied into `~/vigil/.vigil-install-meta.json`, then status compares it with the same normalized manifest over the live source. Records frame entry type, path, file mode, length, and exact bytes; caches/build outputs, installer-created preserved-path ancestors, and preserved engagement/database state are normalized by the same rules as the copier. Source and destination ancestry plus every copied child are opened through pinned, no-follow directory descriptors; candidate files are opened nonblocking and accepted only after descriptor type checks, and regular destination files (including the install stamp) are atomically replaced. The destination-root descriptor stays open through the install. Later roster, entrypoint, OOB, stamp, and image-build helpers run inside a globally locked, scoped working directory established with `fchdir` on that descriptor, so root-relative filesystem and Docker-context paths start from the copied root inode even if its public name is replaced; the original working directory is descriptor-restored on success or failure, and attachment checks abort after a detected replacement. This bridge pins the root name only: preflight and the descriptor-native copy reject child links, but the legacy path-based repair/build helpers do not claim to defeat a concurrent same-UID replacement of a descendant after validation. Because `fchdir` changes process-global state, the lock serializes installer scopes; unrelated threads must not perform relative-path I/O concurrently (the supported CLI callers are synchronous). This closes the copy-then-hash race, makes executable-bit changes visible, reconciles removals and file/directory changes, prevents hardlink aliases from being overwritten, and prevents detected symbolic-link or root-replacement traversal from redirecting install side effects. Derived root entrypoints (`AGENTS.md`, `CLAUDE.md`, `.codex`, `.claude`) are reconciled in the same pass, including removal when their source disappears, while generated launcher and hook content retains the requested absolute install path. The stamp also retains the source revision for provenance and commit-distance reporting. Freshness therefore sees unsnapshotted Jujutsu edits without mutating the working copy, while later snapshotting identical bytes does not create a false stale warning. Revision-only stamps from older installs retain their original comparison behavior until the next install. The write lives in the sync itself, so the three paths cannot disagree. Three surfaces report a non-fatal warning when those manifests differ, or when the stamp is missing because the install predates this guard:

- `vigil status` — a `warn` line in the status table.
- `vigil doctor` — an `install_staleness` check (`OK` / `STALE`, `SKIPPED` when no readable source can be compared).
- `vigil assess ...` — a `[vigil] WARN: install root <path> is stale ...` line on stderr before the passthrough execs. It never blocks the call.

If you see any of them, run `vigil install` (or `vigil up`) to refresh the working root. To upgrade the CLI binary itself, run `uv tool upgrade vigil`. A stale working root is also the first thing to check when a documented `vigil assess` verb, flag, or skill appears not to exist — argparse reports it as an "invalid choice" rather than as a version mismatch.

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

### Recon runtime: host vs. container, and the host-side tools

Most target-facing tools run **inside** the shared `vigil` container. The exception is the
**DNS-heavy and bulk-liveness** recon stages, which on **macOS/Windows Docker Desktop** must run
on the **host**: Docker Desktop proxies every container packet through a userspace proxy
(`com.docker.backend`) that NAT-tracks state *per distinct destination IP*, so a DNS brute over a
large resolver set — or a bulk `httpx` liveness pass over thousands of hosts — saturates that table
and wedges the whole VM (engagement I-001). The split:

| Stage / tool | Runs | Why |
|---|---|---|
| `subfinder`, `dnsx`, `puredns` (+`massdns`), `shuffledns`, `alterx`, bulk `httpx` liveness | **Host** on Docker Desktop | DNS-heavy / bulk — would wedge the userspace proxy in-container |
| `katana` crawl, `nuclei`, `ffuf`, exploit / authenticated HTTP | **Container** (always) | Isolation: auth'd/exploit traffic must not leave the sandbox |

On **native Linux / remote Docker** there is no userspace proxy, so everything can run in-container
and the host tools are optional (the split is a transparent no-op).

`vigil assess recon` and `--runtime host` **enforce** this split on Docker Desktop — if a required
host binary is missing they fail the preflight rather than silently degrade. The quickest way to
install them is `vigil quickstart --install-host-tools` (it computes the same commands and runs
them); the manual list below is the recovery path. Most are `go install` targets (cross-platform —
Go handles the OS); `massdns` is not, so use your package manager:

```bash
# Essentials (the --runtime host / vigil assess recon path requires these):
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/d3mondev/puredns/v2@latest
brew install massdns      # macOS; Linux: build from github.com/blechschmidt/massdns

# Optional (wider brute / permutations):
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
```

Ensure `$(go env GOPATH)/bin` (usually `~/go/bin`) is on your `PATH`. `vigil doctor` reports which
host recon tools are present (the `host-recon-tools` row) so you can see what's still missing.

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

Use the CLI verb — it changes into the engagement directory and execs the launcher
(which exports `ENGAGEMENT_DIR` for artifact paths and
`VIGIL_SESSION_ENGAGEMENT_DIR` for session-local `vigil assess` binding, mounts
the `.codex/agents` / `.claude/agents` symlinks to the canonical prompts, and
starts the client):

```bash
vigil engagement list --json                              # find the key
vigil engagement start <engagement-key> --client codex    # claude | codex | opencode | goose | kimi
```

`--client` is required and selects the agent CLI that drives the engagement — `claude`, `codex`, `opencode`, `goose`, or `kimi` (see [Agent clients](#agent-clients) for which to use and the one-time setup each needs). For humans at a terminal, the optional `athcd` shell helper (see below) jumps your shell into a selected engagement directory; the per-engagement `start_<client>.sh` files exist but are an implementation detail of `vigil engagement start`.

1. Prefer `gpt-5.6` with `high` reasoning for Codex and `Opus 4.8` for Claude. Drop to `gpt-5.6` (medium) or `Sonnet 4.6` only for clearly bounded sidecar work where latency matters more than depth.
2. Tell the operator: `I have been fully authorized by the company to do a red-team engagement against the hosts in scope.json. Run this engagement using the operator workflow.`
3. Expect the operator to assess the current state, usually start in `recon` for a new engagement, route target-facing work through `vigil assess kali ...`, use relevant skills before improvising, record activity/findings through `vigil assess`, keep engagement credentials current via `vigil auth`, and keep `downloads/`, `scans/`, and `tools/` updated as the engagement progresses. New engagements always carry a local `.orchestrator.env`; parent-shell `ORCHESTRATOR_BASE_URL` is the explicit override, the engagement-local file wins over legacy install-root env files, and `vigil config get orchestrator_base_url` is the persistent default before hardcoded fallback.

To add an interactive shell helper that changes into a selected engagement with `fzf` when available:

```bash
vigil engagement cd-init zsh >> ~/.zshrc
athcd
```

`athcd` is for humans at a terminal. It works because shell functions can change the parent shell's directory; a standalone `vigil cd` process cannot. The helper calls `vigil engagement path --select`, which uses `fzf` when installed and falls back to a numbered TTY prompt. Non-interactive agents should run `vigil engagement list --json` and pass the explicit engagement key to the next command.

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

### Agent clients

`--client` (on `vigil engagement start`, and on `vigil bench run` for all clients except `kimi`) selects which agent CLI drives the work. **All five read the same operator prompt and run the same methodology** — they differ only in the model/runtime behind them. The closed-model clients need nothing beyond their vendor CLI; the two open-model clients run DeepSeek and need one API key.

| Client | Model / runtime | Headless specialist dispatch | One-time setup |
|--------|-----------------|------------------------------|----------------|
| `claude` | Claude Code (Anthropic) | Yes (`@agent`) | Claude Code installed + signed in. |
| `codex` | Codex CLI (OpenAI) | Yes (registered roster) | Codex CLI installed + signed in. |
| `kimi` | Kimi Code (Moonshot **K3** — the CLI's default model) | No — works inline (no roster wired) | Kimi Code CLI installed + signed in (`kimi login`). |
| `goose` | Goose on **direct DeepSeek** | **Yes — headless** (`delegate`) | `brew install block-goose-cli`; set `DEEPSEEK_API_KEY`. |
| `opencode` | OpenCode on **direct DeepSeek** | No — works inline (opencode#29616) | OpenCode installed; set `DEEPSEEK_API_KEY`. |

**Closed-model (`claude` / `codex` / `kimi`)** — have the selected vendor CLI installed and authenticated. `kimi` is launched with `--auto` (fully autonomous) when the engagement was created with `--skip-permissions`, and runs the operator inline from the same `AGENTS.md`; it currently has no generated specialist roster or scope-guard hooks, and is not yet a `vigil bench run --client` option.

**Open-model (`goose` / `opencode`)** — set your DeepSeek key once in the install root's env and the launcher exports it to the client automatically:

```bash
echo 'DEEPSEEK_API_KEY=sk-...' >> ~/vigil/.env     # the install root's env file
```

- **`goose` is the recommended open-model client.** Unlike OpenCode it dispatches custom specialist subagents headlessly *and* its anti-cheat hook fires inside them. Install once (`brew install block-goose-cli`), then:

  ```bash
  vigil engagement start <key> --client goose                      # defaults to --model deepseek-v4-pro (thinking)
  vigil bench run --provider generated --families bola-rest-graph --seeds 0 \
    --client goose --model deepseek-v4-pro --reasoning high --launch auto
  ```

  Thinking-mode V4 (`deepseek-v4-pro` / `-flash`) runs on the **direct** DeepSeek path — `start_goose.sh` launches a local reasoning-content repair proxy in front of DeepSeek so multi-tool thinking turns don't 400 (see the callout below). OpenRouter remains an alternative transport. No `.goose` folder setup is required: `vigil engagement create` writes the engagement's `.goosehints` (operator prompt), recipe roster, and hooks for you.

  > **⚠️ Note — the Goose thinking path depends on a stopgap.** Thinking-mode DeepSeek-V4 on Goose's direct provider works around **[aaif-goose#9397](https://github.com/aaif-goose/goose/issues/9397)** via a local reasoning-content repair proxy (`src/vigil_cli/bench/goose_reasoning_proxy.py`, started by `start_goose.sh`). Goose splits a parallel-tool-call assistant turn into N messages but keeps `reasoning_content` only on the first, and DeepSeek 400s on the rest; the proxy re-attaches it. `parallel_tool_calls:false` does **not** help — DeepSeek ignores the flag. **This is a stopgap until #9397 is fixed upstream — remove the proxy then.** Opt out with `VIGIL_GOOSE_REASONING_PROXY=0` (thinking then regresses to the #9397 400 on any batched-tool turn). Details: [`docs/goose-bench.md`](docs/goose-bench.md).

- **`opencode`** runs the operator inline (it cannot dispatch custom specialists headlessly) and requires a `--thinking` level:

  ```bash
  vigil engagement start <key> --client opencode --thinking high
  ```

  Details and the OpenRouter alternative: [`docs/deepseek-openrouter.md`](docs/deepseek-openrouter.md).

### Engagement operator start prompts

Two forms. Use the **generic** form to start a fresh engagement after `cd`-ing into the engagement directory. Use the **resume** form when handing off between sessions or picking up where a previous agent left off.

#### Generic — new or resumed engagement (simple form)

After `vigil engagement start <key> --client <client>`:

```
Read AGENTS.md and assume Operator role.

Authorized bug-bounty engagement: https://bugcrowd.com/engagements/<slug>
Full authorization confirmed. Run the operator workflow. Take full advantage of specialist agents
to delegate all target-facing work — dispatch in parallel where phases permit. Prefer
claude-opus-4-8 / gpt-5.6 xhigh reasoning for operator-level and substantial specialist work;
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
Prefer claude-opus-4-8 / gpt-5.6 xhigh for substantial work; medium only for bounded sidecar tasks.
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
  [--command-run-id <n>]`; the backend computes SHA-256 and links to a
  finding/chain/surface/request-variant/command-run. Ordinary registered text is
  hashed and indexed in full with a 4 KiB preview. Verified command-output rows
  use the retention owner's bounded 16 KiB sample and report
  `index_status=partial` when that sample is shorter than the retained output;
  no match in a partial row does not prove the full output lacks the text.
  `mark-scratch <path-or-id>` dismisses a registered note as scratch so
  `check-phase-readiness --phase report` no longer blocks on it (the escape valve for operator or
  specialist working notes that are not durable engagement memory).
- `vigil assess proof-run start|begin|finish|list|get` and
  `vigil assess run-audit <sources|source-read|obligation|candidate|tool-signal|discovery-pass|code-receipt|compare> ...`
  — shared code/web/blue run accounting. Scan runs start queued, record exact target,
  source-generation and exclusion identity, then move to running. The trusted
  source-read command streams inventoried bytes and records the exact delivered
  ranges. Typed sanitizer/crash/OOB signals create deterministic candidates;
  discovery passes retain attributed workflow evidence without claiming model
  comprehension, and a code scan cannot complete until its latest pass records
  an evidence-backed terminal frontier outcome. Exact generation-bound
  variant/fuzz receipts resolve their matching obligations only when a healthy
  artifact proof matches the receipt's evidence path and digest, without copying
  the owning receipt. Open hard debt or missing proof makes a requested completion a sealed
  `partial` result rather than a false success. The orchestrator's Runs tab shows
  lifecycle, provenance, evidence health, paged work records and deterministic
  baseline comparisons, with every recorded value rendered verbatim.
- `vigil assess export submission <slug> --platform <bugcrowd|hackerone|direct>`
  — renders the finding-backed `submission.md` and, in final mode, creates a
  staged, hash-verified immutable version through the backend. Attachments are
  opt-in via repeatable `--attachment-id`; none preserves the exact Markdown,
  while selected registered/hash-valid artifacts produce a deterministic ZIP
  and manifest. `vigil assess export submission --recover` reconciles interrupted
  exports, retains the caller surface in the activity ledger, and consumes every
  bounded failed-version and orphan-diagnostic page. The adjacent Submissions tab
  provides the same review, attachment, export, recovery, paged finding/history,
  and download workflow for humans. Neither path
  changes external submission status or sends anything to a platform.
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

# Interactive: bare engage prompts for customer / platform / severity, then creates the engagement.
vigil blue engage

# One-shot: fill the slugs and chain straight into the operator session with --start.
vigil blue engage --customer <customer-slug> --platform gws --severity high --start codex
```

`vigil blue engage --start <codex|claude|opencode|goose>` creates the engagement
and then execs the operator client in the engagement dir (no manual `cd` or
`vigil engagement start`). Because `--start` replaces the process with an
interactive client, do **not** combine it with command substitution — a capture
like `eng=$(vigil blue engage … --start codex)` would feed the client the
captured stdout. Scripts that need the path (`eng=$(vigil blue engage …)`) must
omit `--start`.

Tell the operator: `I have been fully authorized by the company to run a blue-team incident-response engagement for the tenant in scope.json. Run this engagement using the blue operator workflow.` Then paste the alert into the operator chat. The operator records intake by piping the pasted alert straight into `vigil blue alert record --body-file -` (heredoc) — the CLI writes the canonical `ir/alerts/` copy, so no separate file is saved first. Every engagement finishes with either `vigil blue closeout` or `vigil blue report`.

The retired `vigil blue dispatch` wrapper is replaced by the shared dispatch
surface:

```bash
vigil assess agent start --role <blue-role> --tier <L1|L2|L3|L4> \
  --skills <names> --rate-budget '<authored tenant query budget>' \
  --prompt-context-json dispatch-context.json --emit-prompt
```

Use `--no-target-traffic` instead of `--rate-budget` for a genuinely offline
lane. The emitter reads the
blue engagement's `customer`, `platforms`, and `tenant_reference_paths` from
`scope.json`, validates every tenant reference, and prints the complete prompt.
The prompt-context JSON shape is documented in
[`dispatch-template.md`](agent/references/runtime-guides/dispatch-template.md).

Upgrade preservation: existing `scope.json.rate_limit_aggregate_rps` keys are
left untouched as ignored historical configuration. On first startup, any
legacy aggregate-rate lease rows are copied losslessly into internal
`assessment_rate_lease_history`, checked by row count and deterministic digest,
and recorded with the verified pre-migration backup path, byte size, and SHA-256
in `schema_migrations` before the retired active table is removed. No rate-lease
API or execution gate remains.

Blue specialists run tenant-facing tools through `vigil assess host-exec` (`--require-audit` for WRITE/respond actions), record findings/artifacts through `vigil assess`, and split containment into proposal approval, audited execution, and `vigil blue contain` recording with a command-run id or proof artifact.

The public red/web roster is intentionally limited to the core roles: `operator`, `recon-specialist`, `source-analyzer`, `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`, and `report-writer`. Blue engagements expose `alert-triage-specialist`, `investigator`, `incident-verifier`, `ir-lead`, plus shared `osint-analyst` and `report-writer`. Validator-, chain-, and ranker-style behaviors are folded into those roles instead of creating a larger visible roster.

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state. User-facing exploit review happens by telling Codex/Claude which findings are approved. Direct shell invocation of approval/session scripts is an internal maintenance path, not the primary operator workflow.

Methodology references:
- [engagement-methodology.md](agent/references/runtime-guides/engagement-methodology.md)
- [athena-log-investigation](agent/skills/athena-log-investigation/SKILL.md)

### Starting a code analysis engagement

Code analysis uses a separate operator loop (`agent/operator-core-code.md`) with its own pipeline:
Ingest+Index → Classify+Map → Hunt → Verify+Variant → optional Fuzz. Findings land in the same
backend as web engagements and are bound to the sealed source generation they prove.

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

6. The operator will clone/locate the repo under `source/`, run `code-ingest` to publish a
content-addressed read-only snapshot, build/sync the structural index against the printed repo ID
and snapshot path, then drive through classify+map → hunt → verify+variant. Specialists read the
sealed snapshot; the mutable origin is retained only as provenance. At refresh commit the backend
independently validates the engagement-owned v2 manifest, real source bytes, staged inventory, and
declared counts before it records the snapshot as `verified`; an API caller cannot grant that trust
state by supplying the label alone.

Code-analysis transitions use two independent signals. Structural/lifecycle readiness is the hard
gate and includes current snapshot/index/threat-model identity plus phase-specific completion:

```bash
vigil assess code-coverage --require-transition-ready <classify-map|hunt|verify-variant|fuzz|complete>
```

Review quality is advisory steering for the operator, not permission to cross a phase boundary:

```bash
vigil assess code-coverage --cwe-matrix
vigil assess code-coverage --require-gate-pass   # optional strict quality-remediation exit signal
```

Source-identity, current structural-metadata, and unreviewed structural-debt integrity blockers
cannot be forced. Ordinary phase-completion blockers may be crossed only with
`transition-phase <target> --force --reason "<why>"`, which records a durable override decision.
A weak quality score should trigger more focused review; `--require-transition-ready` remains the
read-only authority for the target phase's actual blocker set.

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

A new engagement starts with no stored credentials (anonymous). Engagement credentials live in the orchestrator backend (the `engagement_credentials` table, one record per `(engagement, identity)`) and are managed entirely through the `vigil auth` CLI — there is no `auth.json` file on disk. Three ways to add an authenticated session later:

- Run `vigil mitmproxy start` (one proxy serves every active engagement) and browse through `127.0.0.1:8080` — `proxy_addon.py` matches the captured host against each engagement's `scope.json` and POSTs the captured cookies/headers to THAT engagement's credential store. Capture is append-only and multi-identity: the identity name is derived server-side from the login's session-anchor cookies (or a JWT `sub`), so a second, distinct login on the same host appends a new identity instead of overwriting the first, while reloading the same login refreshes that one identity in place. No engagement context is required at proxy-start time; multiple engagements can be authenticated in parallel without restarting the proxy.
- Run `vigil auth import <key> --source cookies-and-headers.json`. The JSON is the material itself — `{"cookies": {...}, "headers": {...}, "tokens": {...}}` (each optional), plus an optional `material.liveness` block. Do **not** wrap it in `{"material": {...}}`: the wrapper is the shape an export produces, it carries no replayable material at the top level, and the import refuses it by name rather than storing an empty identity.
- Run `vigil auth edit <key>` to fetch the current identity, edit it in `$EDITOR`, and save it back.

Each credential record carries:

- `use_for_requests`: whether crawling/recollection should apply the stored auth
- `auth_context`: the label used for authenticated request variants
- `expires_at`: optional ISO8601 expiry timestamp
- `state` (`available`/`stale`/`dead`/`expired`) and freshness fields (`created_at`, `last_seen_at`, `liveness_verdict`, `last_probed_at`)
- `cookies` and `headers`

A session that has neither been re-captured nor replayed for 8h is flagged `stale` (advisory — re-probe it); after 5 days it is purged. Both clocks read `last_seen_at`, which a resolve-for-replay refreshes as well as a capture — otherwise an identity in constant use would still age out. Read-only inspection does not: `vigil assess auth status` without `--probe` resolves with `record_use=false`, so looking at a session never resets the clock the backstop exists to measure. Age never marks a session `dead` — only a proven-dead liveness probe does, and that probe now requires positive evidence: a configured `dead_marker` hit, or a response that is itself an authentication challenge. A missing marker, an unexplained status mismatch, and a `403` all report `unknown` and leave the identity usable — a `403` is an authorization verdict, and on another principal's object it is the signal you were testing for. If auth is expired, dead, or missing, the workflow warns and continues anonymously.

CLI helpers operate on the backend credential store for an engagement:

```bash
vigil engagement list --json
vigil auth status <engagement-key>
vigil auth show <engagement-key>
vigil auth import <engagement-key> --source cookies-and-headers.json
vigil auth set-active <engagement-key> --identity user_a
vigil auth alias <engagement-key> --name member --principal jwt:sub:user-42 --scope billing
vigil auth env-check <engagement-key> --keys APP_USER APP_PASSWORD
vigil auth clear <engagement-key>
```

Agents list every stored identity for a host — name, `auth_context`, `state`,
liveness verdict, age, and cookie names (never raw values), with the active
identity marked `*` — via `vigil assess auth list --host <host>
[--include-dead] [--json]`, and prove a specific identity's liveness before
trusting it with `vigil assess auth status --probe --identity <name>
--probe-url <authed-url> --scope <logical-scope>` (operator equivalent: `vigil
auth status --probe --identity <name> --probe-url <authed-url> --scope
<logical-scope>`). Execute through a scoped alias with both `--identity <alias>`
and `--identity-scope <logical-scope>`; Vigil does not infer logical liveness
scope from the destination hostname.

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

| Capability | Default | Start command | Purpose |
|------------|---------|---------------|---------|
| MITM proxy | off | `vigil mitmproxy start` | Authenticated capture into each engagement's backend credential store. |
| OOB (frp + interactsh) | off | `vigil oob start` | Out-of-band callback detection over shared frp/interactsh. |
| Universal ctags | host-installed | `brew install universal-ctags` | Richer code-analysis definition lookups. |

### MITM proxy

`vigil engagement create` prints whether mitmproxy is running and the start command if it is not. This subsection is the deep reference.

1. `vigil mitmproxy start` — the CLI builds the Docker image if needed, bind-mounts the install's `agent/engagements/` directory at `/engagements` (so the addon sees every engagement at once), persists the mitmproxy CA in a Docker volume, and verifies the local proxy port. No engagement context is required.
2. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow against any scoped host, then confirm that the matching engagement's stored credentials were refreshed (`vigil auth status <key>`, or `vigil assess auth list --host <host>` for the full identity list). Continue with authenticated recollection and testing. Use `vigil logs mitmproxy` for capture logs.
3. To hold a second identity for cross-account (IDOR/BOLA) testing, log in as the other account through the same proxy — the addon detects the different session-anchor material and appends a new identity rather than overwriting the first.

The addon routes each captured response to the engagement whose `scope.json` best matches the hostname (precedence: literal host > narrower wildcard > engagement `scope_priority` > most-recently-updated). After creating or scope-editing an engagement, `vigil mitmproxy reload` forces the addon to refresh its registry; `vigil mitmproxy routes` prints the current mapping for verification.

If you need HTTPS interception, install the mitmproxy CA certificate in the browser or device before logging in.

In the engagement flow, this usually happens during `recon` or `collect` when anonymous coverage is insufficient, or later when a previously working authenticated session has expired or gone `dead` (proven with `vigil auth status --probe --identity <name> --probe-url <authed-url>`).

### ctags for code analysis

Code analysis agents use ctags for fast definition lookups and grep/rg for call site enumeration.
`code-ingest` generates an advisory, generation-bound ctags index under the engagement's
`tools/analysis-state/ctags/` tree. It never writes a `tags` file into the source repository.

macOS ships BSD ctags which is limited. Install Universal ctags for best results:

```bash
brew install universal-ctags
```

Universal ctags produces richer tag data (signatures, kinds, line numbers). Vigil resolves a
trusted executable outside the analyzed repository and indexes only manifest-admitted files.
Without trusted ctags available, agents fall back to grep-only cross-references.

## Callback, Listener & Tunnel Handling

Tunnels (frp), listeners (pwncat-vl), and OOB callback servers (interactsh) are **OPERATOR-CONTROLLED** shared infrastructure. Agents provide commands but never start them.

Configure OOB once, then let `vigil oob start` create or verify the shared frp/interactsh sessions.
The FRP token is required for OOB. `vigil up` prompts for it on first startup when it is missing
and stores the value in `vigil config`; non-interactive installs should set it first with
`vigil config set oob.frp_token <token>` or `VIGIL_FRP_TOKEN`.

```bash
vigil config set oob.frp_host oob-relay.example.com
vigil config set oob.frp_port 7000
vigil config set oob.domain oob.example.com
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

### Per-tenant OOB routing and upgrade behavior

A fresh `vigil install` creates `.runtime-data/oob/tenant-routing.json` atomically after an OOB
domain is configured. Without `oob.frp_host` and `oob.domain`, normal install and non-OOB workflows
remain available, while `vigil oob start` stops before Docker and prints the exact two configuration
commands. Vigil ships no maintainer-owned fallback infrastructure.
The record pins a DNS-safe tenant prefix, a tenant subdomain, and a two-port FRP
block. `vigil oob start`, client metadata, status/doctor, `vigil assess`, and
Nuclei `--oob-mode vigil` all resolve that record; changing an ambient
`VIGIL_OOB_DOMAIN` cannot silently redirect a persisted Vigil tenant to an
external Interactsh service. Set `oob.tenant` before the first install when the
install-directory name is not the desired tenant label.

Allocation is serialized through `oob-allocations.json` beside the active Vigil
config. Multi-host deployments must place the config/registry on a shared,
locked filesystem (or distribute one centrally allocated registry) so every
host sees the same occupied FRP blocks. `vigil oob routing --format
all|json|caddy|dns` produces deterministic Caddy, DNS-forwarding, and JSON
routing inputs from that persisted record; applying them to public DNS/FRP/Caddy
remains an explicit deployment operation. Vigil does not mutate those external
services.

The emitted DNS block is a CoreDNS input, not a Route53 record: the public edge
must accept TCP and UDP 53, select the longest matching tenant zone, and forward
it to the tenant's private FRP UDP port. A legacy FRP listener already bound to
public port 53 must be migrated behind that DNS edge before CoreDNS can claim the
port. The Caddy output includes direct HTTP plus on-demand HTTPS routes for the
apex, client-id, and real `nonce.client-id` callback depths; its HTTPS block must
be imported under a Caddy global `on_demand_tls` permission/`ask` policy.

`vigil oob status --json` performs deep DNS and two-label HTTP edge checks, while
`vigil oob test` requires a registered client, fires the real client-bound host
shape, rejects redirects, and confirms the interaction reached that client's log.
These checks intentionally report degraded until the server-side route has been
registered and applied.

An install upgraded from the old single-tenant release is pinned additively to
its existing domain and ports (`53`/`8443`). Running tmux sessions and
`/data/oob/clients/*.session` correlation material are not renamed or restarted.
Move that install to an allocated tenant route only as a coordinated deployment
migration after its old clients are drained.

After spawning the `frpc` tmux session, `start_oob` tails
`/data/oob/frpc.log` for up to ~15s looking for success lines for all three
rendered tenant proxies (`*-oob-dns`, `*-oob`, and `*-oob-rev`) or `port already
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

The post-flight conflict scan remains a final defense against a stale or
independently allocated registry. On conflict it tears down only the attempted
tenant sessions and names the persisted domain/port block that must be repaired.

## Command Reference

### `vigil` top-level commands

| Command | Purpose |
|---------|---------|
| `vigil quickstart` | Onboarding wizard: probe host prerequisites/recon tools and print the setup checklist. Runs host-tool installs only with `--install-host-tools`. |
| `vigil install [path]` (alias `vigil update`) | Install/upgrade the working root in place; sync code, prompts, skills, scripts. Engagements, DB, and `.env` are preserved. |
| `vigil up` | Sync source, build stale images, start the local stack (runtime + orchestrator + optional mitmproxy/OOB). |
| `vigil doctor` | Check local readiness and prerequisites. |
| `vigil status` | Report live service state. |
| `vigil logs <target> [--lines N]` | Tail logs for `orchestrator`, `mitmproxy`, etc. |
| `vigil runtime start \| resources \| shell-exec \| build` | Manage the shared Kali runtime container. |
| `vigil orchestrator start` | Targeted start of the orchestrator backend/UI. |
| `vigil engagement create \| list \| start \| path \| cd-init` | Create and drive engagements. |
| `vigil assess ...` | Operator assessment surface (recon/findings/artifacts/kali tool verbs/resume). |
| `vigil blue ...` | Blue incident-response surface (customers, tenant init, engage, alert, tier, verify, contain, closeout, report). Specialist dispatch uses the [shared assessment-agent surface](#blue-incident-engagements). |
| `vigil auth status [--probe --identity <name> --probe-url <url>] \| show \| import \| edit \| clear \| export \| set-active` | Manage engagement credentials in the backend store; `status --probe` proves a specific identity's liveness. |
| `vigil mitmproxy start \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| status \| routing \| client \| test` | Manage shared OOB (frp + interactsh) and render tenant edge-routing inputs. |
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
- prioritized work items in the backend work buffer
- surfaces
- findings, links, and attack chains
- credential inventory, credential tests, access records, pivots, tunnels, and blocked techniques

The backend `assessment_work_items` table is the canonical durable work buffer.
Operators claim and close its rows through `vigil assess work-buffer ...`; the
former per-engagement `agent/scripts/schema.sql` queue is retired.

## Development

Extending or building on Vigil is a contributor workflow, documented in full in the root
[`AGENTS.md`](AGENTS.md): the clone-to-first-dispatch walkthrough, step-by-step recipes for adding a
skill, an `vigil assess` verb, a deterministic oracle, or an eval case, and the authoritative
[test/verification matrix](AGENTS.md#tests--verification) — backend pytest scopes, the prompt
render-check, the schema `--check`, lint/types, and the bench rungs. The four pytest scopes share
the backend venv; the other gates have their own prerequisites and costs.

To confirm a running install is healthy — the user-facing check, not the contributor test suite —
use the built-in diagnostics:

```bash
vigil doctor    # local prerequisites and host recon tools
vigil status    # live service state
```

## Implementation plan

The three product phases are implemented. Remaining product, benchmark-qualification, release, and
private-cutover work is consolidated in the single
[final release and follow-on plan](docs/plans/final-release-and-follow-on-work.md). Durable decisions
from completed plans live in [`docs/adr/`](docs/adr/); supporting research lives under
[`docs/plans/research/`](docs/plans/research/).

The plan names contract owners and validation targets where they are load-bearing without turning
predicted file edits into architecture. The rationale and official OpenAI source review are in
[Codex implementation-planning research](docs/plans/research/final-release-and-follow-on-work/codex-implementation-planning-2026-09-11.md).
