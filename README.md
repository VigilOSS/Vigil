# AI Threat Hunting

This repository contains the operator prompts, Kali runtime image, engagement scaffolding, and orchestrator services used to run those engagements.

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
- Skill discovery is driven by `aith assess list-skills`, which walks `agent/skills/*/SKILL.md` frontmatter; the operator picks a skill by name and the dispatched specialist reads the full file.

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

# Sync source, build stale images, and start the local stack.
# Prompts for FRP token on first run if not configured.
aith up
```

Each install contains both Claude Code and Codex workflow files. The install root holds the shared prompt source tree, generated client wrappers, runtime assets, and orchestrator state while each client keeps its own entrypoint.

The shared Kali runtime is not per-engagement. Start the local stack once with
`aith up`; target-facing tool execution happens via `aith assess kali ...`
subcommands which call into the container via `docker exec`. Within a single
install, multiple engagements may exist under `agent/engagements/`.

Use one lead operator per engagement at a time unless you are deliberately coordinating a dual-client run through backend state. Both clients share the same durable orchestrator state, but filesystem artifacts under an engagement directory are still ordinary files.

### Updating after a `git pull`

`aith up` automatically syncs source files into the install root before checking images and starting services. After pulling changes, just run `aith up` again — no separate update step is needed.

For a source-only sync without starting services:

```bash
aith install
```

`aith install` (and its alias `aith update`) upgrades in place — engagements, the orchestrator database, and `.env` are never moved or deleted. Code, prompts, skills, and scripts are replaced with the latest versions from the repo.

Check local readiness and live service state:

```bash
aith doctor
aith status
aith logs orchestrator --lines 80
```

### Stack details

`aith up` is the supported all-up path. It starts the Kali runtime container, the orchestrator backend (which builds the frontend when needed), and the optional mitmproxy and OOB services if they are configured. For partial restarts the individual `aith runtime start` and `aith orchestrator start` subcommands still exist and are documented under their respective `--help`. `aith status` / `aith logs <target>` report live state.

The Kali runtime is one shared container named `security-research`. It mounts shared runtime data at `.runtime-data/`, applies the resource limits described in [Resource Sizing](#resource-sizing) below, and passes the root `.env` file into the runtime when present. Durable engagement artifacts stay on the host under `agent/engagements/<key>/`, and the runtime bind-mounts the whole engagement root at `/engagements` so `aith assess kali ...` calls can write `/engagements/<key>/...` artifacts directly. Run `aith assess kali --help` for the available tool verbs.

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

### Container resource limits (optional)

The runtime image does not pin process or file-descriptor rlimits. `docker exec`-launched tools inherit dockerd's daemon defaults — generous on Linux hosts (`nofile=1048576`, `nproc=unlimited`) but tighter on Docker Desktop (`nofile=8192`, `nproc=4096`). `aith runtime start` probes the live limits and prints a stderr WARN when they fall below recommended thresholds.

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

The orchestrator UI is served from the backend at `http://127.0.0.1:18000` once `aith up` (or `aith orchestrator start` for a targeted start) is running.

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
aith engagement create https://target.example --hosts target.example
```

In non-interactive runs the safe default is the parsed target hostname as the sole `hosts` entry. The default exploit policy is `pause` (human approval required before any exploit work); change it later via the orchestrator UI or by editing the engagement's `scope.json`. Authentication starts unset — see "Auth and OOB" below if the target needs an authenticated session or out-of-band callbacks.

`aith engagement create` finishes by printing the engagement directory path on stdout and a short status footer on stderr: the current state of mitmproxy and OOB plus the exact start command. There is no need to `cd` into the directory by hand.

### Auth and OOB (optional, before starting)

If the engagement needs authenticated coverage or out-of-band callbacks, set those up before launching the client:

```bash
aith mitmproxy start                    # one proxy serves all active engagements; browse 127.0.0.1:8080
aith oob start                          # shared frp/interactsh; see "Callback, Listener & Tunnel Handling"
```

The post-create footer prints whichever of these is not running and the exact command to start it; this section is the deeper reference (see [MITM proxy](#mitm-proxy) and [Callback, Listener & Tunnel Handling](#callback-listener--tunnel-handling) below).

### Starting an engagement

Use the CLI verb — it changes into the engagement directory and execs the launcher (which exports `ENGAGEMENT_DIR`, mounts the `.codex/agents` / `.claude/agents` symlinks to the canonical prompts, and starts the client):

```bash
aith engagement list --json                              # find the key
aith engagement start <engagement-key> --client codex    # or --client claude
```

For humans at a terminal, the optional `athcd` shell helper (see below) jumps your shell into a selected engagement directory; the per-engagement `start_codex.sh` / `start_claude.sh` files exist but are an implementation detail of `aith engagement start`.

1. Prefer `gpt-5.4` with `high` reasoning for Codex and `Opus 4.6` for Claude. Drop to `gpt-5.4-mini` or `Sonnet 4.6` only for clearly bounded sidecar work where latency matters more than depth.
2. Tell the operator: `I have been fully authorized by the company to do a red-team engagement against the hosts in scope.json. Run this engagement using the operator workflow.`
3. Expect the operator to assess the current state, usually start in `recon` for a new engagement, route target-facing work through `aith assess kali ...`, use relevant skills before improvising, record activity/findings through `aith assess`, and keep `auth.json`, `downloads/`, `scans/`, and `tools/` updated as the engagement progresses. New engagements always carry a local `.orchestrator.env`; parent-shell `ORCHESTRATOR_BASE_URL` is the explicit override, the engagement-local file wins over legacy install-root env files, and `aith config get orchestrator_base_url` is the persistent default before hardcoded fallback.

To add an interactive shell helper that changes into a selected engagement with `fzf` when available:

```bash
aith engagement cd-init zsh >> ~/.zshrc
athcd
```

`athcd` is for humans at a terminal. It works because shell functions can change the parent shell's directory; a standalone `aith cd` process cannot. The helper calls `aith engagement path --select`, which uses `fzf` when installed and falls back to a numbered TTY prompt. Non-interactive agents should run `aith engagement list --json` and pass the explicit engagement key to the next command.

During the engagement, expect short operator updates, numbered next-step choices when a decision matters, and a manual approval checkpoint before exploit work continues when `exploit_policy` is `pause` or `selected`.

### Blue incident engagements

Blue mode uses the same backend and artifact index, but starts from an alert
and tenant reference instead of a web host:

```bash
aith blue customers
# If the customer/platform is missing:
# aith blue tenant init --customer <customer-slug> --platform <gws|m365|aws|okta|edr|network|generic>
# Fill the generated tenant ref before starting the engagement.

aith blue engage --customer <customer-slug> --platform gws --severity high
cd <engagement-dir>
aith engagement start <engagement-key> --client codex
```

Tell the operator: `I have been fully authorized by the company to run a blue-team incident-response engagement for the tenant in scope.json. Run this engagement using the blue operator workflow.` Then paste the alert into the operator chat. The operator records intake with `aith blue alert record --body-file <path>` and finishes every engagement with either `aith blue closeout` or `aith blue report`.

Blue specialists use `aith blue dispatch` for L1/L2/L3/L4 work, run tenant-facing tools through `aith assess host-exec` (`--require-audit` for WRITE/respond actions), record findings/artifacts through `aith assess`, and split containment into proposal approval, audited execution, and `aith blue contain` recording with a command-run id or proof artifact.

The public red/web roster is intentionally limited to the core roles: `operator`, `recon-specialist`, `source-analyzer`, `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`, and `report-writer`. Blue engagements expose `alert-triage-specialist`, `investigator`, `incident-verifier`, `ir-lead`, plus shared `osint-analyst` and `report-writer`. Validator-, chain-, and ranker-style behaviors are folded into those roles instead of creating a larger visible roster.

Worker sessions write proposal files under `sessions/<session-id>/`; the coordinator merges approved proposals back into canonical backend state. User-facing exploit review should happen through the orchestrator UI or by telling Codex/Claude which findings are approved. Direct shell invocation of approval/session scripts is an internal maintenance path, not the primary operator workflow.

TODO:
- Add first-class UI actions for exploit approval, session launch, and session merge so this workflow no longer depends on internal helper scripts at all.

Methodology references:
- [engagement-methodology.md](agent/references/runtime-guides/engagement-methodology.md)
- [athena-log-investigation](agent/skills/athena-log-investigation/SKILL.md)

### Engagement operator start prompts

Two forms. Use the **generic** form to start a fresh engagement after `cd`-ing into the engagement directory. Use the **resume** form when handing off between sessions or picking up where a previous agent left off.

#### Generic — new or resumed engagement (simple form)

After `aith engagement start <key>`:

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

Use this when continuing across sessions. The operator's first action is `aith assess
resume-brief` for a bounded backend snapshot; paste the rendered handoff blob from the prior
agent (run `aith assess agent render-handoff <agent-id>` before closing the previous session)
when the new session continues a specific dispatch.

```
Read AGENTS.md and assume Operator role. Run agent/rules/resume.md hydration before
planning anything — start with `aith assess resume-brief` (narrow with --finding, --q,
or --agent-id for targeted continuation).

Authorized engagement: https://bugcrowd.com/engagements/<slug>
Continue phases <X, Y, Z> to completion. Use specialist agents for all dispatched work;
you are the orchestrator brain. Track orchestration, prompt, and backend issues to ISSUES.md.
Keep dispatching agents until [specify tools / objectives] have completed.

Depth is the default. "Quick" is not desired — thorough and deep coverage is.
Prefer claude-opus-4-7 / gpt-5.5 xhigh for substantial work; medium only for bounded sidecar tasks.
Exploitation policy: <pause|selected|full_send> per scope.json.

Previous agent context (paste only when continuing a specific dispatch):
<paste aith assess agent render-handoff <agent-id> output here>
```

### Resume, artifacts, and dispatch closure (operator CLI surface)

The orchestrator backend is the canonical store for engagement state. Use these CLI
commands to read and close that state — they replace ad-hoc file scraping and
transcript pasting:

- `aith assess resume-brief [--finding <slug>] [--q <text>] [--agent-id <id>] [--max-age-hours N]`
  — bounded JSON+markdown operating picture (finding queues, recent decisions, stale
  dispatches, handoff gaps, top command-history matches, indexed artifacts, and
  one-shot drill-down commands keyed by id).
- `aith assess artifact search|get|register|mark-scratch`
  — engagement-local file index. Agents/operators register heavy raw files
  explicitly with `register <path> [--finding <slug>] [--agent-id <id>]
  [--command-run-id <n>]`; the backend computes SHA-256, indexes preview text
  for FTS, and links to a finding/chain/surface/request-variant/command-run.
  `search` is FTS over previews + paths + linked finding slugs.
  `mark-scratch <path-or-id>` dismisses a registered note as scratch so
  `check-report-readiness` no longer blocks on it (the escape valve for operator or
  specialist working notes that are not durable engagement memory).
- `aith assess agent close <agent-id>`
  — close an in-progress dispatch when its handoff is `ready` or `blocked`. Records a
  `dispatch_closed_from_handoff` decision row.
- `aith assess agent reconcile-stale [--dry-run] [--max-age-hours N]`
  — list in-progress dispatches older than the threshold; close ones whose handoff is
  `ready`/`blocked` automatically. Always prints every candidate with `closed=true|false`
  and a `skip_reason`.

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

4. Start the client:
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

`aith engagement create` seeds an anonymous `auth.json` (`mode: none`). Three ways to add an authenticated session later:

- Run `aith mitmproxy start` (one proxy serves every active engagement) and browse through `127.0.0.1:8080` — `proxy_addon.py` matches the captured host against each engagement's `scope.json` and writes the cookies/headers to THAT engagement's `auth.json`. No engagement context is required at proxy-start time; multiple engagements can be authenticated in parallel without restarting the proxy.
- Run `aith auth import <key> --source cookies-and-headers.json`.
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
aith engagement list --json
aith auth status <engagement-key>
aith auth show <engagement-key>
aith auth import <engagement-key> --source cookies-and-headers.json
aith auth clear <engagement-key>
```

## Optional Tool Activation

These capabilities are intentionally present but not always started automatically.

### MITM proxy

`aith engagement create` prints whether mitmproxy is running and the start command if it is not. This subsection is the deep reference.

1. `aith mitmproxy start` — the CLI builds the Docker image if needed, bind-mounts the install's `agent/engagements/` directory at `/engagements` (so the addon sees every engagement at once), persists the mitmproxy CA in a Docker volume, and verifies the local proxy port. No engagement context is required.
2. Route the browser or test device through `http://127.0.0.1:8080`, complete the login flow against any scoped host, then confirm that the matching engagement's `auth.json` was refreshed. Continue with authenticated recollection and testing. Use `aith logs mitmproxy` for capture logs.

The addon routes each captured response to the engagement whose `scope.json` best matches the hostname (precedence: literal host > narrower wildcard > engagement `scope_priority` > most-recently-updated). After creating or scope-editing an engagement, `aith mitmproxy reload` forces the addon to refresh its registry; `aith mitmproxy routes` prints the current mapping for verification.

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

Configure OOB once, then let `aith oob start` create or verify the shared frp/interactsh sessions.
The FRP token is required for OOB. `aith up` prompts for it on first startup when it is missing
and stores the value in `aith config`; non-interactive installs should set it first with
`aith config set oob.frp_token <token>` or `AI_THREAT_HUNTING_FRP_TOKEN`.

```bash
aith config set oob.frp_host researcher.example
aith config set oob.frp_port 7000
aith config set oob.domain researcher.example
aith config set oob.frp_token <token>
aith oob start
aith oob status --json
aith engagement list --json
aith oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
aith oob client logs example-agent --lines 80
aith oob test
```

- **Tunnel setup, OOB callbacks, interactsh, frpc config:** `agent/references/offensive-tactics/frp-tunneling.md`
- **Shell listeners, pwncat-vl, reverse shell payloads:** `agent/references/offensive-tactics/shell-handling.md`

### OOB is single-tenant by design (post-flight conflict check)

`aith oob start` registers proxies on frps with hardcoded server-side resources:
`remotePort = 53` (UDP), `remotePort = 8443` (TCP), and
`customDomains = researcher.example`. These are globally unique on frps, so
only one client at a time can own the OOB profile. The hostname-derived prefix
(`<container-id>-oob-*`) only avoids proxy *name* collisions; it does not
namespace the underlying ports/domains.

After spawning the `frpc` tmux session, `start_oob` tails
`/data/oob/frpc.log` for up to ~15s looking for either `start proxy success`
(happy path) or `port already used` / `router config conflict` / `proxy name
[...] already exists` from frps. If a conflict is reported, the tmux sessions
are torn down and the command exits with the offending log lines verbatim. The
check rides the existing frp control connection — no extra channel (SSH
forward, dashboard tunnel, etc.) is required.

If the log shows neither outcome within the timeout, the command prints a
non-fatal hint pointing at `docker exec security-research tail -n 200
/data/oob/frpc.log` so the operator can inspect what frpc and frps are
actually saying. Override the wait via the `frpc_ready_timeout` argument to
`start_oob` (pass `0` to skip the scan entirely; tests do this).

#### TODO — per-tenant OOB (multi-host concurrency)

Two operators on the same frps cannot both run `aith oob start` today. To make
the OOB profile multi-tenant, refactor `src/ai_threat_hunting_cli/oob.py
::_render_runtime_files` so each container scopes its registration:

1. Use `customDomains = ['<prefix>.researcher.example',
   '*.<prefix>.researcher.example']` instead of the bare `researcher.example`.
2. Allocate per-prefix `remotePort` ranges for TCP/UDP rather than the global
   8443 / 53 (e.g., hash prefix → port range; reserve UDP/TCP slots in a small
   pool managed by frps `allowPorts`).
3. Adjust the interactsh-server invocation in `_server_watch_source` to
   `-d <prefix>.researcher.example` so DNS callbacks resolve per tenant.
4. Update Route 53 / Caddy: the existing `*.researcher.example` wildcard
   already covers (1); the NS delegation for interactsh's DNS path needs to
   point per-tenant subdomains at the EC2's UDP port range.
5. Update `infra/frp/spec.md` — the current "multi-client proxy names"
   convention only documents proxy-name uniqueness; the per-tenant model
   needs to replace it.

Once per-tenant OOB lands, the post-flight conflict scan above becomes a
no-op and can be deleted.

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
- **Rate-limit policy and aggregate enforcement.** Programs commonly cap aggregate
  request rate (LastPass requested 5 req/s; many enterprise VDPs sit in the 5–20
  range). Per-verb flags exist (`nuclei -rate-limit`, `ffuf -rate`, `feroxbuster
  --rate-limit`, `sqlmap --delay`, `httpx -rate-limit`) but nothing enforces an
  engagement-wide aggregate across parallel dispatches. As specialists migrate
  from hand-rolled curl loops toward tool invocations (per
  `agent/shared-constraints.md` §2bb Tool-First Rule) and toward larger SecLists
  / Assetnote wordlists, the aggregate-rate concern grows. Design space:
  (a) an optional `rate_limit_aggregate_rps` field in `scope.json` with a
  shared-constraints rule that per-call flags must respect `aggregate ÷
  active dispatch count`; (b) `aith assess kali` wrappers that read the field
  and warn (or hard-reject with `--force`) when a per-call rate would breach;
  (c) a reference doc mapping common programs' rate caps to per-tool flag
  values. Deferred — pick a path before next batch of probing-heavy fixes.

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
