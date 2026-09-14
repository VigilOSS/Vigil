<div align="center">

# Vigil

**AI-driven offensive and incident-response engagements — operator prompts, a full Kali runtime, and durable orchestrator state in one CLI.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/vigil-oss/vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/vigil-oss/vigil)

</div>

Vigil drives a security engagement end to end from one CLI. An LLM operator reads a phased
workflow prompt, dispatches specialist agents, runs real tooling inside a shared Kali
container, and records every target, service, request variant, probe, finding, and attack
chain into a durable orchestrator database. Five modes run against the same backend: web red-team,
white-box code analysis, combined web and code, Android application analysis, and blue incident
response.

> **Authorized use only.** Vigil can autonomously drive offensive tooling against live systems.
> Use it only where you have explicit authorization and a reviewed scope. It is provided without
> warranty under the [Apache License 2.0](LICENSE); you are responsible for commands, credentials,
> infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private vulnerability
> reporting and the operator-data boundary.

- **A full Kali runtime** — ProjectDiscovery recon tooling, fuzzers, post-access tooling, OOB
  callback detection, and tunneling in one long-lived container.
- **Durable state** — every target, service, request variant, probe, finding, chain, and
  credential in SQLite, with rotated backups and a web UI.
- **A gated phase model** — an operator plus specialist roles work an ordered phase roster with
  readiness checks between phases.
- **Five agent CLIs** — Claude Code, Codex, Kimi, goose, and opencode, one methodology.

## Documentation

| Document | What it covers |
|----------|----------------|
| [`agent/AGENTS.md`](agent/AGENTS.md) | The operator prompt — the workflow every engagement runs. |
| [`CODE-MAP.md`](CODE-MAP.md) | Map of the codebase: where each subsystem lives. |
| [`AGENTS.md`](AGENTS.md) | Maintainer and contributor workflow, and the verification matrix. |
| [`docs/assessment-cli.md`](docs/assessment-cli.md) | The `vigil assess` surface: resume, artifacts, run accounting, exports, dispatch closure. |
| [`docs/session-commands.md`](docs/session-commands.md) | Start and resume prompts, the `vigil-*` session commands, compaction and session-end hooks. |
| [`docs/agent-clients.md`](docs/agent-clients.md) | Per-client setup, launch behaviour, and flag forwarding. |
| [`docs/authentication.md`](docs/authentication.md) | Credential records, capture, freshness clocks, liveness verdicts, proxy routing. |
| [`docs/blue-engagements.md`](docs/blue-engagements.md) | Blue incident response, end to end. |
| [`docs/code-analysis.md`](docs/code-analysis.md) | White-box code analysis, end to end. |
| [`docs/oob-routing.md`](docs/oob-routing.md) | Per-install relay-slot OOB routing, CoreDNS/Caddy inputs, the frpc conflict scan. |
| [`docs/operations.md`](docs/operations.md) | Runtime sizing, kernel limits, orchestrator data and backups. |
| [`docs/engagement-prompt-playbook.md`](docs/engagement-prompt-playbook.md) | Steering prompts for a session that goes shallow, overclaims, or loses the loop. |
| [`agent/references/`](agent/references/) | Payloads, tactics, recon, tenants, tools. Discover with `vigil assess list-references`. |

## Quick start

```bash
# 1. Install the CLI
uv tool install --from git+https://github.com/vigil-oss/vigil.git vigil

# 2. Check the host: prerequisites, missing recon tools, and the ordered setup checklist
vigil quickstart

# 3. Install a working root and bring the local stack up (Kali runtime + orchestrator)
#    First run builds the Kali image — several GB, and it needs Docker running.
vigil install ~/vigil && vigil up

# 4. Create an engagement against an authorized target
vigil engagement create https://target.example --hosts target.example

# 5. Start the operator on it
vigil engagement start <engagement-key> --client codex   # or claude | opencode | goose | kimi
```

`vigil quickstart` mutates nothing unless you pass `--install-host-tools`, so it is safe to run
first; `--json` gives a machine-readable readiness report. The orchestrator UI is at
`http://127.0.0.1:18000` once the stack is up. Vigil is distributed from source — pin a Git
revision for reproducible installs, or use `uv tool install --editable .` for development.

### The two layers: CLI binary vs working root

The **CLI binary** (`vigil` itself) is installed and upgraded with `uv tool install` /
`uv tool upgrade vigil`. The **working root** (`~/vigil` — the `agent/` tree of code, prompts,
skills, and scripts, plus the orchestrator) is installed and upgraded with `vigil install`
or with `vigil up`, which syncs first.

`vigil --version` reports the CLI binary's version; `vigil status` reports the working root's.

Upgrading one does not upgrade the other, and a newer CLI against a stale working root leaves
the affected features silently inert. Every sync path stamps a SHA-256 manifest of what it
copied and compares it against the live source, so the drift is detectable. Three surfaces warn
without blocking: a `warn` line in `vigil status`, an `install_staleness` check in
`vigil doctor`, and a `[vigil] WARN: install root <path> is stale ...` line on stderr before a
`vigil assess` passthrough execs. Run `vigil install` when you see one — it upgrades in place,
never moving or deleting engagements, the database, or `.env`. Mechanism:
[`docs/install-integrity.md`](docs/install-integrity.md).

### Recon runtime: host vs container

Most target-facing tools run **inside** the shared `vigil` container. The exception is the
DNS-heavy and bulk-liveness recon stages, which on **macOS/Windows Docker Desktop** must run on
the **host**: Docker Desktop proxies every container packet through a userspace proxy
(`com.docker.backend`) that NAT-tracks state *per distinct destination IP*, so a DNS brute or a
bulk `httpx` liveness pass over thousands of hosts saturates that table and wedges the whole VM.

| Stage / tool | Runs | Why |
|---|---|---|
| `subfinder`, `dnsx`, `puredns` (+`massdns`), `shuffledns`, `alterx`, bulk `httpx` liveness | **Host** on Docker Desktop | DNS-heavy / bulk — would wedge the userspace proxy in-container |
| `katana` crawl, `nuclei`, `ffuf`, exploit / authenticated HTTP | **Container** (always) | Isolation: auth'd and exploit traffic must not leave the sandbox |

On native Linux or a remote Docker host there is no userspace proxy, so everything runs
in-container and the host tools are optional — the split is a transparent no-op. On Docker
Desktop, `vigil assess recon` and `--runtime host` **enforce** it: a missing host binary fails
the preflight rather than silently degrading. `vigil quickstart --install-host-tools` runs these
installs for you; `vigil doctor`'s `host-recon-tools` row reports what is missing, and
`$(go env GOPATH)/bin` must be on your `PATH`.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/d3mondev/puredns/v2@latest
brew install massdns      # macOS; Linux: build from github.com/blechschmidt/massdns

# Optional: wider brute and permutations
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
```

## Running an engagement

```bash
vigil engagement create https://target.example --hosts target.example
vigil engagement list --json                              # find the key
vigil engagement start <engagement-key> --client codex
```

`create` starts the exploit policy at `pause` — explicit human approval before any exploit work
— and leaves authentication unset. When `--type` is omitted it is inferred from the inputs
(URL/host → `web`, `--repo` → `code`, both → `both`, APK or `--package-name` → `android`) and
echoed on stderr so it can be overridden; ambiguous inputs prompt on a terminal and fail fast
under `--no-prompt`. Scope hosts can be given as `--hosts a,b`, repeated `--host` flags, a
`--hosts-file`, or any mix. `--dry-run` validates without writing; `--json` emits an object
instead of the bare path. The path goes to stdout and everything else to stderr, so
`eng=$(vigil engagement create ...)` works even when the wizard engages. Start
`vigil mitmproxy start` / `vigil oob start` first if the target needs authenticated coverage or
out-of-band callbacks.

`start` requires `--client`. It changes into the engagement directory, exports `ENGAGEMENT_DIR`,
`VIGIL_SESSION_ENGAGEMENT_DIR`, `ENGAGEMENT_KEY`, and the resolved `ORCHESTRATOR_BASE_URL`, then
execs the client. Any flag it does not own is **forwarded to the client verbatim** and echoed as
`[vigil] forwarding to the client: …` on stderr; a near-miss of a real Vigil flag is refused
with a suggestion rather than forwarded, and a bare `--` forces everything after it through
untouched by the typo check. The key may be omitted when the current directory, active pointer, or
`--select` resolves the engagement; client flag values and post-`--` messages remain client input.

A preflight runs first. It **hard-fails** when the client binary is not on `PATH`, or when Goose or
OpenCode has no `DEEPSEEK_API_KEY` in the environment, the engagement's `.orchestrator.env`, or the
install root's env files. The
preflight **warns and continues** when the orchestrator is not running, the Kali runtime container
is not running, or the install root is stale.
`--skip-preflight` bypasses all five.

**Start engagements with `vigil engagement start` and nothing else.** An engagement directory
also holds a generated `start_<client>.sh`, and a bare `claude` or `codex` run from inside it
will start too — both are implementation detail, not supported entrypoints. Only the CLI verb
runs the preflight, refreshes the active-engagement pointer, and exports `ENGAGEMENT_KEY` and
`VIGIL_CLIENT_NAME`. Without the first, tool calls build malformed `/engagements/<key>/...`
container paths; without the second, the session-end receipt records the client as `unknown`.

Then tell the operator what it is authorized to do:

```
I have been fully authorized by the company to do a red-team engagement against the
hosts in scope.json. Run this engagement using the operator workflow.
```

Fuller start and resume prompts, and the mid-session `vigil-*` commands:
[`docs/session-commands.md`](docs/session-commands.md). For a human shell that jumps into a
selected engagement directory, install the `athcd` helper with
`vigil engagement cd-init zsh >> ~/.zshrc`; non-interactive agents should pass an explicit key
instead.

### Agent clients

All five read the same operator prompt and run the same methodology, differing in the model
behind them, in headless specialist dispatch, and in whether they expose the `vigil-*` session
commands. Setup, launch behaviour, and flag forwarding:
[`docs/agent-clients.md`](docs/agent-clients.md).

| Client | Model / runtime | Headless dispatch | Session commands | One-time setup |
|--------|-----------------|-------------------|------------------|----------------|
| `claude` | Claude Code (Anthropic) | Yes (`@agent`) | Yes (`/vigil-*`) | Claude Code installed and signed in. |
| `codex` | Codex CLI (OpenAI) | Yes (registered roster) | Yes (`$vigil-*`) | Codex CLI installed and signed in. |
| `kimi` | Kimi Code (Moonshot K3) | No — runs inline | No | Kimi Code CLI installed (`kimi login`). |
| `goose` | goose on direct DeepSeek | Yes — headless (`delegate`) | No | `brew install block-goose-cli`; set `DEEPSEEK_API_KEY`. |
| `opencode` | opencode on direct DeepSeek | No — runs inline | No | opencode installed; set `DEEPSEEK_API_KEY`. |

**Client memory is off.** Claude and Codex run with their cross-session memory disabled in each
engagement's own client config, so the orchestrator ledger stays the engagement's single record —
a second context store would hold engagement facts Vigil cannot audit, export, or hand to the
next operator.

**goose is the recommended open-model client** — it dispatches custom specialist subagents
headlessly and its anti-cheat hook fires inside them. A bare start opens an interactive
`goose session`; seeded with an operator message it opens `goose run --interactive`. Thinking
mode runs behind a local reasoning-repair proxy, a stopgap for
[aaif-goose#9397](https://github.com/aaif-goose/goose/issues/9397); see
[`docs/goose-bench.md`](docs/goose-bench.md). **opencode** opens its TUI as the `operator` agent
and takes the message via `--prompt`; both open-model launchers currently support direct DeepSeek
only.

Run one lead operator per engagement at a time unless you are deliberately coordinating a
dual-client run: both clients share durable orchestrator state, but filesystem artifacts under
an engagement directory are still ordinary files.

## Engagement tracks and phases

Vigil runs three independent tracks, each with its own ordered roster terminating in the shared
`complete` state. The rosters are pinned in
[`agent/scripts/assess/lib/phases.py`](agent/scripts/assess/lib/phases.py).

| Track | Phases | Persisted as |
|---|---|---|
| **web** (red) | `recon → collect → consume-test → verify → exploit → report` | `scope.json.current_phase` |
| **code** (white-box) | `ingest → classify-map → hunt → verify-variant → fuzz` | `scope.json.code_phase` |
| **blue** (incident response) | `intake → triage → investigate → verify → respond → report` | `scope.json.current_phase` |

`complete` is a terminal state, not a working phase: no readiness gate, no audit tag, no
per-phase operator doc. The code vocabulary is deliberately distinct from the web one, and a
`both` engagement advances the two tracks independently. Phase values are persisted, so
`consume` and `consume_test` are accepted as input aliases resolving to the canonical
`consume-test` at the boundary; the UI labels it "Consume & Test". Optional Athena log
investigation is a numbered step inside the exploit phase, not a phase of its own.

The specialist roster is shared across tracks and shipped with every engagement: `operator`,
`recon-specialist`, `surface-collector`, `source-analyzer`, `vulnerability-analyst`,
`exploit-developer`, `fuzzer`, `osint-analyst`, `report-writer`, the code roles
(`code-architect`, `code-vuln-hunter`, `code-vuln-verifier`, `code-variant-hunter`,
`code-fuzz-engineer`), and the blue roles (`alert-triage-specialist`, `investigator`,
`incident-verifier`, `ir-lead`). Validator-, chain-, and ranker-style behaviours are folded into
those roles rather than adding roster surface.

Transitions are gated on every track by `transition-phase`, which resolves the track from the
engagement (`--track web|code|blue` overrides). `--force` records a durable override decision, and
some integrity blockers cannot be forced at all.

```bash
vigil assess transition-phase <phase> [--track code] [--force --reason "<why>"]
```

Previewing readiness before a transition is per-track, because the tracks measure different
things. `check-phase-readiness` is the **web** gate and accepts only web phases; the code track
reads its readiness out of the coverage ledger; the blue gate runs inside `transition-phase`
itself and has no separate preview command.

```bash
vigil assess check-phase-readiness --phase <web-phase>                 # web
vigil assess code-coverage --require-transition-ready <code-phase>     # code
```

Blue engagements start from an alert and a tenant reference rather than a web host, and
containment is split into proposal, audited execution, and recording — see
[`docs/blue-engagements.md`](docs/blue-engagements.md). Code analysis runs a separate operator
loop against a sealed, content-addressed source snapshot — see
[`docs/code-analysis.md`](docs/code-analysis.md).

## Runtime model

The runtime is one long-lived Kali container named `vigil`, started by `vigil up` (or
`vigil runtime start`). Target-facing execution goes through `vigil assess kali ...`, which
calls into the container via `docker exec`. Long-running scans go through
`vigil assess kali job start ...`, which uses the in-container `dtach` supervisor so workers
survive operator session exit.

The container mounts shared runtime data at `.runtime-data/`, bind-mounts the engagement root at
`/engagements` so tool calls can write `/engagements/<key>/...` directly, and receives the root
`.env` when present. Durable artifacts stay on the host under `agent/engagements/<key>/`. For
non-interactive maintenance inside the container use `vigil runtime shell-exec "<cmd>"`, so
quoting and exit codes stay under the CLI.

`agent/docker/runtime-full/Dockerfile` is the only supported runtime for target-facing
execution. It bundles:

| Category | Tools |
|----------|-------|
| Authenticated crawling | Katana, Chromium |
| ProjectDiscovery recon | `httpx`, `dnsx`, `gau`, `katana`, `nuclei`, `dalfox`, `puredns`, `shuffledns`, `alterx`, `asnmap`, `cero`, `bbot` |
| Web scanning / fuzzing | nuclei, ffuf, gobuster, wfuzz, dirb, sqlmap, WhatWeb, hydra, john, hashcat, nikto |
| DNS / XML coverage | `massdns`, `xmllint` |
| Job supervision | `dtach` |
| Secret scanning | TruffleHog (filesystem and git) |
| Post-access | evil-winrm, impacket, mitm6, chisel, ligolo-ng, proxychains-ng, Responder |
| Shell handling | pwncat-vl, tmux |
| OOB and tunneling | interactsh, frp |

A lightweight image at `agent/docker/runtime-lightweight/Dockerfile` exists for faster
Dockerfile iteration only; build it with `vigil runtime build lightweight --dev`.

Sizing, kernel limits, and orchestrator backups: [`docs/operations.md`](docs/operations.md).

## Optional capabilities

| Capability | Default | Start command | Purpose |
|------------|---------|---------------|---------|
| MITM proxy | off | `vigil mitmproxy start` | Authenticated capture into each engagement's backend credential store. |
| OOB (frp + interactsh) | off | `vigil oob start` | Out-of-band callback detection over shared frp/interactsh. |
| Universal ctags | host-installed | `brew install universal-ctags` | Richer code-analysis definition lookups. |

**Authenticated capture.** `vigil mitmproxy start` bind-mounts `agent/engagements/` so the addon
sees every engagement at once, persists the mitmproxy CA in a Docker volume, and verifies the
local proxy port — no engagement context required. Route a browser through
`http://127.0.0.1:8080`, log in against any scoped host, then confirm with
`vigil auth status <key>`. A second login through the same proxy appends a second identity for
cross-account (IDOR/BOLA) testing. Credential fields, freshness clocks, liveness verdicts, and
the addon's routing precedence: [`docs/authentication.md`](docs/authentication.md).

**Callbacks, listeners, and tunnels** — frp tunnels, pwncat-vl listeners, and interactsh
callback servers are **operator-controlled** shared infrastructure. Agents provide commands but
never start them. `vigil oob start` refuses without `oob.frp_host`, `oob.domain`, and
`oob.frp_token`; `oob.frp_port` defaults to 7000. Vigil ships no maintainer-owned fallback
infrastructure — the relay itself is yours to run. This install's relay slot — its reserved
subdomain and port block on the shared relay — is allocated by `vigil install`, and only when
`oob.domain` is already configured, so configure the keys first or re-run `vigil install` after
setting them. The one root that keeps the shared legacy route (ports 53/8443) instead is an
install that was already running OOB before relay slots existed, whose live callbacks would stop
correlating if its ports moved.

```bash
vigil config set oob.frp_host oob-relay.example.com   # also: oob.frp_port, oob.domain, oob.frp_token
vigil install                                        # reserves this install's relay slot
vigil oob start && vigil oob status --json
vigil oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
vigil oob test
```

Relay-slot routing records, the CoreDNS and Caddy inputs `vigil oob routing` renders, and the
frpc conflict scan: [`docs/oob-routing.md`](docs/oob-routing.md). Payload-side tradecraft:
[`frp-tunneling.md`](agent/references/offensive-tactics/frp-tunneling.md) and
[`shell-handling.md`](agent/references/offensive-tactics/shell-handling.md).

## Command reference

| Command | Purpose |
|---------|---------|
| `vigil quickstart` | Probe host prerequisites and recon tools, print the setup checklist. Installs host tools only with `--install-host-tools`. |
| `vigil install [path]` | Install or upgrade the working root in place. Engagements, DB, and `.env` are preserved. Builds the Kali image when it is missing, so it needs a running Docker daemon — `--skip-image-check` syncs without one. |
| `vigil up` | Sync source, build stale images, start the local stack. |
| `vigil doctor` | Check local readiness and prerequisites. Exits non-zero on a `FAIL` row; `--json` for a machine-readable report. |
| `vigil status` | Report live service state. |
| `vigil logs <target> [--lines N]` | Tail logs for `orchestrator`, `runtime`, `mitmproxy`, `oob`, or `all`. |
| `vigil runtime build \| start \| stop \| restart \| status \| shell \| shell-exec \| resources` | Manage the shared Kali runtime container. |
| `vigil orchestrator start \| stop \| restart \| status \| open \| build` | Manage the orchestrator backend and UI. |
| `vigil engagement create \| list \| start \| open \| path \| current \| cd-init \| archive \| export \| export-pdf` | Create and drive engagements. Scope edits (`add-host`, `add-oos`, `set-header`, `add-track`, `set-rate-limit`, …) live here too — `vigil engagement --help`. |
| `vigil use <key>` | Set the persisted active engagement for global services. |
| `vigil assess ...` | The assessment surface — see [`docs/assessment-cli.md`](docs/assessment-cli.md). |
| `vigil blue ...` | Blue incident response — see [`docs/blue-engagements.md`](docs/blue-engagements.md). |
| `vigil auth status \| show \| edit \| clear \| export \| quarantine \| import \| alias \| env-check \| set-active \| keepalive` | Manage engagement credentials in the backend store. |
| `vigil mitmproxy start \| stop \| status \| cert \| build \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| stop \| restart \| status \| routing \| test \| clean \| mint \| poll \| client` | Manage shared OOB and render relay-slot edge-routing inputs. |
| `vigil config path \| list \| get \| set \| unset \| edit` | Read and write persistent CLI config. |
| `vigil backup create \| list \| show \| restore` | Manual orchestrator DB backup operations. |
| `vigil bench ...` | Benchmark harness — see [`docs/benchmarking.md`](docs/benchmarking.md). |
| `vigil email <mailbox>` | Read a local Mail.app test mailbox for verification codes during authenticated testing. |

Every command documents its full flag set under `--help`; runtime tool verbs live under
`vigil assess kali --help`.

## Security

Vigil ships a full offensive Kali runtime and drives autonomous specialist agents against live
targets. Treat it accordingly.

- **Authorized targets only.** Every operator start prompt begins with an explicit authorization
  statement, and engagement scope is pinned in `scope.json`. Only run against hosts and tenants
  you are contractually authorized to test.
- **Exploit work is gated.** The default exploit policy is `pause` — explicit human approval
  before any exploit-developer dispatch. Policies (`pause` / `selected` / `full_send`) are set
  per engagement in `scope.json` and enforced through the operator workflow.
- **Operator-controlled infrastructure.** Tunnels, listeners, and OOB callback servers are
  started by the operator, never by an agent.
- **Blue write-actions are audited.** Tenant-facing WRITE and respond actions run with
  `--require-audit`, and containment is split into proposal approval, audited execution, and
  explicit recording.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Repository layout and development

| Path | Contents |
|---|---|
| `src/vigil_cli/` | The `vigil` CLI: install, runtime, orchestrator, engagements, auth, OOB, bench. |
| `agent/` | Operator and specialist prompts, phase docs, rules, skills, the reference library, the `vigil assess` scripts, and the runtime Dockerfiles. |
| `orchestrator/` | Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility. |
| `tests/` | CLI pytest suite. Backend tests live in `orchestrator/backend/tests/`. |
| `docs/` | Deep reference, ADRs, and plans. |

Extending Vigil is a contributor workflow, documented in the root [`AGENTS.md`](AGENTS.md): the
clone-to-first-dispatch walkthrough, recipes for adding a skill, a `vigil assess` verb, a
deterministic oracle, or an eval case, and the authoritative
[test and verification matrix](AGENTS.md#tests--verification). Durable design decisions live in
[`docs/adr/`](docs/adr/). To confirm a *running install* is healthy rather than the contributor
suite, use `vigil doctor` and `vigil status`.
