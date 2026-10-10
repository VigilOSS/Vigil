<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/vigil-lockup-dark.svg">
  <img alt="Vigil" src="docs/assets/logo/vigil-lockup-light.svg" width="280">
</picture>

**AI-driven offensive and incident-response engagements — operator prompts, a full Kali runtime, and durable orchestrator state in one CLI.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/VigilOSS/Vigil)

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

## Models, access, and what I have tested

I have built and refined Vigil primarily around **Claude Code and Codex**. In my testing,
authorized web red-team engagements have worked with **Claude Opus 5** under Anthropic's
Cyber Verification Program (CVP) and **GPT-5.6 Sol** with OpenAI's Trusted Access for Cyber.
Those results reflect the models, clients, and access available in my own setup; blocking can
vary with your account, access tier, model version, and engagement.

To select Opus 5 in Claude Code, run `/model claude-opus-5[1m]` in the session, if that
model is available to your account. `/model` opens the model picker. The `[1m]` suffix
requests the extended context window; Opus 5 already has native 1M context. See
[Claude Code's model configuration](https://code.claude.com/docs/en/model-config).

**I have not yet validated Vigil's engagement workflows with Claude Opus 5.5 or GPT-6.1 Sol.**
As of October 2026, Anthropic calls its defensive CVP tier **Defense Access**; **Red Team Access**
is a separate tier currently limited to qualifying organizations. OpenAI calls its defensive
offering **Daybreak Blue**, with **Daybreak Red** requiring separate approval and provisioning.
Defensive access alone should not be treated as assurance that a web red-team engagement will
run through without refusals. Check the provider's current terms and the access enabled for your
specific model and client before starting. See [Anthropic's CVP tiers](https://www.anthropic.com/news/cyber-verification-program)
and [OpenAI's model and access guidance](https://learn.chatgpt.com/docs/cyber-safety).

I want Vigil to remain practical for independent researchers doing authorized work. As frontier
model access becomes more restrictive, I plan to broaden support for **GLM 5.3** and other models
with more predictable access to these workflows. That will take substantial work: reducing
orchestration overhead, adapting prompts to the models, and refining integrations with **OpenCode**
and other harnesses. This is planned work; Claude Code and Codex remain the integrations I have
refined most extensively today.

## What Vigil provides

- **Findings are independently verified.** A finding is confirmed, downgraded, or marked a false
  positive only by a dispatch other than its author's, citing a proof receipt of captured evidence.
- **Target-facing commands are audited.** `vigil assess kali` records each command's technique,
  intent, and probe kind, so the engagement keeps a trail of what was sent and why.
- **Real attack tooling** — a long-lived Kali container with ProjectDiscovery recon, fuzzers,
  an audited Playwright browser, MITM capture with multiple identities for cross-account testing,
  and out-of-band callbacks correlated back to the probe that caused them.
- **White-box code analysis** against a sealed, content-addressed source snapshot with a
  tree-sitter structural index and a coverage ledger.
- **Durable state** — targets, services, request variants, probes, findings, chains, and
  credentials in SQLite, with rotated backups and a web UI.
- **Six client integrations, one methodology** — Claude Code, Codex, Kimi, goose, opencode, and
  Pi; Pi is currently limited to remediation engagements.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/findings-dark.png">
  <img alt="Vigil orchestrator UI: an engagement's findings grouped by severity, workflow, and verification" src="docs/assets/findings-light.png">
</picture>

## Quick start

```bash
# 1. Install the CLI
uv tool install --from git+https://github.com/VigilOSS/Vigil.git@v1.0.0 vigil
# ...or over SSH, if you authenticate to GitHub with a key
uv tool install --from git+ssh://git@github.com/VigilOSS/Vigil.git@v1.0.0 vigil

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

Then tell the operator what it is authorized to do:

```
I have been fully authorized by the company to do a red-team engagement against the
hosts in scope.json. Run this engagement using the operator workflow.
```

The orchestrator UI is at `http://127.0.0.1:18000`. Code engagements need ripgrep (`rg`) on the
host. The two installed layers, host-side recon tools on Docker Desktop, and other install
detail: [`docs/installation.md`](docs/installation.md).

## Documentation

| Document | What it covers |
|----------|----------------|
| [`docs/installation.md`](docs/installation.md) | Install detail: the CLI binary vs working root, host-side recon tools, ripgrep. |
| [`docs/engagements.md`](docs/engagements.md) | Creating engagements, tracks and modes, the start preflight, phase transitions. |
| [`agent/AGENTS.md`](agent/AGENTS.md) | The operator prompt — the workflow every engagement runs. |
| [`CODE-MAP.md`](CODE-MAP.md) | Map of the codebase: where each subsystem lives. |
| [`AGENTS.md`](AGENTS.md) | Maintainer and contributor workflow, and the verification matrix. |
| [`docs/assessment-cli.md`](docs/assessment-cli.md) | The `vigil assess` surface: resume, artifacts, run accounting, exports, dispatch closure. |
| [`docs/session-commands.md`](docs/session-commands.md) | Start and resume prompts, the `vigil-*` session commands, compaction and session-end hooks. |
| [`docs/agent-clients.md`](docs/agent-clients.md) | Per-client setup, launch behaviour, and flag forwarding. |
| [`docs/authentication.md`](docs/authentication.md) | Credential records, capture, freshness clocks, liveness verdicts, proxy routing. |
| [`docs/blue-engagements.md`](docs/blue-engagements.md) | Blue incident response, end to end. |
| [`docs/code-analysis.md`](docs/code-analysis.md) | White-box code analysis, end to end. |
| [`docs/remediation.md`](docs/remediation.md) | Work-in-progress remediation cases, evidence, review approval, and development verification. |
| [`docs/oob-routing.md`](docs/oob-routing.md) | Per-install relay-slot OOB routing, CoreDNS/Caddy inputs, the frpc conflict scan. |
| [`docs/operations.md`](docs/operations.md) | Runtime sizing, kernel limits, orchestrator data and backups. |
| [`docs/engagement-prompt-playbook.md`](docs/engagement-prompt-playbook.md) | Steering prompts for a session that goes shallow, overclaims, or loses the loop. |
| [`agent/references/`](agent/references/) | Payloads, tactics, recon, tenants, tools. Discover with `vigil assess list-references`. |

## Running an engagement

```bash
vigil engagement create https://target.example --hosts target.example
vigil engagement list --json                              # find the key
vigil engagement start <engagement-key> --client codex
```

`create` infers the engagement type from its inputs and starts the exploit policy at `pause`.
`start` runs a preflight, exports the engagement environment, and execs the client; flags it does
not own are forwarded to the client. Start engagements with `vigil engagement start` only — the
generated `start_<client>.sh` and a bare client run skip the preflight and environment. A web and
code engagement runs one session per track with `--mode web` or `--mode code`. Detail:
[`docs/engagements.md`](docs/engagements.md).

A later session on the same engagement opens the same way, then runs `vigil-resume`, which
restores the operator role and rebuilds live state from the backend. Fuller start and resume
prompts and the mid-session `vigil-*` commands: [`docs/session-commands.md`](docs/session-commands.md).

All clients read the same operator prompt. They differ in model, headless specialist dispatch,
and session-command support; `pi` is available for remediation engagements. Setup per client:
[`docs/agent-clients.md`](docs/agent-clients.md).

Remediation uses the repository's `PROJECT.md` for ticket readers, MCPs, skills,
branch/workspace policy, checks, PR guidance, and deployment choices. Open its
repository-context Claude session with `vigil remediation -k <key> start`, then
use `/vigil-remediate SEC-123` or supply several ticket IDs/URLs. One bug uses the
current developer conversation; batches coordinate separate joinable sessions.
Case code lives in its registered Git/JJ workspace while native project context
remains at the repository root. See [`docs/remediation.md`](docs/remediation.md).

When the profile selects `hook_policy = "disabled"`, Vigil announces that
non-managed hooks are disabled only for that remediation session. Required
formatting, analysis, and tests run explicitly against case source during
verification and before publishing. Managed policy hooks remain active; ordinary
sessions and repository hook files are unchanged.

## Engagement tracks and phases

| Track | Phases | Persisted as |
|---|---|---|
| **web** (red) | `recon → collect → consume-test → verify → exploit → report` | `scope.json.tracks.web.phase` |
| **code** (white-box) | `ingest → classify-map → hunt → verify-variant → fuzz` | `scope.json.tracks.code.phase` |
| **blue** (incident response) | `intake → triage → investigate → verify → respond → report` | `scope.json.current_phase` |

Each track ends in the shared `complete` state. `vigil assess transition-phase` gates every
transition; `--force` records a durable override, and some integrity blockers cannot be forced.
Roster, readiness previews, and the specialist roles: [`docs/engagements.md`](docs/engagements.md#phases).
Blue engagements: [`docs/blue-engagements.md`](docs/blue-engagements.md). Code analysis:
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

**Authenticated capture.** Route a browser through `http://127.0.0.1:8080` after
`vigil mitmproxy start`, log in against any scoped host, then confirm with
`vigil auth status <key>`. A second login appends a second identity for cross-account
(IDOR/BOLA) testing. Detail: [`docs/authentication.md`](docs/authentication.md).

**Callbacks, listeners, and tunnels** are operator-controlled shared infrastructure: agents
provide commands but never start them, and Vigil ships no fallback relay — the relay is yours to
run. Configure it before `vigil install`, which reserves this install's relay slot:

```bash
vigil config set oob.frp_host oob-relay.example.com   # also: oob.frp_port, oob.domain, oob.frp_token
vigil install                                        # reserves this install's relay slot
vigil oob start && vigil oob status --json
vigil oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
vigil oob test
```

Relay slots, refusal cases, and edge routing: [`docs/oob-routing.md`](docs/oob-routing.md).
Payload-side tradecraft:
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
| `vigil remediation ...` | **Work in progress.** Separate remediation engagements: Jira/bounty import, `from-finding` intake, shared-fix finding links, worktrees, evidence, review, and PR handoff — see [`docs/remediation.md`](docs/remediation.md). |
| `vigil blue ...` | Blue incident response — see [`docs/blue-engagements.md`](docs/blue-engagements.md). |
| `vigil auth status \| show \| edit \| clear \| export \| quarantine \| import \| alias \| env-check \| set-active \| keepalive` | Manage engagement credentials in the backend store. |
| `vigil mitmproxy start \| stop \| status \| cert \| build \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| stop \| restart \| status \| routing \| test \| clean \| mint \| poll \| client` | Manage shared OOB and render relay-slot edge-routing inputs. |
| `vigil config path \| list \| get \| set \| unset \| edit` | Read and write persistent CLI config. |
| `vigil backup create \| list \| show \| restore` | Manual orchestrator DB backup operations. |
| `vigil email <mailbox>` | Read a local Mail.app test mailbox for verification codes during authenticated testing. |

Every command documents its full flag set under `--help`; runtime tool verbs live under
`vigil assess kali --help`.

### When a command name changes

A renamed verb keeps its old spelling as an alias where it honestly can, and
[`CHANGELOG.md`](CHANGELOG.md) records both spellings. Older audit rows and transcripts keep the
name that ran; if a name is missing from `--help`, check the changelog.

## Security

Vigil ships a full offensive Kali runtime and drives autonomous specialist agents against live
targets. Treat it accordingly.

- **Authorized targets only.** Every operator start prompt begins with an explicit authorization
  statement, and engagement scope is pinned in `scope.json`. Scope drives recon shaping,
  attribution, and coverage accounting; it is not a destination firewall. Only run against hosts
  and tenants you are contractually authorized to test.
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
| `src/vigil_cli/` | The `vigil` CLI: install, runtime, orchestrator, engagements, auth, and OOB. |
| `agent/` | Operator and specialist prompts, phase docs, rules, skills, the reference library, the `vigil assess` scripts, and the runtime Dockerfiles. |
| `orchestrator/` | Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility. |
| `tests/` | CLI pytest suite. Backend tests live in `orchestrator/backend/tests/`. |
| `docs/` | Deep reference, ADRs, and plans. |

Extending Vigil is a contributor workflow, documented in the [maintainer recipes](docs/maintainer-guide.md):
adding a skill, a `vigil assess` verb, a deterministic oracle, or an eval case. Use the authoritative
[test and verification matrix](AGENTS.md#tests--verification). Durable design decisions live in
[`docs/adr/`](docs/adr/). To confirm a *running install* is healthy rather than the contributor
suite, use `vigil doctor` and `vigil status`.
