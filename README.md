<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/vigil-lockup-dark.svg">
  <img alt="Vigil" src="docs/assets/logo/vigil-lockup-light.svg" width="280">
</picture>

**AI-driven offensive and incident-response engagements — operator prompts, a full Kali runtime, and durable orchestrator state in one CLI.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.1.0-green.svg)](https://github.com/VigilOSS/Vigil)

</div>

An LLM operator follows a phased workflow prompt, dispatches specialist agents, runs real
tooling in a shared Kali container, and records every target, service, request variant, probe,
finding, and attack chain in a durable orchestrator database. Web red-team, white-box code,
Android, and blue incident-response engagements share one backend; an offensive engagement can
enable web and code tracks together, with each client process running one mode.

> **Authorized use only.** Vigil autonomously drives offensive tooling against live systems.
> Use it only with explicit authorization and a reviewed scope. It is provided without warranty
> under the [Apache License 2.0](LICENSE); you are responsible for commands, credentials,
> infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private vulnerability
> reporting and the operator-data boundary.

## Models and access

Vigil is built primarily around **Claude Code** and **Codex**.

| Model | Engagements |
|---|---|
| Claude Opus 5, with Anthropic's Cyber Verification Program (CVP) | Web and code |
| GPT-5.6 Sol, with OpenAI's Trusted Access for Cyber | Web and code |
| Claude Opus 5.5, GPT-6.1 Sol | Code; web needs an organization-only red-team tier |

- **Claude Code:** CVP works with Opus 5, which is not in the `/model` picker. Select it directly
  with `/model claude-opus-5[1m]` ([model configuration](https://code.claude.com/docs/en/model-config)).
- **Codex:** choose GPT-5.6 Sol and its reasoning effort in `/model`.

As of October 2026, red-team access to the newest models is for organizations only:

- **Anthropic:** CVP **Defense Access** is open to organizations and individual researchers;
  **Red Team Access** is organizations only ([CVP tiers](https://www.anthropic.com/news/cyber-verification-program)).
- **OpenAI:** **Daybreak Blue** covers defensive work for individuals and organizations;
  **Daybreak Red** is for approved organizations only
  ([access guidance](https://learn.chatgpt.com/docs/cyber-safety),
  [Daybreak overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview)).

Planned: broader support for **GLM 5.3** and other models with more predictable access, through
lower orchestration overhead, model-specific prompts, and deeper **OpenCode** integration.

## Effort and usage

The operator keeps a small context and delegates: 95%+ of tokens are spent by specialist
sub-agents, which keeps one operator session on track for much longer. Expect to hit usage
limits quickly.

| Engagement | Reasoning effort | Plan |
|---|---|---|
| Code | Medium | $100/month — expect limits before you finish a repository |
| Code, hardened codebase | High | $200/month |
| Web | High or above | $200/month |

State lives in the backend: after a limit resets, start the engagement again and run
`vigil-resume`.

> [!TIP]
> **Bug bounties:** look for source maps, an exposed `.git`, or backups first. A code engagement
> on recovered source has much greater success than black-box testing. Add the code track to the
> same engagement with `vigil engagement add-track <key> code`; its findings land in the same
> findings table as the web session's
> ([details](docs/code-analysis.md#mid-engagement-code-analysis)).

## What Vigil provides

- **Independently verified findings.** Only a dispatch other than the author's can confirm,
  downgrade, or mark a finding false positive, citing a proof receipt of captured evidence.
- **Audited target-facing commands.** `vigil assess kali` records each command's technique,
  intent, and probe kind.
- **Real attack tooling** — a long-lived Kali container with ProjectDiscovery recon, fuzzers,
  an audited Playwright browser, MITM capture with multiple identities for cross-account testing,
  and out-of-band callbacks correlated to the probe that caused them.
- **White-box code analysis** against a sealed, content-addressed source snapshot with a
  tree-sitter structural index and a coverage ledger.
- **Durable state** — targets, services, request variants, probes, findings, chains, and
  credentials in SQLite, with rotated backups and a web UI.
- **Six clients, one methodology** — Claude Code, Codex, Kimi, goose, opencode, and Pi
  (remediation only).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/findings-dark.png">
  <img alt="Vigil orchestrator UI: an engagement's findings grouped by severity, workflow, and verification" src="docs/assets/findings-light.png">
</picture>

## Quick start

```bash
# 1. Install the application release (CLI, backend, prompts, docs, and prebuilt UI)
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v1.1.0/vigil-1.1.0-py3-none-any.whl vigil

# 2. Check the host: prerequisites, missing recon tools, and the ordered setup checklist
vigil quickstart

# 3. Bring the local stack up; ~/vigil is initialized as your private workspace
#    First run builds the Kali image — several GB, and it needs Docker running.
vigil up

# 4. Create an engagement; follow the questions to choose its type and give it a name/target
vigil engagement create

# 5. Start the operator on it
vigil engagement start <engagement-key> --client codex   # or claude | opencode | goose | kimi
```

For a **code** engagement, put your source files or project folders in the `source/` location
printed by creation (Git is optional). The code client asks you to confirm them at startup; an
empty folder leaves it waiting. Code engagements need ripgrep (`rg`) on the host. Details:
[`docs/code-analysis.md`](docs/code-analysis.md).

For a **web** engagement, tell the operator what it is authorized to do:

```
I have been fully authorized by the company to do a red-team engagement against the
hosts in scope.json. Run this engagement using the operator workflow.
```

The orchestrator UI is at `http://127.0.0.1:18000`. Releases, private workspaces, and host-side
recon tools on Docker Desktop: [`docs/installation.md`](docs/installation.md).

## Running an engagement

- `vigil engagement start` selects one session mode, runs a preflight, prints the workspace,
  engagement, client, mode, and phase to stderr, exports the engagement environment, and execs
  the client. Flags it does not own are forwarded to the client.
- Always start through `vigil engagement start`; the generated `start_<client>.sh` and a bare
  client run skip the preflight and environment.
- A web + code engagement needs `--mode web` or `--mode code`; a single track is selected
  automatically. Change modes by starting a new client process. `vigil engagement mode <key>`
  shows enabled tracks, phases, prompt paths, and start commands.
- Later sessions start the same way, then run `vigil-resume` to restore the operator role and
  rebuild live state from the backend.

All clients read the same operator prompt; they differ in model, headless specialist dispatch,
and session-command support. Detail: [`docs/engagements.md`](docs/engagements.md),
[`docs/session-commands.md`](docs/session-commands.md),
[`docs/agent-clients.md`](docs/agent-clients.md).

**Remediation** (work in progress) reads the repository's `PROJECT.md` for ticket readers, MCPs,
skills, branch policy, checks, PR guidance, and deployment. Start with
`vigil remediation -k <key> start`, then `/vigil-remediate SEC-123` (or several ticket IDs/URLs).
See [`docs/remediation.md`](docs/remediation.md).

## Engagement tracks and phases

| Track | Phases | Persisted as |
|---|---|---|
| **web** (red) | `recon → collect → consume-test → verify → exploit → report` | `scope.json.tracks.web.phase` |
| **code** (white-box) | `ingest → classify-map → hunt → verify-variant → fuzz` | `scope.json.tracks.code.phase` |
| **blue** (incident response) | `intake → triage → investigate → verify → respond → report` | `scope.json.current_phase` |

Each track ends in `complete`. `vigil assess transition-phase` gates every transition; `--force`
records a durable override, and some integrity blockers cannot be forced. Roster, readiness
previews, and specialist roles: [`docs/engagements.md`](docs/engagements.md#phases).

## Runtime model

`vigil up` (or `vigil runtime start`) starts one long-lived Kali container named `vigil`.
Target-facing commands run through `vigil assess kali ...` via `docker exec`; long scans run
through `vigil assess kali job start ...` under an in-container `dtach` supervisor, so they
survive the operator session.

The container mounts shared runtime data at `.runtime-data/`, bind-mounts the engagement root at
`/engagements`, and receives the root `.env` when present. Fresh workspaces keep artifacts under
`engagements/<key>/`; adopted workspaces keep their existing paths. For non-interactive
maintenance, use `vigil runtime shell-exec "<cmd>"` so quoting and exit codes stay under the CLI.

`agent/docker/runtime-full/Dockerfile` is the only supported runtime for target-facing
execution:

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

`agent/docker/runtime-lightweight/Dockerfile` is for faster Dockerfile iteration only
(`vigil runtime build lightweight --dev`). Sizing, kernel limits, and backups:
[`docs/operations.md`](docs/operations.md).

## Optional capabilities

| Capability | Default | Start command | Purpose |
|------------|---------|---------------|---------|
| MITM proxy | off | `vigil mitmproxy start` | Authenticated capture into each engagement's backend credential store. |
| OOB (frp + interactsh) | off | `vigil oob start` | Out-of-band callback detection over shared frp/interactsh. |
| Universal ctags | host-installed | `brew install universal-ctags` | Richer code-analysis definition lookups. |

**Authenticated capture.** After `vigil mitmproxy start`, route a browser through
`http://127.0.0.1:8080`, log in to any scoped host, and confirm with `vigil auth status <key>`.
A second login adds a second identity for cross-account (IDOR/BOLA) testing. Detail:
[`docs/authentication.md`](docs/authentication.md).

**Callbacks, listeners, and tunnels** are started by the operator, never by agents. Vigil ships
no fallback relay; configure your own before `vigil install`, which reserves this install's
relay slot:

```bash
vigil config set oob.frp_host oob-relay.example.com   # also: oob.frp_port, oob.domain, oob.frp_token
vigil install                                        # reserves this install's relay slot
vigil oob start && vigil oob status --json
vigil oob client start example-agent --engagement <engagement-key> --agent vulnerability-analyst
vigil oob test
```

Relay slots, refusal cases, and edge routing: [`docs/oob-routing.md`](docs/oob-routing.md).
Payload-side tradecraft: [`frp-tunneling.md`](agent/references/offensive-tactics/frp-tunneling.md),
[`shell-handling.md`](agent/references/offensive-tactics/shell-handling.md).

## Command reference

| Command | Purpose |
|---------|---------|
| `vigil quickstart` | Probe host prerequisites and recon tools, print the setup checklist. Installs host tools only with `--install-host-tools`. |
| `vigil install [path]` | Initialize or adopt a private workspace in place, preserving engagements, DB, `.env`, and client files. |
| `vigil up` | Initialize or adopt the workspace, build stale images, start the local stack from matched application assets. |
| `vigil doctor` | Check local readiness and prerequisites. Exits non-zero on a `FAIL` row; `--json` for a machine-readable report. |
| `vigil status` | Report live service state. |
| `vigil logs <target> [--lines N]` | Tail logs for `orchestrator`, `runtime`, `mitmproxy`, `oob`, or `all`. |
| `vigil runtime build \| start \| stop \| restart \| status \| shell \| shell-exec \| resources` | Manage the shared Kali runtime container. |
| `vigil orchestrator start \| stop \| restart \| status \| open \| build` | Manage the orchestrator backend and UI. |
| `vigil engagement create \| list \| mode \| start \| open \| path \| current \| cd-init \| archive \| export \| export-pdf` | Create, inspect, and drive engagements. Scope edits (`add-host`, `add-oos`, `set-header`, `add-track`, `set-rate-limit`, …) live here too — `vigil engagement --help`. |
| `vigil use <key>` | Set the persisted active engagement for global services. |
| `vigil assess ...` | The assessment surface — see [`docs/assessment-cli.md`](docs/assessment-cli.md). |
| `vigil remediation ...` | **Work in progress.** Remediation engagements: Jira/bounty import, `from-finding` intake, shared-fix links, worktrees, evidence, review, and PR handoff — see [`docs/remediation.md`](docs/remediation.md). |
| `vigil blue ...` | Blue incident response — see [`docs/blue-engagements.md`](docs/blue-engagements.md). |
| `vigil auth status \| show \| edit \| clear \| export \| quarantine \| import \| alias \| env-check \| set-active \| keepalive` | Manage engagement credentials in the backend store. |
| `vigil mitmproxy start \| stop \| status \| cert \| build \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| stop \| restart \| status \| routing \| test \| clean \| mint \| poll \| client` | Manage shared OOB and render relay-slot edge-routing inputs. |
| `vigil config path \| list \| get \| set \| unset \| edit` | Read and write persistent CLI config. |
| `vigil backup create \| list \| show \| restore` | Manual orchestrator DB backup operations. |
| `vigil email <mailbox>` | Read a local Mail.app test mailbox for verification codes during authenticated testing. |

Every command documents its full flag set under `--help`; runtime tool verbs live under
`vigil assess kali --help`.

## Security

- **Authorized targets only.** Every operator start prompt begins with an explicit authorization
  statement, and scope is pinned in `scope.json`. Scope drives recon shaping, attribution, and
  coverage accounting; it is not a destination firewall.
- **Exploit work is gated.** The default exploit policy is `pause`: explicit human approval before
  any exploit-developer dispatch. Policies (`pause` / `selected` / `full_send`) are set per
  engagement in `scope.json` and enforced through the operator workflow.
- **Blue write actions are audited.** Tenant-facing WRITE and respond actions run with
  `--require-audit`; containment is split into proposal approval, audited execution, and
  explicit recording.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Documentation

| Document | What it covers |
|----------|----------------|
| [`docs/installation.md`](docs/installation.md) | Application releases, private workspaces, upgrades, host-side recon tools, ripgrep. |
| [`docs/engagements.md`](docs/engagements.md) | Creating engagements, tracks and modes, the start preflight, phase transitions. |
| [`agent/AGENTS.md`](agent/AGENTS.md) | The operator prompt — the workflow every engagement runs. |
| [`docs/assessment-cli.md`](docs/assessment-cli.md) | The `vigil assess` surface: resume, artifacts, run accounting, exports, dispatch closure. |
| [`docs/session-commands.md`](docs/session-commands.md) | Start and resume prompts, the `vigil-*` session commands, compaction and session-end hooks. |
| [`docs/agent-clients.md`](docs/agent-clients.md) | Per-client setup, launch behaviour, and flag forwarding. |
| [`docs/authentication.md`](docs/authentication.md) | Credential records, capture, freshness clocks, liveness verdicts, proxy routing. |
| [`docs/blue-engagements.md`](docs/blue-engagements.md) | Blue incident response, end to end. |
| [`docs/code-analysis.md`](docs/code-analysis.md) | White-box code analysis, end to end. |
| [`docs/remediation.md`](docs/remediation.md) | Work-in-progress remediation cases, evidence, review approval, development verification, and hook policy. |
| [`docs/oob-routing.md`](docs/oob-routing.md) | Per-install relay-slot OOB routing, CoreDNS/Caddy inputs, the frpc conflict scan. |
| [`docs/operations.md`](docs/operations.md) | Runtime sizing, kernel limits, orchestrator data and backups. |
| [`docs/engagement-prompt-playbook.md`](docs/engagement-prompt-playbook.md) | Steering prompts for a session that goes shallow, overclaims, or loses the loop. |
| [`agent/references/`](agent/references/) | Payloads, tactics, recon, tenants, tools. Discover with `vigil assess list-references`. |
| [`CODE-MAP.md`](CODE-MAP.md) | Map of the codebase: where each subsystem lives. |
| [`AGENTS.md`](AGENTS.md) | Maintainer and contributor workflow, and the verification matrix. |

## Repository layout and development

| Path | Contents |
|---|---|
| `src/vigil_cli/` | The `vigil` CLI: install, runtime, orchestrator, engagements, auth, and OOB. |
| `agent/` | Operator and specialist prompts, phase docs, rules, skills, the reference library, the `vigil assess` scripts, and the runtime Dockerfiles. |
| `orchestrator/` | Backend and frontend for durable run state, events, artifacts, coverage, and phase visibility. |
| `tests/` | CLI pytest suite. Backend tests live in `orchestrator/backend/tests/`. |
| `docs/` | Deep reference, ADRs, and plans. |

To extend Vigil (a skill, `vigil assess` verb, deterministic oracle, or eval case), follow the
[maintainer recipes](docs/maintainer-guide.md) and the
[test and verification matrix](AGENTS.md#tests--verification). Design decisions live in
[`docs/adr/`](docs/adr/). To check a running install, use `vigil doctor` and `vigil status`.
