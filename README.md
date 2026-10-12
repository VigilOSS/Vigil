<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/vigil-lockup-dark.svg">
  <img alt="Vigil" src="docs/assets/logo/vigil-lockup-light.svg" width="280">
</picture>

**An AI harness for long-running pentests, bug bounties, and code audits, with independently verified findings.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.2.4-green.svg)](https://github.com/VigilOSS/Vigil)

</div>

Vigil runs long offensive security engagements: web app pentesting and bug bounty hunting,
white-box code audits, or both against one target. A lean operator keeps the engagement on track
while specialist agents recon, hunt, and exploit inside a full Kali runtime. A finding counts only
when a second agent confirms it against captured evidence, and attack chains show its real
impact. Every command, request, probe, and finding lands in a durable database, so the work
survives context limits and restarts and can be audited afterward.

> **Authorized use only.** Vigil autonomously drives offensive tooling against live systems.
> Use it only with explicit authorization and a reviewed scope. It is provided without warranty
> under the [Apache License 2.0](LICENSE); you are responsible for commands, credentials,
> infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private vulnerability
> reporting and the operator-data boundary.

## What Vigil provides

- **Long-running engagements.** State lives in the backend, so an engagement survives
  compaction, restarts, and new sessions.
- **Independently verified findings.** Only a dispatch other than the author's can confirm,
  downgrade, or mark a finding false positive, and it must cite a proof receipt of captured
  evidence.
- **Impact.** Attack chains link findings into end-to-end exploitation; by default, exploit work
  waits for your approval.
- **An audit trail.** Target-facing commands run through `vigil assess kali`, which records each
  command's argv, agent, phase, technique, intent, probe kind, exit status, and output. Coverage
  ledgers show what was tested and what was not.
- **Attack tooling.** A long-lived Kali container with ProjectDiscovery recon, fuzzers, an
  audited Playwright browser, MITM capture with multiple identities for cross-account testing,
  and out-of-band callbacks correlated to the probe that caused them.
- **White-box code audits.** A sealed, content-addressed source snapshot with a tree-sitter
  structural index and a coverage ledger.
- **Submission-ready output.** Findings export as hash-verified Bugcrowd, HackerOne, or direct
  disclosure write-ups.
- **Clients.** Claude Code and Codex have full support: headless specialist dispatch, `vigil-*`
  session commands, and compaction and session hooks. goose, opencode, and Kimi lack session
  commands and compaction hooks, and opencode and Kimi run specialists inline. Pi supports
  remediation engagements only.

### How Vigil hunts

- **No pre-named bugs.** Over-prompting caps what a model finds. Dispatches carry the surface,
  scope, and rules of engagement, never the bug to look for or a checklist. Web specialists choose
  what to probe within that surface; code hunters get a file batch and the vulnerability classes
  to score.
- **One lens per hunt.** Each hunting dispatch sets how wide to go, how to work through its
  inputs, and at most one mindset lens: developer, injection, access control, business logic,
  chain impact, or skeptical verifier.
- **Independent verification.** A finding is confirmed only by a different agent working from
  captured evidence. Code engagements add an anchor-free re-read of the highest-risk files and a
  variant sweep across every file; web testing walks every sibling route, method, and content type
  that shares the vulnerable code path.
- **Kill-first triage.** Web leads must pass eight ordered questions, including whether a real
  request reproduces it and whether the impact is proven. Code findings must earn PASS with the
  same evidence a KILL would need.
- **A skill library, not pasted prompts.** 90+ skills and 200+ references are found through
  `vigil assess list-skills` and `vigil assess list-references`. Web specialists load them when
  they see the matching signal; the code operator names them in each dispatch.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/findings-dark.png">
  <img alt="Vigil orchestrator UI: an engagement's findings grouped by severity, workflow, and verification" src="docs/assets/findings-light.png">
</picture>

## Quick start

```bash
# 1. Install the application release (CLI, backend, prompts, docs, and prebuilt UI)
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v1.2.4/vigil-1.2.4-py3-none-any.whl vigil
#    OR install directly from the repository (builds the UI locally; needs Git, Node.js, and npm)
uv tool install git+https://github.com/VigilOSS/Vigil vigil

# 2. Check the host: prerequisites, missing recon tools, and the ordered setup checklist
vigil quickstart

# 3. Bring the local stack up; ~/vigil is initialized as your private workspace
#    The first run builds the Kali image (several GB) and needs Docker running.
vigil up

# 4. Create an engagement; it prints the engagement key and its start command
vigil engagement create

# 5. Start the operator on it
vigil engagement start <engagement-key> --client codex   # or --client claude
```

For a **code** engagement, put your source files or project folders in the `source/` location
printed by creation (Git is optional). The code client asks you to confirm them at startup; an
empty folder leaves it waiting. Code engagements need ripgrep (`rg`) on the host. Details:
[`docs/code-analysis.md`](docs/code-analysis.md).

For a **web** engagement, tell the operator what it is authorized to do:

```
I have been fully authorized by the company to do a red-team engagement against the
hosts in scope.json. Run this engagement using the operator web workflow.
```

The orchestrator UI is at `http://127.0.0.1:18000`. On macOS or Windows Docker Desktop,
DNS-heavy recon runs on the host; `vigil quickstart --install-host-tools` installs those tools.
Upgrades and workspace layout: [`docs/installation.md`](docs/installation.md).

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
| Code | Medium | $100/month; expect limits before you finish a repository |
| Code, hardened codebase | High | $200/month |
| Web | High or above | $200/month |

> [!TIP]
> **Bug bounties:** look for source maps. Download the `.map` files, recover the source with
> `vigil assess code-sourcemap-extract`, and run a code engagement on it. Then run
> `vigil engagement add-track <key> web` and `vigil engagement add-host <key> <host>` so web
> testing builds on its findings ([tracks](docs/engagements.md#tracks-and-modes)).

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

Detail: [`docs/engagements.md`](docs/engagements.md),
[`docs/session-commands.md`](docs/session-commands.md),
[`docs/agent-clients.md`](docs/agent-clients.md).

## Engagement tracks and phases

| Track | Phases | Persisted as |
|---|---|---|
| **web** (red team) | `recon → collect → consume-test → verify → exploit → report` | `scope.json.tracks.web.phase` |
| **code** (white-box) | `ingest → classify-map → hunt → verify-variant → fuzz` | `scope.json.tracks.code.phase` |
| **remediation** (work in progress) | `intake → baseline → fixing → review → approved → pr_draft → development → verified → closed` | `remediation_cases.status` per case |

Web and code tracks end in `complete`, and `vigil assess transition-phase` gates every
transition; `--force` records a durable override, and some integrity blockers cannot be forced.
Roster, readiness previews, and specialist roles: [`docs/engagements.md`](docs/engagements.md#phases).

**Remediation** (work in progress) takes a finding or ticket to a reviewed fix. Each case gets
its own Git worktree or JJ workspace, records proof that the fix works, and needs your approval
before a draft PR. The repository's `PROJECT.md` configures ticket
readers, checks, and publishing. Start with `vigil remediation -k <key> start`, then
`/vigil-remediate SEC-123`. See [`docs/remediation.md`](docs/remediation.md).

Blue incident response also runs on the same backend; see
[`docs/blue-engagements.md`](docs/blue-engagements.md).

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
execution.

<details>
<summary>Bundled tools</summary>

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

</details>

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

<details>
<summary>All commands</summary>

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
| `vigil assess ...` | The assessment surface; see [`docs/assessment-cli.md`](docs/assessment-cli.md). |
| `vigil remediation ...` | **Work in progress.** Remediation engagements: Jira/bounty import, `from-finding` intake, shared-fix links, worktrees, evidence, review, and PR handoff — see [`docs/remediation.md`](docs/remediation.md). |
| `vigil auth status \| show \| edit \| clear \| export \| quarantine \| import \| alias \| env-check \| set-active \| keepalive` | Manage engagement credentials in the backend store. |
| `vigil mitmproxy start \| stop \| status \| cert \| build \| reload \| routes` | Manage the shared MITM proxy. |
| `vigil oob start \| stop \| restart \| status \| routing \| test \| clean \| mint \| poll \| client` | Manage shared OOB and render relay-slot edge-routing inputs. |
| `vigil config path \| list \| get \| set \| unset \| edit` | Read and write persistent CLI config. |
| `vigil backup create \| list \| show \| restore` | Manual orchestrator DB backup operations. |
| `vigil email <mailbox>` | Read a local Mail.app test mailbox for verification codes during authenticated testing. |
| `vigil blue ...` | Blue incident response; see [`docs/blue-engagements.md`](docs/blue-engagements.md). |

</details>

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

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

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
