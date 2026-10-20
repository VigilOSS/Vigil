<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/vigil-lockup-dark.svg">
  <img alt="Vigil" src="docs/assets/logo/vigil-lockup-light.svg" width="280">
</picture>

**Find bugs, follow the code, and prove what an attacker can do.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/VigilOSS/Vigil/releases/tag/v2.0.0)

</div>

Vigil is an AI harness for code audits, web pentests, and bug bounty hunting. It coordinates
Claude Code or Codex through broad review, focused rereads, authenticated testing, and runtime
reproduction. Start with a codebase, a live application, or both.

The first pass is a starting point. Higher-risk code gets another look with a different
objective. Specialists follow callers, challenge guards, join paths across modules, and hunt
variants of defects they find. Promising leads stay on the books when runtime proof or access
is still missing. Findings, evidence, coverage, and handoffs carry across sessions.

Vigil was built by an application security engineer and refined over eight months and hundreds
of hours of hands-on use. Much of that work is in the methodology: how to find something worth
testing, how to tell a failed test from a real negative, and how to keep a plausible source bug
from becoming an unsupported impact claim.

**You are still the operator.** Review what the agents are testing and why. Ask for another
pass when a conclusion is weak, check the proof, and read the final report. A completed workflow
is useful accounting; the quality of the investigation still depends on the model and your review.

> **Authorized use only.** Vigil drives offensive tooling against live systems. Use it only
> with explicit authorization and a reviewed scope. You are responsible for commands,
> credentials, infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private
> vulnerability reporting and the operator-data boundary, and [LICENSE](LICENSE) for the warranty.

## See it work

One [Fluent Bit](https://github.com/fluent/fluent-bit) engagement began with
`plugins/out_es/es.c`. Following the code expanded the admitted analysis scope to nine files.

| | Result |
|---|---|
| Elapsed session | **2 h 59 m**, from the initial brief to a finished advisory |
| Analysis scope | **9 files / 2,572 LOC**, all nine reviewed; a separate 495-file core tree indexed for context |
| Findings | **3**, reproduced at runtime against a live Elasticsearch 8.15.0: one critical, two medium |
| Agent work | 17 tasks across five specialist agents; 945 tool calls and 7.2 hours of combined agent time |

https://github.com/user-attachments/assets/bf99a0bb-df71-4966-a390-708cf23d9e62

[Watch the video](https://vigiloss.github.io/Vigil/vigil-fluent-bit-audit.mp4) if it does not play
here. It is heavily trimmed to eleven moments from the three-hour session.

**This was a historical replay.** The source was pinned before an upstream fix. Repository
lookups and cloning were off limits; CVE, advisory, and changelog checks waited until the
write-up was done. This demonstrates the workflow on that revision, rather than a fresh
zero-day discovery benchmark. One finding remains withheld pending vendor disclosure.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fluent-bit-findings-dark.png">
  <img alt="The engagement's three recorded findings. Two are shown in full; the third is withheld pending vendor disclosure because it is still unfixed upstream." src="docs/assets/fluent-bit-findings-light.png">
</picture>

<details>
<summary>What the investigation established</summary>

`out_es` pastes a record-derived index name into Bulk API syntax. A log producer who controls
that field can add an extra action line, sent under Fluent Bit's Elasticsearch credential.
Against a cluster with security enabled and a collector role restricted to `fluent-bit*`, one
record deleted another producer's document without Fluent Bit recording an error. The sibling
`out_opensearch` implementation carries the same code. Upstream fixed this in 4.2.6; it has
no CVE, GHSA, or published advisory.

A separate verifier dispatch challenged the critical finding five ways. Two challenges were
resolved by runtime capture. Severity changed from 9.1 to 7.1 on scope reasoning, then returned
to 9.1 after an authenticated retest measured the availability loss. A third agent received
only the draft advisory and found six errors, including repeated incorrect line citations and
a proposed patch that would have hung the process. Those errors were corrected before release.

Lab commands went through the audited execution surface, retaining their purpose, target,
exit status, and output. Advisory claims trace to those records, runtime transcripts, or
verifier scripts. The withheld finding stays with maintainers until a fix ships or the
disclosure window closes.

</details>

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then install the release.
It includes the CLI, backend, prompts, documentation, and prebuilt UI; Git and Node are not needed.

```bash
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v2.0.0/vigil-2.0.0-py3-none-any.whl vigil
```

Install and sign in to an agent client before starting an operator. Engagement clients:
**Claude Code, Codex, OpenCode, ZCode, Goose, Kimi, and Pi**. Setup and support differences:
[agent clients](docs/agent-clients.md). Model access affects what testing the provider permits;
check [models and access](docs/model-access.md).
For ZCode desktop, follow [ZCode setup](docs/zcode-setup.md): open the exact generated
workspace printed by Vigil, enable its local plugin, and begin a fresh task.

Start without an engagement ID to choose an existing engagement by recent work
or client opening, or choose **Create new engagement** using the same creation
questions. This picker works for every client; an explicit ID skips it:

```bash
vigil engagement start --client zcode
```

For ZCode, creation comes before opening the project: Vigil opens the generated
**Project folder**, whose root `AGENTS.md` walks through setup. Enable the printed
local plugin and start a new task in that project. Do not open the audited source
directory or the Vigil source checkout as the engagement's ZCode project.
The installed `vigil` recognizes the generated project's engagement, workflow and
client during mode checks, client diagnostics and assessment commands. Setup checks
explain any identity conflict before workflow work begins.

### Audit source code

Static investigation needs `uv`, your agent client, and host-side ripgrep (`rg`). You can
start source review before building Kali or setting up browser capture.

```bash
vigil install
vigil engagement create --type code --name acme --source-dir ./acme --no-prompt
vigil engagement start <engagement-key> --mode code --client codex
```

Point `--source-dir` at the original project. The operator asks you to confirm the source,
and that you trust its build and test code to run inside the Vigil runtime, before creating
one sealed audit copy directly from it. The original stays untouched; loose files
work and Git history is optional. You can also create without `--source-dir` and put files
in the printed `source/` folder. Refreshing a snapshot requires another confirmation.

Starting the engagement brings up Vigil's backend on the host when needed. Source intake,
indexing, and source investigation run without Docker. Start Docker before compiling or
running target code, reproducing a bug, or fuzzing. Vigil prepares and starts Kali when an
audited command first needs it. If the release includes a matching image pin, Vigil pulls it; otherwise it builds
locally, which can take time on first use. See [code analysis](docs/code-analysis.md).

### Test a live application

Start Docker, then create the engagement:

```bash
vigil install
vigil engagement create https://app.example.com --hosts app.example.com
vigil engagement start <engagement-key> --mode web --client codex
```

Replace the example with your authorized target. Review `scope.json` and tell the operator
the allowed work, exclusions, accounts, and program rules. Exploit work waits for approval
by default. Already admitted hosts carry across sessions. New roots still need admission.
On Docker Desktop, broad DNS and liveness recon also needs host tools;
`vigil doctor --install-host-tools` installs missing tools. See [installation](docs/installation.md).

Kali starts when an audited command needs it. A release with a pinned runtime pulls the
matching image; a source checkout builds locally. `vigil up` explicitly starts the full
stack, including capture. Shared services and detached jobs outlive client sessions.

For authenticated testing, either import existing cookies and headers with
`vigil auth import <engagement-key> --source cookies-and-headers.json`, or route a browser
through `127.0.0.1:8080` after `vigil mitmproxy start` and log in. HTTPS capture needs the proxy
CA trusted by that browser.
Use separate accounts for cross-account tests. These are target identities, separate from
your Claude or Codex login. See [authentication](docs/authentication.md).

### Continue the investigation

Start the same engagement again. The operator uses `vigil-resume` to retrieve
recorded progress, evidence, blockers, and handoffs instead of reconstructing the investigation
from conversation alone. In an already open conversation, run `vigil-resume` yourself. Always
use `vigil engagement start` so preflight checks and engagement selection run. Upgrades and private workspace layout: [installation](docs/installation.md).

Talk to the operator in your native agent client. The UI at `http://127.0.0.1:18000` shows
findings, evidence, coverage, and proof work. A blocked proof stays visible while other
investigations continue. The operator claims proof work before dispatching a specialist,
so reopening a conversation is not a reason to launch the same work again.

A local library or CLI bug can be proved through its supported API in Kali. A live application
test reuses admitted targets and checks the applicable exploit approval. The specialist treats
the candidate as a hypothesis to challenge: confirm it, disprove it, narrow it, or explain what
blocks the test. Neither preparing work nor completing a task confirms the finding.

For manual inspection or recovery, use `vigil engagement prove <engagement-key>` or open
**Proof work** in the UI. The operator normally drives these steps; you do not need to assemble
handoff JSON or open a second operator just to prove a code finding.

For example prompts to deepen code or web testing, check coverage, or challenge a
finding, see the [engagement prompt playbook](docs/engagement-prompt-playbook.md).

## How Vigil hunts

### Start broad, then change the question

A guessed bug can become the limit of an investigation. Code hunters examine the applicable
vulnerability classes before checking the architect's suggested hypotheses. They receive the
source, its structural index, the threat model, and an objective. Small, related file batches
leave room to reason about the code rather than skim an oversized context dump.

Higher-risk files then get a fresh hostile reread with prior findings left out of the intended
dispatch context. The objective changes from finishing the review to finding what survived it.
Focused passes apply different lenses: access control, error handling, business logic, state,
lifetime, and other classes relevant to the target. A clean result under one lens leaves room
for another.

The developer lens asks what the implementation assumes: a copied endpoint kept its guard,
an old API has the same controls, a framework default is safe, a client validates the input,
or a failed allocation leaves the caller in a usable state. Those assumptions become questions
to investigate, rather than findings by themselves.

### Follow the code across boundaries

Hunters trace callers, transformations, guards, and the operation that can cause harm. They
also examine supported state and lifetime sequences, where there may be no simple input-to-sink
path. The structural index helps account for functions; it does not replace reading them.

A dedicated pass examines crossings between modules. Does one module rely on a guarantee the
other does not provide? Can a second entry path bypass the guard? Can a read, redirect, SSRF,
or state change combine with another primitive? Larger codebases are split into bounded seams,
then a further pass checks how those seams join into longer chains.

The product matters. A library's supported API or callback sequence can expose a real defect
even without the embedding application's source. Vigil's method separates that product path
from deployment-specific attacker access and limits the impact claim to the evidence available.
It also asks whether the alleged bug gives the caller any power they did not already have.

### Use a finding to find its relatives

A surviving defect triggers variant work: sibling routes, controllers, providers, content
types, authentication contexts, and copied implementations. Historical fixes can seed a hunt
for incomplete patches and semantic siblings. Related findings are linked by root cause while
retaining their distinct paths and outcomes.

### Prove the test worked

A timeout, WAF challenge, empty output, validation error, or stale login can invalidate a test.
Vigil's methodology calls for a working positive control on the same route, identity, and
gateway before accepting a negative. Failed or incomplete measurements remain visible as
inconclusive work. Previous negatives guide the next check and can be reopened when the
identity, technique, or target state changes.

One host can contain several substantial applications. Web coverage tracks application units,
inputs, identities, and probes so a quick host touch is distinguishable from deeper testing.
Specialists concentrate on promising surfaces, change technique when attempts stop teaching
anything, and return to unresolved breadth. Named identities support authenticated replay and
cross-account tests; the operator still needs to provision genuinely distinct usable accounts.

### Carry source findings through to runtime proof

A suspicious line is the start of a claim. The workflow asks for the shipped entry point or
supported operation, feasible preconditions, a failed security property, and a harmful outcome.
Source-backed leads waiting for runtime proof remain parked. Missing access is recorded as a
blocker. Program rules that forbid the final test are recorded alongside the unproven step.

Local reproduction of a library API, parser, or other supported code path can stay in the code
workflow and use Kali. When proof needs a live application, the current operator can dispatch
a fresh specialist with the explicit web proof route, admitted hosts, and applicable approval.
That specialist loads the web method; the operator does not need a second session or both
operator cores. A broader web engagement can still use its own track. Live proof enriches
the same finding. See [tracks and modes](docs/engagements.md#tracks-and-modes).

For bug bounties with source maps, recover the served source with
`vigil assess code-sourcemap-extract` and admit it to the code workflow. Its findings can then
guide live testing under the program's scope.

### Make the claim survive another agent

A finding has to stand on its evidence. Confirmation requires attributable proof from a
different registered dispatch. The workflow calls for a fresh agent to follow the authored
reproduction steps and another fresh-context review of the external report. Report writers
work from the recorded proof and reproduction sequence.

For medium-or-higher findings, the versioned per-finding submission flow checks that the
accepted review still matches the current report and attachments. Review instructions aim
to reduce anchoring; they cannot establish that an agent actually reasoned independently.
Human review remains necessary.

Report-writing rules favor demonstrated impact, short reproducible steps, and facts stated
once. If evidence supports less than the initial theory, the claim changes with it.

## What coverage tells you

Coverage records investigation work. It does not measure how many bugs exist or establish
that every vulnerability was found.

| Track | What is recorded |
|---|---|
| Code | A sealed source snapshot, structural index, file/function review, applicable-class effort, and unresolved structural or context gaps. Reference-only source remains available for tracing without counting as reviewed analysis scope. |
| Web | Hosts, application units, inputs, identities, and probes, including untested and inconclusive work. Relevant applications can carry class-specific depth requirements and recorded deferrals. |
| Continuation | Findings, evidence, dispatches, handoffs, work ownership, and blockers. These reconstruct the investigation; they are not a portable checkpoint of the native client's entire conversation or execution. |

Readiness checks use the recorded state to identify unfinished work and integrity problems.
Some gaps block progress, some warn, and some accept an explicit deferral or audited override.
A code audit cannot be forced to complete with outstanding durable coverage debt. None of
these checks can decide whether the reasoning was good enough or the target is free of bugs.

The methodology lives in the [operator](agent/AGENTS.md), [specialist roles](agent/agents/),
[skills](agent/skills/), and [references](agent/references/). The backend preserves the work
and checks its relationships. Read both when evaluating what Vigil can do.

## Tools and working environment

- **Authenticated replay:** named test identities, scoped cookies and headers, and `--identity`
  selection for cross-account testing.
- **Browser-assisted testing:** audited headless Chromium for client-rendered routes and
  challenges alongside plain HTTP observations.
- **Correlated callbacks:** nonce-tagged OOB URLs and `vigil oob poll` link callbacks to probes.
- **Resumable recon:** checkpointed subdomain discovery, liveness, crawling, JS mining, and
  archived URL collection, filtered against the engagement scope.
- **Submission drafts:** Bugcrowd, HackerOne, and direct-disclosure packages from recorded
  findings. Vigil does not submit to third-party platforms on your behalf.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/findings-dark.png">
  <img alt="Vigil orchestrator UI: an engagement's findings grouped by severity, workflow, and verification" src="docs/assets/findings-light.png">
</picture>

Target-facing tools run through `vigil assess kali ...` in one shared, long-lived Kali
container. Long scans use `vigil assess kali job start ...` so they can outlive the operator
session. DNS-heavy and bulk-liveness recon uses the host on Docker Desktop.

<details>
<summary>Bundled tools</summary>

| Category | Tools |
|---|---|
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

Browser capture uses `vigil mitmproxy start`; `vigil up` also starts the proxy. OOB callbacks
need your own relay configuration and `vigil oob start`. Universal ctags on the host improves
code definition lookups. Setup: [authentication](docs/authentication.md),
[OOB routing](docs/oob-routing.md), [code analysis](docs/code-analysis.md).

## Effort and model access

**Vigil spends tokens on depth.** Broad review, different hunting lenses, cross-file reasoning,
runtime experiments, variant searches, and reproduction all cost model work. Large repositories
and authenticated applications can consume substantial usage. Plan for provider interruptions
and use the persisted state to continue.

The operator keeps a small working context and delegates most analysis. Specialists load
detailed skills when the corresponding signal appears. That helps preserve context for the
investigation, but does not remove its cost.

Start code audits at medium reasoning effort and increase it for complex or hardened code.
Web testing generally benefits from high or greater effort where provider access allows it.
Current model selections and cyber-access restrictions: [models and access](docs/model-access.md).

## Workflows and controls

| Track | Phases |
|---|---|
| Web | `recon → collect → consume-test → verify → exploit → report` |
| Code | `ingest → classify-map → hunt → verify-variant → fuzz` |

The operator uses `vigil assess transition-phase` to evaluate readiness. Code findings use
the same per-finding submission workflow as web findings. Exploit policy defaults to `pause`,
requiring human approval before live exploit work; local sandbox proof follows the code route.
`selected` and `full_send`
policies are configured per engagement and applied through the operator workflow.

Scope in `scope.json` steers recon, attribution, and coverage. It is not a destination firewall;
the operator is responsible for staying inside the authorized boundaries. Credentials and
evidence remain operator data and can appear verbatim in engagement views and exports.

Other workflows: [blue incident response](docs/blue-engagements.md) and
[remediation](docs/remediation.md) (work in progress). Remediation prepares isolated fixes,
records verification, and requires approval before a draft PR. Blue containment separates
proposal approval, audited execution, and explicit recording.

Remediation clients: **Claude Code, OpenCode, and ZCode**. See
[agent clients](docs/agent-clients.md#repository-context-remediation-clients).
Run `vigil remediation start` to choose a recent remediation engagement or create
one for your repository, then select a client. `vigil remediation --help` explains
the ticket-to-fix workflow and the commands you need first.
For desktop installation, Coding Plan selection, local plugin enablement, and
workspace selection, see [ZCode setup](docs/zcode-setup.md).

The rationale behind hunting, evidence, coverage, and operator trust is in the
[architecture decisions](docs/adr/). Particularly relevant:
[measurement failures](docs/adr/0015-honest-instruments-distinguish-no-measurement-from-clean.md),
[retryable negatives](docs/adr/0016-target-knowledge-is-derived-and-negatives-are-retryable.md),
[proof ownership](docs/adr/0028-producer-provenance-binds-proof-to-work.md),
[rotating lenses](docs/adr/0034-one-lens-per-dispatch-rotated-across-surfaces.md), and
[unfinished findings](docs/adr/0035-unproven-findings-are-parked-or-blocked-never-dropped.md).

## Documentation and development

| Start here | What it covers |
|---|---|
| [Installation](docs/installation.md) | Releases, private workspaces, upgrades, and host tools |
| [Engagements](docs/engagements.md) | Creation, tracks, modes, preflight, and phase transitions |
| [Code analysis](docs/code-analysis.md) | Source admission, indexing, review, and runtime work |
| [Authentication](docs/authentication.md) | Capture, import, identities, freshness, and replay |
| [Agent clients](docs/agent-clients.md) / [model access](docs/model-access.md) | Client setup, launch behavior, and provider access |
| [Session commands](docs/session-commands.md) | Start, resume, compaction, and session-end hooks |
| [Assessment CLI](docs/assessment-cli.md) | Agent commands, evidence, exports, and dispatch closure |
| [Operations](docs/operations.md) / [OOB routing](docs/oob-routing.md) | Runtime sizing, backups, and callback infrastructure |

The CLI lives in `src/vigil_cli/`, the methodology and assessment helpers in `agent/`, and the
backend, UI, and report renderer in `orchestrator/`. [CODE-MAP.md](CODE-MAP.md) identifies
contract owners and subsystem boundaries.

To contribute, start with [CONTRIBUTING.md](CONTRIBUTING.md), the
[maintainer recipes](docs/maintainer-guide.md), and the
[verification matrix](AGENTS.md#tests--verification). The UI has received less attention than
the agents and backend; contributions there are welcome. Use `vigil doctor` and `vigil status`
to inspect a running installation. Report vulnerabilities privately through
[SECURITY.md](SECURITY.md).
