<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo/vigil-lockup-dark.svg">
  <img alt="Vigil" src="docs/assets/logo/vigil-lockup-light.svg" width="280">
</picture>

**An AI harness for long-running code audits, web pentests, and bug bounty hunting.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/VigilOSS/Vigil/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.2.5-green.svg)](https://github.com/VigilOSS/Vigil/releases/tag/v1.2.5)

</div>

Vigil runs authorized, long-form offensive security engagements: white-box code audits, web
application pentests, bug bounty hunting, or code and web analysis against the same target.
A lightweight operator coordinates specialist agents and a Kali runtime. Tool executions,
probes, findings, evidence, and coverage are recorded in the backend so the investigation can
survive context compaction, restarts, and multiple sessions.

Vigil was built by an application security engineer and refined over eight months and hundreds
of hours of hands-on use. Much of that work went into the operator instructions, specialist
prompts, skills, and the small decisions that shape an investigation: which assumptions to
challenge, what counts as a real negative, when to dig deeper, and what evidence is needed
before making a claim.

> **Authorized use only.** Vigil autonomously drives offensive tooling against live systems.
> Use it only with explicit authorization and a reviewed scope. It is provided without warranty
> under the [Apache License 2.0](LICENSE); you are responsible for commands, credentials,
> infrastructure, and target effects. See [SECURITY.md](SECURITY.md) for private vulnerability
> reporting and the operator-data boundary.

## How Vigil hunts

### Prompts built around security-research failure modes

The operator, specialist roles, and skills encode specific decisions about how investigations fail:
jumping to a familiar bug class, stopping after an ambiguous response, repeatedly running a probe
that teaches nothing, trusting an incomplete tool result, or writing up impact that was never
demonstrated.

The operator plans and tracks the work. Specialists do the analysis and choose techniques. They
load detailed skills and references as the corresponding signal appears, rather than stuffing
every playbook into every agent's context. Long-running sessions periodically re-anchor on their
methodology to counter drift toward shallow, checklist-style testing.

### Investigate the assumptions behind the implementation

Alongside "which vulnerability class applies?", the first question is "what did the developer
assume was safe?" Vigil's developer lens looks for copied endpoints missing a guard, old API
versions that retained weaker controls, reliance on framework defaults, trusted client-side
validation, and differences in naming or error responses that suggest different implementations.
These are leads for the specialist to evaluate.

Vigil gives specialists a surface, an objective, scope constraints, and relevant context. It never
names the bug to find, because a pre-named bug caps the hunt at the operator's guess. A broad pass
generates hypotheses from the actual code or observed behavior; subsequent passes use focused
lenses for access control, injection, business logic, and chain impact. A clean result under one
lens doesn't preclude a fresh investigation under another.

For code audits, hunters evaluate the applicable vulnerability classes before checking the
architect's suggested attack hypotheses. Higher-risk files get an additional, less-anchored
reread. Structured coverage provides a minimum standard without telling the agent what it
*must* discover.

### Don't mistake an inconclusive test for a negative result

A transport failure, WAF challenge, empty tool output, or validation error can say more about
the test than the target. Vigil distinguishes these cases from evidence that a security control
actually held. Before recording a negative, agents prove a positive on the same route, identity,
and gateway in the same window, so the test is known to have reached the intended behavior.

Negative findings retain the context in which they were established. A route denied to one
identity may need retesting with another; a surface examined under one lens is not automatically
closed under all the others. Prior conclusions guide the next pass but do not substitute for
rechecking the evidence when conditions change.

### Go deep where a quick pass would miss an application

One URL may represent a substantial authenticated application. Vigil tracks distinct application
units instead of assuming that touching a host means testing every feature behind it. Its
operator deliberately concentrates deeper work on promising surfaces, varies investigative
lenses, and returns to breadth when those leads have been resolved.

When successive attempts produce the same response class without new information, the next step is
a different hypothesis or technique. Surfaces closed after shallow testing are revisited before an
engagement is declared ready. A conclusion such as "these subdomains are all the same application"
must be supported by the hosts it would otherwise remove from consideration.

### Keep evidence, findings, and investigative history connected

Vigil records tool executions, probes, coverage, findings, agent decisions, and handoffs in a
durable backend. The operator can retrieve a compact view of the current engagement instead of
asking each new agent to reconstruct it from a long conversation. Existing findings can inform
variant hunts, root-cause grouping, and attack-chain analysis without becoming a fixed list of
bugs the next specialist is allowed to find.

A finding has to stand on its evidence. Verification is performed by a different dispatch using
attributable proof. Reproduction steps point back to recorded runs, and a fresh agent follows them
with no author context before the report is drafted. The report writer cannot invent a missing
reproduction sequence from the hunt's summary. Medium-or-higher submissions receive a blind review
of the exact external report and attachments; edits that change that reviewed packet require a new
review.

Report-writing rules favor demonstrated impact, short reproducible steps, and facts stated once.
Internal instrumentation, speculation, and repetitive AI-generated narration stay out of the
submission.

### What coverage means

Coverage records investigation work. It does not measure how many vulnerabilities were found,
and Vigil cannot guarantee that every bug in a codebase or application was discovered.

- **Code:** A sealed source snapshot and structural index define what was admitted for analysis.
  The ledger tracks file/function review, applicable vulnerability-class effort, recorded outcomes,
  and unresolved structural or context gaps. Reference-only files are available for tracing but
  are not counted as reviewed unless admitted to the analysis queue.
- **Web:** Host, application-unit, input, identity, and probe records distinguish observed testing
  from untested or inconclusive work. A completed dispatch is not proof that a whole host or
  application was exhausted. Decisive or high-confidence app units can carry class-specific
  depth requirements at report time; gaps require more testing or an explicit, recorded deferral.
- **Readiness:** Phase gates evaluate the recorded work and known blockers. Passing them establishes
  the required accounting and dispositions.

## Real results

One engagement against [Fluent Bit](https://github.com/fluent/fluent-bit) (CNCF), scoped to a
single file: `plugins/out_es/es.c`.

| | |
|---|---|
| Operator time | **2 h 59 m**, one session, start to finished advisory |
| Scope | 9 files / 2,572 LOC, plus a 495-file core tree indexed for context, not analysis |
| Coverage | 9 of 9 scoped files analysed |
| Findings | 3, all reproduced at runtime against a live Elasticsearch 8.15.0: one critical, two medium |

https://github.com/user-attachments/assets/19cdd31a-eb6f-43cc-8f1d-2675eeebac91

> **Heavily trimmed down from a three-hour session.** Ten moments from the operator thread, one
> hunter agent's own transcript, and the finished disclosure. Across the full run, the operator
> handed 17 tasks to five specialist agents, which made 945 tool calls over 7.2 hours of agent time.

The engagement is named `historical-replay` because the source was pinned to a revision from
before the upstream fix. One finding is redacted because it is still unfixed upstream.

`out_es` pastes a record-derived index name into Bulk API syntax. A log producer who controls
that field can add an extra action line of its own choosing, posted under Fluent Bit's own
Elasticsearch credential. Against a cluster with security enabled and a collector role
restricted to `fluent-bit*`, one such record deleted another producer's document, and Fluent
Bit recorded no error. `out_opensearch` carries the same code.

Upstream fixed this in 4.2.6. It carries no CVE, no GHSA, no published advisory. Vigil found it
independently: source was pinned to a revision from before that fix, repository lookups and
cloning were off limits, and CVE, advisory, and changelog checks were withheld until the
write-up was done.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/fluent-bit-findings-dark.png">
  <img alt="The engagement's three recorded findings. Two are shown in full; the third is withheld pending vendor disclosure because it is still unfixed upstream." src="docs/assets/fluent-bit-findings-light.png">
</picture>

The third finding is withheld here: it is still unfixed upstream, so it stays with the
maintainers until a fix ships or the disclosure window closes.

### Verification

A separate verifier dispatch tried to kill the critical and couldn't: five attempts failed, two
of them disproven by runtime capture rather than argument. Severity moved from 9.1 to 7.1 on
scope reasoning, then back to 9.1 once an authenticated re-test measured the actual availability
loss. A third agent, given only the draft advisory and no engagement context, found six real
errors in it — a line number cited wrong three times, a patch that would have hung the process
— and all six were fixed before anything shipped.

### Provenance

Every command the run executed against the lab went through an audited surface that logs the
command, its purpose, target, exit status, and output. Each claim in the advisory traces to one of
those records, a runtime transcript, or a verifier script.

## What ships

- **Test identities.** Log in through the MITM proxy and each account becomes a named identity.
  Kali tools replay a request as an identity with `--identity` for cross-account testing such as
  IDOR and BOLA.
- **Callbacks tied to probes.** Blind payloads use nonce-tagged URLs and `vigil oob poll`
  correlates observed callbacks with their originating probes and source information.
- **A browser for what curl misses.** Client-rendered routes and challenge pages can be examined
  in an audited headless Chromium alongside plain HTTP observations.
- **Resumable recon.** Subdomain discovery, liveness checks, crawling, JS mining, and archived
  URLs form a checkpointed, scope-filtered reconnaissance pipeline.
- **A file-level ledger for code.** Source is sealed in a content-addressed snapshot with a
  tree-sitter index and attributable review records.
- **Signal-triggered methodology.** Specialist roles use a library of skills and references when
  the relevant behavior appears; see [`agent/`](agent/).
- **Program-ready exports.** Bugcrowd, HackerOne, and direct-disclosure drafts are rendered from
  recorded findings and published as versioned, hash-verified packages. Vigil does not submit
  them to a third-party platform on your behalf.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/findings-dark.png">
  <img alt="Vigil orchestrator UI: an engagement's findings grouped by severity, workflow, and verification" src="docs/assets/findings-light.png">
</picture>

> [!NOTE]
> The orchestrator UI has had far less attention than the agents and backend. It shows
> engagement state, findings, and coverage, but it is rough in places. If you'd like to take it
> on, see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue.

## Quick start

```bash
# 1. Install the application release (CLI, backend, prompts, docs, and prebuilt UI)
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v1.2.5/vigil-1.2.5-py3-none-any.whl vigil
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
Always start through `vigil engagement start`, which runs the preflight and exports the
engagement environment. Later sessions start the same way and then run `vigil-resume`. Upgrades
and workspace layout: [`docs/installation.md`](docs/installation.md); modes and preflight:
[`docs/engagements.md`](docs/engagements.md).

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

goose, opencode, and Kimi run with reduced support; see
[`docs/agent-clients.md`](docs/agent-clients.md).

Planned: broader support for **GLM 5.3** and other models with more predictable access, through
lower orchestration overhead, model-specific prompts, and deeper **OpenCode** integration.

## Effort and usage

**Vigil is designed for depth, not low-token scanning.** It spends model effort on repeated
investigation, cross-file reasoning, different hunting lenses, evidence collection, re-testing,
variant searches, and reports that can be reproduced. That can consume substantial tokens,
especially on large repositories or authenticated web applications. It does not mean every target
will take the same amount of time or tokens.

The operator keeps a relatively small working context and delegates most analysis to
specialists. Durable backend state and on-demand skill loading reduce wasted context, but they
are not substitutes for the actual investigation work. Usage caps and pricing depend on the
model/provider and change over time; plan for interruptions on large engagements.

| Engagement | Suggested starting reasoning effort |
|---|---|
| Code audit | Medium; increase for hardened or complex code |
| Web pentest / bug bounty | High or above, where your model access permits |

> [!TIP]
> **Bug bounties:** look for source maps. Download the `.map` files, recover the source with
> `vigil assess code-sourcemap-extract`, and run a code engagement on it. Then run
> `vigil engagement add-track <key> web` and `vigil engagement add-host <key> <host>` so web
> testing builds on its findings ([tracks](docs/engagements.md#tracks-and-modes)).

## How an engagement runs

| Track | Phases |
|---|---|
| **web** | `recon → collect → consume-test → verify → exploit → report` |
| **code** | `ingest → classify-map → hunt → verify-variant → fuzz` |

Every transition runs `vigil assess transition-phase`, which refuses while the phase still owes
work. `--force` records an audited override; a code audit can never be forced to `complete`.
Code findings go through the same per-finding submission flow as web.

Phase completion depends on readiness checks and recorded decisions, not a fixed engagement
duration; individual commands and dispatches still have timeouts. Web testing may require
multiple identities, class-specific probes, browser-assisted observations, and deliberate
rate-limiting across concurrent specialists. Code work expands as hunters follow call chains
and add related files for analysis. Verified findings can trigger sibling/variant checks and
attack-chain review. Exploit work waits for approval by default.

**Remediation** (work in progress) takes a finding or ticket to a reviewed fix. Each case gets
its own Git worktree or JJ workspace, records proof that the fix works, and needs your approval
before a draft PR. The repository's `PROJECT.md` configures ticket
readers, checks, and publishing. Start with `vigil remediation -k <key> start`, then
`/vigil-remediate SEC-123`. See [`docs/remediation.md`](docs/remediation.md).

Blue incident response also runs on the same backend; see
[`docs/blue-engagements.md`](docs/blue-engagements.md).

## Runtime

`vigil up` starts one long-lived Kali container named `vigil`. Target-facing commands run through
`vigil assess kali ...`; long scans run as `vigil assess kali job start ...` so they survive the
operator session. Mounts, maintenance commands, sizing, and backups:
[`docs/operations.md`](docs/operations.md).

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

## Optional capabilities

| Capability | Default | Start command | Purpose |
|------------|---------|---------------|---------|
| MITM proxy | off | `vigil mitmproxy start` | Authenticated capture into each engagement's backend credential store. |
| OOB (frp + interactsh) | off | `vigil oob start` | Out-of-band callback detection over shared frp/interactsh. |
| Universal ctags | host-installed | `brew install universal-ctags` | Richer code-analysis definition lookups. |

Route a browser through `http://127.0.0.1:8080` and log in to capture credentials; a second
login adds a second identity ([`docs/authentication.md`](docs/authentication.md)). Callbacks need
your own relay, configured before `vigil install`
([`docs/oob-routing.md`](docs/oob-routing.md)).

## Commands you run

The agents drive `vigil assess`. These are the commands you use yourself:

| Command | Use |
|---|---|
| `vigil up`, `vigil status`, `vigil doctor` | Start the local stack and check it |
| `vigil engagement create`, `vigil engagement start <key>` | Create an engagement and start a session |
| `vigil mitmproxy start`, `vigil auth status <key>` | Capture logins as test identities |
| `vigil oob start` | Start out-of-band callbacks |

Every command lists its flags under `--help`.

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

## Design decisions

The decisions behind the method are recorded in [`docs/adr/`](docs/adr/). The ones that shape
hunting most:

- [Coverage steers; it blocks only at report](docs/adr/0001-coverage-as-harness-not-gate.md),
  where untouched high-value applications need a test or a recorded reason. Gates read structured
  records, never an agent's own summary.
- [Depth is checked per vulnerability class](docs/adr/0012-coverage-grain-selective-load-bearing-depth.md)
  on decisive applications, so one probe can't mark a whole family covered.
- [A crashed scan and a clean scan look different](docs/adr/0015-honest-instruments-distinguish-no-measurement-from-clean.md).
  Missing output, truncated input, and transport failures are recorded as "no measurement".
- [Negatives are retryable](docs/adr/0016-target-knowledge-is-derived-and-negatives-are-retryable.md).
  A past "nothing here" guides the next check but can't suppress it.
- [A verifier can only confirm with its own evidence](docs/adr/0028-producer-provenance-binds-proof-to-work.md).
  Every proof is bound to the dispatch that produced it.
- [One lens per dispatch, rotated](docs/adr/0034-one-lens-per-dispatch-rotated-across-surfaces.md).
  A specialist gets one lens at a time, and a surface that came back clean under it is still open
  under the next. Only the hard rules of engagement constrain a dispatch.
- [Unproven findings stay on the books](docs/adr/0035-unproven-findings-are-parked-or-blocked-never-dropped.md).
  A finding is parked when it lacks runtime proof, graded at impact-if-true when only the
  program's rules block the last step, and held as blocked when it needs access nobody has
  provisioned. None is silently dropped or downgraded.

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
[test and verification matrix](AGENTS.md#tests--verification). To check a running install, use
`vigil doctor` and `vigil status`.
