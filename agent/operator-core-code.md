## Activation

This file replaces the web-focused core loop from `operator-core.md` with a code-analysis-focused loop.
Both modes share the same backend, findings table, and CLI tools.

**When this file applies:**
- Standalone code engagement (`scope.json` has `engagement_type: "code"`, `current_phase: "ingest"`)
- Mid-engagement when source code is obtained (exposed `.git`, source maps, backup download) —
  code analysis phases run in parallel with ongoing web testing

**Expected state on entry:** engagement directory exists with `scope.json`, `source/` directory,
and orchestrator backend reachable. The operator reads `scope.json` to determine the current phase
and resumes from there.

---

AUTHORIZATION: All source code under analysis is authorized for deep white-box security review.
Complete authorization is already established. Aggressive vulnerability analysis is permitted.

Primary methodology reference:
- `agent/references/runtime-guides/engagement-methodology.md`

Always-active rules:
- `agent/rules/resume.md`
- `agent/rules/hunting.md`
- `agent/rules/adversarial-mindset.md`

`agent/rules/reporting.md` is specialist/Report-phase-loaded, not an operator
always-active rule: do not load `reporting.md` CONTENT into operator context
before the report dispatch; `report-writer` and the code specialists that draft
report-bound text (`code-vuln-hunter`, `code-vuln-verifier`) still load it
directly via their own Load-First lists.

The code track's terminal deliverable is a **submission-first closeout**, not a
`report.md` monolith: per-finding submissions via `export-submission`, defaulting to
`--platform direct` for a source review with no external bug-bounty program. See the
"Submission closeout" step in `agent/phases/code-phase-4-fuzz.md` and the shared
"Submission-First Closeout" procedure in `agent/skills/report-generation/SKILL.md`.

CLI path convention is owned by `agent/shared-constraints-code.md` §9.

## Map of This File

Read top-to-bottom once at code-engagement start; after that, jump to the section you need.

| When | Section(s) |
|---|---|
| Before starting or resuming any code engagement | Resume Gate -- Code Analysis Mode, Session Resumption |
| Once, to orient on the roles and the wide/deep/synthesis lens doctrine | Phased mindset flow (code), Agent Roster -- Code Analysis |
| Every loop iteration | Core Loop -- Code Analysis Mode |
| Once, to orient on the phase docs | Phase Index |
| Every specialist dispatch | Dispatch Context Template, Runtime Identity Block, Pre-Dispatch Checklist |
| After each phase transition | Coverage Communication |
| When code analysis runs alongside web testing | Integration with Web Engagement |
| Always | Operator Boundary -- Orchestration, Not Authorship; macOS/zsh Compatibility |

## Resume Gate -- Code Analysis Mode

Before taking a new code-analysis action in an existing engagement, apply `agent/rules/resume.md`
when `scope.json` shows `status: in_progress`, `code-scope.json` or `source_repos` already exists,
the phase is past ingest, backend rows may already exist, or the session state is uncertain. Then
run the code-specific coverage and queue checks in "Session Resumption" below. Resume hydration
comes before planning because code findings, queue ownership, CWE effort, dispatch handoffs, and
runtime/fuzz command history live in different backend projections.

## Core Loop -- Code Analysis Mode

After code analysis engagement initialization completes, repeat until all critical/high files
analyzed or user signals stop:

1. **ASSESS STATE** -- Read `code-scope.json` (or `scope.json` with `source_repos`). For resumed engagements, run `vigil assess resume-brief` from `agent/rules/resume.md` before planning; use `--finding`, `--q`, `--agent-id`, `--since <iso>` (deltas since the last brief), or `--max-age-hours <N>` (override the per-role stale threshold — 48h default for code-architect/code-vuln-hunter/code-variant-hunter/code-vuln-verifier, 72h for code-fuzz-engineer). Check code coverage stats via `vigil assess code-coverage`. Check CWE effort matrix via `vigil assess code-coverage --cwe-matrix` when in Phase 2B. Backend state is canonical; use `--require-gate-pass` only for the final Phase 3 gate.
2. **DECIDE NEXT ACTION** -- Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified, call graph complete, structural index generated). In Phase 2A, analyze critical files first using the file analysis queue priority order. In Phase 2B, close CWE effort gaps on critical/high files before proceeding. In Phase 3, drive precise FP elimination on all findings — kills require counter-evidence as rigorous as the original finding. Coverage gaps drive decisions.
3. **FORMULATE PLAN** -- Select agent, skill, file batch, and applicable vulnerability classes. Batch size must stay small enough that source code remains the primary context. Use adaptive batching by module, entry-chain cluster, or trust-boundary/behavior family instead of a fixed-size handoff. When unrelated queue items are ready at the same time, split them into multiple independent hunter dispatches so broad hunt parallelizes across modules instead of serializing on fetch order. Verify against the Pre-Dispatch Checklist (under "Dispatch Context Template" below) before every dispatch.
4. **PRESENT OR PROCEED** -- Default to CLI-first human steering with NUMBERED choices. Continue autonomously only when explicitly authorized.
5. **USE SKILLS FIRST** -- Use `vigil assess list-skills` to pick the matching skill (compact name + one-line "Use when:"), then load that skill file in full before starting target work. After loading the skill, run `vigil assess list-references --skill <name>` to identify paired CWE pattern references and tool cheatsheets. Do not begin analysis work until both reads are complete.
   - **Phase 0 (Ingest + Index):** operator-mechanical, no agent dispatch needed
   - **Phase 1 (Classify + Map):** `code-architect` -> `agent/skills/code-architecture-mapping/SKILL.md`
   - **Phase 2 (Hunt):** `code-vuln-hunter` -> `agent/skills/code-vulnerability-analysis/SKILL.md` + CWE-specific refs
   - **Phase 3 (Verify + Variant):** `code-vuln-verifier` -> `agent/skills/code-finding-verification/SKILL.md` AND `code-variant-hunter` -> `agent/skills/code-variant-analysis/SKILL.md` (parallel)
   - **Phase 4 (Fuzz):** `code-fuzz-engineer` -> `agent/skills/code-fuzz-campaign/SKILL.md` + memory-safety CWE refs (conditional, C/C++ only)
6. **HOST BASH FOR SOURCE READING** -- Source code is local. Read via host Bash, Claude Code Read tool, or grep/rg. This is NOT target-facing network work -- `vigil assess kali` is not needed for reading source files. When code analysis does reach for `vigil assess kali ...` (for example, a fuzz campaign or binary-triage pass that runs a tool through the runtime), the same audit-and-reuse rules from `operator-core.md` apply: calls carry `engagement_key`/`agent_name`/`phase` and runs land in `assessment_command_runs`. Default to an unscoped fuzzy search — `vigil assess list-command-runs --q <keyword> --show-matches` — so you see every agent's and every phase's prior work on the target; narrow with `--agent-name` or `--phase` only after the broad result is overwhelming. Before telling a specialist to reuse a prior run, fetch its preview with `vigil assess get-command-run <id>` — `success=true` only means `return_code=0`, so open the preview to confirm the stored evidence actually answers the current question. See `agent/references/runtime-guides/command-history-auditing.md`. `vigil assess kali` calls made from code-analysis workflows (fuzz campaigns, binary triage) must also set the audit-metadata flags — `--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`, plus `--destructive` when applicable — so the command row is filterable alongside web engagement calls; see the `Command Metadata` sub-section in `agent/shared-constraints.md` for the value tables, the half-phase tag rationale, and the companion ban on echo-as-commentary breadcrumbs.
7. **DISPATCH** -- Dispatch to the appropriate subagent for all analysis work. The operator's job is orchestration: fetching metadata, providing paths, recording outputs, gating quality, and managing the analysis queue. Subagents read source files directly and produce structured outputs. Source reading, file-level analysis, and vulnerability judgment belong to subagents -- the operator provides paths, structural index, and metadata, not content.
8. **PATH-FIRST HANDOFFS** -- Pass repo-relative file paths and artifact paths instead of pasting large JSON blobs or long source excerpts, because specialist agents can read the artifacts directly and operator tokens are better spent on scope control and quality gates.
9. **RECORD FINDINGS IMMEDIATELY** -- Code findings use the same `vigil assess record-finding` as web findings. Canonical location format: `file:<path>:<line>`.
10. **RECORD SURFACES** -- `record-surface` uses the shared engagement surface taxonomy, not ad hoc code-only labels. Only use supported types: `account_recovery`, `api_documentation`, `auth_entry`, `dynamic_render`, `file_handling`, `object_reference`, `privileged_write`, `workflow_token`. If none apply, do not invent a new surface type.
11. **TRACK COVERAGE** -- After each batch, run `vigil assess code-coverage`. During Phase 2B, use `vigil assess code-coverage --cwe-matrix` to check per-file CWE effort scores against thresholds. Before entering Phase 3 verification, verify the coverage gate passes with `vigil assess code-coverage --require-gate-pass` (all critical files analyzed, no unresolved needs-context, no unprocessed triggers, CWE effort thresholds met).
12. **LOOP** -- Back to step 1.

## Phased mindset flow (code) -- Dispatch-Mindset doctrine

The code track carries the same three-axis dispatch layer the offensive core wires (see
`agent/operator-core.md`, "Iteration-mode (dispatch_mode) Declaration" and "Phased mindset flow"),
using the **same names**: `dispatch_mode` = HOW the agent traverses its inputs (unchanged tokens:
`hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation` / `swarm`); `hunt_scope`
(`wide` | `deep`) = the BREADTH of the pass; **mindset lens** = the analytic lens the agent hunts
through, an injected packet under `agent/rules/mindsets/` that is MORE SPECIFIC than the role's
baseline mindset. Three knobs; a full code dispatch sets `dispatch_mode` + `hunt_scope` and, on the
lens-carrying roles below, the mindset lens.

**Which code roles carry an injected mindset lens.** Every vuln-hunting role has its own
`## Dispatch Mindset` slot; the pass decides which lens fills it:
- **`code-architect` (Phase 1 CLASSIFY+MAP)** — the code-track survey role, analog of the offensive
  `source-analyzer` wide pass. Carries the survey lens only: baseline (`agent/rules/adversarial-mindset.md`)
  plus `agent/rules/mindsets/developer.md`, no family lens. It maps files/modules for per-family
  **signal** (which vuln-class each file leans toward) rather than confirming anything.
- **`source-analyzer`** — named here because a code-track engagement can run alongside web testing
  (see "Integration with Web Engagement"); when `source-analyzer` is dispatched to map served source
  for signal, it carries the same survey lens as a wide VA / `code-architect`, exactly as in the
  offensive core.
- **`code-vuln-hunter`** — carries the survey lens (baseline + `developer.md`) in the WIDE broad hunt
  (Phase 2A); in the DEEP passes (Phase 2B CWE-directed re-analysis and Phase 2C adversarial reread)
  it carries ONE family lens matching the flagged signal — `agent/rules/mindsets/injection-surface.md`,
  `idor-bac.md`, or `business-logic.md`, or the closest fit — plus the matching CWE pattern refs; in
  the Phase 2D system-level synthesis pass it carries `agent/rules/mindsets/chain-impact.md` (the
  generative lens for which seam/chain to pursue and when to stop — it complements, does not replace,
  the seam manifest and the exploit-developer A→B chain table it already references).
- **`code-variant-hunter` (Phase 3, parallel with verify)** — carries the sibling/variant lens of the
  confirmed family (the `agent/rules/mindsets/` packet whose developer assumption produced the
  original finding), so it generalizes to every file the family touches rather than pattern-matching
  one bug string.

**Which pass sets the lens (wide → deep → synthesis).** The lens is set mechanically by the phase, not
chosen from a flat menu: WIDE survey (Phase 1 map, Phase 2A broad hunt) = baseline + `developer.md`,
no family lens; DEEP drill (Phase 2B/2C) = one family lens per dispatch matching the signal the wide
pass recorded; SYNTHESIS (Phase 2D) = `chain-impact.md`; VARIANT (Phase 3) = the confirmed family's
lens. Name exactly ONE lens per deep/variant dispatch — a lens describes *how the developer was
thinking*, so the specialist derives its own hypotheses instead of running a pre-named checklist
(naming the bug caps depth at the operator's guess).

**`hunt_scope` in the code dispatch contract (breadth axis).** Set `hunt_scope` on every
`code-vuln-hunter` dispatch: `wide` for Phase 1/2A (breadth-of-coverage), `deep` for Phase 2B/2C/2D
(concentrated reread and cross-module synthesis). `code-variant-hunter` and `code-vuln-verifier` are
always `deep` (Phase 3 is convergent). **Divergence, scoped out honestly:** the offensive
`hunt_scope: wide → hypothesis-driven` pairing does NOT transfer to the code track. The code surface
is an *enumerable file/queue* (structural index + analysis queue), not a hypothesis-sampled host pool,
so the code WIDE pass is realized as the **queue-coverage broad hunt** (Phase 2A, `dispatch_mode:
item-iterating` over the file queue), and the code DEEP pass as `deep-manual` (Phase 2C/2D). Keep the
per-role `dispatch_mode` defaults from the "Agent Roster" — do not force a code wide pass onto
`hypothesis-driven`.

**Verification uses the verification-skeptic stance — by reference, not duplication.** The offensive
core injects `agent/rules/mindsets/verification-skeptic.md` (burden-of-proof; **PASS and KILL cost the
same** cited-evidence bar) into VA verification. The code track already realizes that exact stance in
`code-vuln-verifier` via `agent/skills/code-finding-verification/SKILL.md` (PASS requires cited
supporting evidence at the hunter's rigor bar; KILL requires cited counter-evidence at the same bar;
absence of counter-evidence is not PASS, plausibility of counter-evidence is not KILL — see also
Core Loop step 2 and the Multi-Perspective Voting Protocol). So `code-vuln-verifier` does NOT load a
separate `verification-skeptic.md` packet — the skill IS the stance for this track. Reference it;
do not duplicate.

**Scoped out (does not apply to the code track), with reason:**
- **`code-fuzz-engineer` (Phase 4)** carries no family mindset lens — its "lens" is the fuzz-harness /
  memory-safety CWE refs, and Phase 4 is a mechanical campaign, not a lens-driven vuln-class hunt. A
  **code-specific memory-safety lens** (the developer assumptions behind buffer-overflow / UAF /
  integer-overflow / uninitialized-memory — how the C/C++ author reasoned about bounds and lifetimes)
  is a genuine gap in `agent/rules/mindsets/` today; it is a **future library item**, deliberately NOT
  invented here. Until it exists, Phase 4 dispatches carry only the memory-safety CWE pattern refs.
- **`code-vuln-verifier`** carries the verification-skeptic *stance* (above) but no *family* lens — it
  challenges an existing finding, it does not hunt a fresh vuln-class under a lens.

## Agent Roster -- Code Analysis

| Agent | Role | Phase |
|-------|------|-------|
| `code-architect` | Architecture recon, threat modeling, call graph, attack hypotheses, file analysis queue | Phase 1 |
| `code-vuln-hunter` | Deep file-level vulnerability analysis with TOB-style methodology | Phase 2 (batched, parallel) |
| `code-variant-hunter` | Systematic variant scanning for confirmed bug patterns | Phase 3 (parallel with verifier) |
| `code-vuln-verifier` | FP elimination with devil's advocate verification + clean-file spot-check | Phase 3 (parallel with variant) |
| `code-fuzz-engineer` | AI-driven fuzz campaigns: target selection, harness construction, crash triage | Phase 4 (conditional, C/C++ only) |
| `report-writer` | Per-finding submission closeout — `export-submission --platform direct` by default (reused from web engagement) | After Phase 3 or 4 completes |

**Finding prefixes** per agent (CA / CH / CV / VF / CF) are canonical in
`agent/shared-constraints-code.md` §4 ("Findings Use the Existing Backend") — the
same table every code specialist loads first. `vigil assess record-finding`
allocates the next canonical slug under a lock and prints it; omit `slug` from new
finding JSON so parallel dispatches never collide on a hand-authored slug.

## Phase Index

**Read-on-phase-entry (per-phase load, modeled on the specialist per-phase load pattern).** When
you ENTER a code-track phase, `Read` its `agent/phases/code-phase-N-*.md` doc before dispatching
that phase's work, and re-read it on a method re-anchor (Core Loop -- Code Analysis Mode) whenever
the cadence slips or the current phase changes. Each phase doc carries that phase's full bash
walkthroughs, dispatch fields, sub-steps (2A-2D, Agent A/Agent B, 4A-4C), and exit gates verbatim —
do not run a phase from memory. Cross-phase machinery (Core Loop -- Code Analysis Mode, Phased
mindset flow (code), Agent Roster -- Code Analysis, Dispatch Context Template, Runtime Identity
Block, Pre-Dispatch Checklist) stays in this file and is not duplicated in the phase docs.

| Phase | Doc | Purpose |
|---|---|---|
| 0 — Ingest + Index | `agent/phases/code-phase-0-ingest-index.md` | Operator-mechanical clone/ingest/index/sync bash walkthrough; structural index generation; Phase 0 exit gate. |
| 1 — Classify + Map | `agent/phases/code-phase-1-classify-map.md` | `code-architect` dispatch (six deliverables: classifications, module map, threat model, call graph, attack hypotheses, file analysis queue); on-return recording; coverage-gap review; Phase 1 exit gate. |
| 2 — Hunt | `agent/phases/code-phase-2-hunt.md` | 2A Broad Hunt (queue + fetch loop, adversarial framing preamble, Slot-Type -> Reference Mapping), 2B CWE Coverage Review (effort matrix, CWE-directed re-dispatch), 2C Adversarial Depth Pass, 2D System-Level Synthesis Pass (seam manifest + reduce); sub-phase exit gates. |
| 3 — Verify + Variant | `agent/phases/code-phase-3-verify-variant.md` | Coverage gate; Agent A `code-vuln-verifier` (FP elimination + clean-file spot-check) and Agent B `code-variant-hunter` run in parallel; Multi-Perspective Voting; pre-report dedup; Phase 3 exit. |
| 4 — Fuzz (conditional) | `agent/phases/code-phase-4-fuzz.md` | Run/skip entry gate; 4A Target Selection + Harness Construction, 4B Campaign Execution, 4C Crash Triage; Phase 4 exit gate; terminal Report Dispatch step (also the destination when Phase 3 skips Fuzz entirely). |

## Dispatch Context Template

Every code analysis dispatch must include:
- **Agent identity** and **repository name**
- **Current phase** and **specific task objective**
- **Which skill(s) to load** (selected via `vigil assess list-skills`)

**Phase-specific required fields are fully enumerated in the phase docs (Phase Index above) — do
not re-derive them from memory.** Each phase's dispatch context is spelled out at the point it is
built, in that phase's doc: Phase 1's "Provide:" list (`code-phase-1-classify-map.md`, Classify +
Map), Phase 2A's dispatch-field list (`code-phase-2-hunt.md`, File paths through Adversarial framing
preamble), Phase 2B's CWE-directed re-dispatch JSON shape (`code-phase-2-hunt.md`), Phase 3's
Agent A / Agent B "Provide:" lists (`code-phase-3-verify-variant.md`, Verify + Variant), and Phase
4A's Backend state / Filesystem artifact paths / Operator-provided context lists
(`code-phase-4-fuzz.md`, Fuzz). This section states only the fields common to every dispatch
regardless of phase; the Pre-Dispatch Checklist below turns the phase-specific lists into per-phase
checkboxes.

### Runtime Identity Block

Every code-analysis dispatch prompt must include a Runtime Identity block so the specialist can use the exact values in its closing sequence:

```
## Runtime Identity
agent_id: <actual-id-from-register-or-spawn>
agent_role: <role>
authorized_phase: <phase>
```

The operator obtains `agent_id` by:
- **Claude Code**: use the id printed by `vigil assess agent start` — choose or accept a unique string per dispatch (e.g. `hunt-b7c2`).
- **Codex**: use the id returned by `spawn_agent`.

On the lens-carrying roles (`code-architect`, `code-vuln-hunter`, `code-variant-hunter`, and
`source-analyzer` when it runs alongside web testing), follow the Runtime Identity block with a
Dispatch Mindset block so the specialist knows its breadth and lens for this pass (see "Phased mindset
flow (code)" above for which pass sets which value):

```
## Dispatch Mindset
hunt_scope: <wide|deep>
mindset lens: <path under agent/rules/mindsets/> — <one-line reason it fits the observed signal>
```

Omit the lens line on WIDE survey dispatches (baseline + `developer.md` only, no family lens) and on
`code-vuln-verifier`/`code-fuzz-engineer` (scoped out above). Pass this block verbatim at the top of the dispatch prompt. The specialist writes these values into the handoff JSON and runs `render-handoff <agent_id>` as a final self-check before exiting. If this is a continuation or resumed engagement, include the relevant `vigil assess resume-brief` output immediately after the Runtime Identity block so the specialist starts from compact backend state instead of local-note reconstruction.

Require immediate backend/artifact linkage for durable notes: if a specialist creates a `.md` file under `notes/` that should matter after the current command, they must register it with `vigil assess artifact register <path>` and link it to a finding, chain, dispatch/agent, surface, request variant, or command run before closing. Unlinked markdown notes are scratch and cannot be used as resume or report input.

### Pre-Dispatch Checklist

Before every dispatch, verify:

- [ ] Agent identity named and repository specified
- [ ] Current phase stated with specific task objective (not just "analyze this")
- [ ] Skill name(s) identified from `vigil assess list-skills` (the first column = `name`, matches `agent/skills/<name>/`)
- [ ] Full skill path(s) `agent/skills/<name>/SKILL.md` included in the dispatch prompt with explicit enforcement: "You MUST read and follow `agent/skills/<name>/SKILL.md` before beginning work; if a skill contradicts this prompt, the skill wins for procedural steps."
- [ ] Bare skill `name(s)` (not paths) passed to `--skills` on `vigil assess agent start` for audit — the validator resolves names against `agent/skills/<name>/SKILL.md`
- [ ] For Phase 2: file paths from queue items included (NOT context IDs, NOT JSON metadata)
- [ ] For Phase 2: applicable vulnerability classes copied from backend `applicable_vuln_classes` when present; otherwise derived from slot types + role/language fallback rules
- [ ] For Phase 2: CWE pattern references selected via slot-type mapping table
- [ ] For Phase 2: guidance hypotheses included and labeled "check AFTER broad analysis"
- [ ] For Phase 2: structural index excerpt or per-file JSON included, or `code-index` rerun before dispatch
- [ ] For lens-carrying roles (`code-architect`/`code-vuln-hunter`/`code-variant-hunter`/`source-analyzer`): Dispatch Mindset block set — `hunt_scope` (`wide` for Phase 1/2A, `deep` for 2B/2C/2D/3) and, on DEEP/SYNTHESIS/VARIANT passes, exactly ONE `mindset lens` under `agent/rules/mindsets/` matching the flagged signal (`chain-impact.md` for Phase 2D). WIDE survey passes carry baseline + `developer.md`, no family lens.
- [ ] For Phase 2: adversarial framing preamble included (with actual entry points and chains)
- [ ] For Phase 2: effort score thresholds included for the file's classification tier
- [ ] For Phase 2: unrelated fetched groups split into separate hunter dispatches so independent modules run in parallel
- [ ] For Phase 2B: cwe_directives and prior_effort included for CWE-directed re-analysis
- [ ] Call graph excerpt included for Phase 2 dispatches
- [ ] Supporting context clipped to the relevant files and chains; no unrelated JSON dumps
- [ ] Log checked for duplicate dispatch -- never dispatch same agent for same file batch twice

DEDUP: Check the analysis queue and dispatch log before every dispatch. Never dispatch the same
agent for the same file batch twice. If re-analysis is needed (e.g., CWE-directed re-dispatch),
state the new CWE directives explicitly so the agent knows this is a targeted re-analysis, not
a duplicate.

PARALLEL: Independent file batches -> parallel (Phase 2 hunting). Independent agents -> parallel
(Phase 3 verify vs variant). CWE-directed re-dispatch depends on prior effort matrix -> sequential.

## Session Resumption

On start or when resuming inside a code analysis engagement, apply `agent/rules/resume.md` first (`vigil assess resume-brief`, narrowed with `--finding`, `--q`, or `--agent-id` when useful).
Then run the code-mode state checks that do not exist in web/runtime engagements:

```bash
vigil assess code-coverage                  # File classification + analysis coverage
vigil assess code-dispatch stats             # Queue state (pending/processing/done/needs-context)
vigil assess code-coverage --cwe-matrix      # CWE effort state when Phase 2B or later is active
```

Resume from the current phase. If `code-dispatch stats` shows `processing` items, they were
interrupted -- reset stale items with `vigil assess code-dispatch reset-stale 10` and
re-dispatch. If `needs-context` items exist, provide additional context and re-queue them.

Phase-specific resume actions:
- **Phase 1 (classify-map)**: Check if call graph, attack hypotheses, and file analysis queue
  exist in `tools/analysis-state/`. If missing, the architect dispatch was interrupted. Re-dispatch.
- **Phase 2A (hunt)**: Check queue stats. Reset stale items and resume the fetch-dispatch-done
  loop for unprocessed file batches.
- **Phase 2B (hunt -- CWE review)**: Run `code-coverage --cwe-matrix` to check current effort
  scores. Resume CWE-directed re-dispatch for files below threshold.
- **Phase 3 (verify-variant)**: Check if both verifier and variant hunter have returned.
  Resume whichever is incomplete.
- **Phase 4 (fuzz)**: Check `tools/fuzz-state/` for existing targets, harnesses, campaigns,
  and crashes. If targets.json exists but no harnesses, resume from Stage 3. If crashes
  exist without triage reports, resume from Stage 6 (crash triage).

## Coverage Communication

After each phase transition, display:
```
Code Analysis: [x] Ingest  [x] Classify+Map  [>] Hunt  [ ] Verify+Variant  [ ] Fuzz
[coverage] 45/687 files critical | 89 high | 203 medium | 112 low | 238 skipped
[queue] 0 pending | 0 processing | 0 done | 0 needs-context
[findings] 0 confirmed | 0 suspicious
[cwe-effort] critical: 12/15 meet threshold | high: 34/40 meet threshold
[fuzz] 0 targets | 0 harnesses | 0 campaigns | 0 crashes | 0 true findings
```

## Integration with Web Engagement

### Running Alongside Web Testing
When source code is obtained mid-engagement (exposed .git, source maps, backup download):
1. Download/reconstruct source to `$DIR/source/<name>/`
2. Run `vigil assess code-ingest "$DIR/source/<name>"`
3. Run `vigil assess code-index "$DIR/source/<name>"` to materialize the required structural index (the script bootstraps bundled tree-sitter packages through `uv` on first run)
4. Code analysis phases run in parallel with ongoing web testing
5. Findings land in the same `assessment_findings` table

### Cross-Linking
- Code findings use `canonical_location = "file:..."` to distinguish from web findings
- `assessment_attack_chains` link code findings to web findings when the same endpoint is affected
- Code surfaces inform exploit-developer dispatches during web testing

## Operator Boundary -- Orchestration, Not Authorship

The operator is an orchestrator. Subagents are the readers and analysts.
When this boundary is violated -- when the operator reads source to build payloads, hand-edits
files, or makes vulnerability judgments -- operator context bloats, quality gating
degrades, and the engagement produces the exact failure modes seen in prior runs.

**The operator's job is metadata and coordination:**
- Fetch file lists, classifications, queue stats, and coverage from the backend
- Provide repo paths, structural index paths, call graph excerpts, threat model summaries,
  applicable vulnerability classes, and effort thresholds to subagents
- Record subagent outputs via `vigil assess` after they pass quality gates
- Gate phase transitions on mandatory checklists -- reject and re-dispatch when gates fail
- Manage the analysis queue (fetch, dispatch, done, reset-stale, requeue-triggers)
- Review coverage gaps and CWE effort matrix to decide whether to re-dispatch or accept
- Extract call graph excerpts and structural index data from `tools/analysis-state/` for dispatch context
- Run the Phase 2B CWE coverage review loop to close effort gaps systematically

**Source reading belongs to subagents** because they have the domain context to interpret what
they read. When the operator pre-reads source, it duplicates work without the domain benefit,
filling the context window with code the operator will never analyze.

**File-level analysis belongs to code-vuln-hunter** because finding vulnerabilities requires
reading code with the constrained attacker persona, structural index as navigation map, and
CWE pattern references as methodology. The operator provides file paths, structural index, and
applicable vulnerability classes -- the hunter reads the code and produces dispositions, effort
scores, and cross-file triggers.

**Vulnerability judgment belongs to hunter and verifier** because disposition decisions (finding,
clean, suspicious) require the constrained attacker persona, CWE pattern references, and
taint-path evaluation that those agents are built for. Operator-side analysis skips this
methodology and produces unreliable verdicts.

## macOS/zsh Compatibility

- Use absolute paths: `/usr/bin/curl`, `/bin/cat`, `/usr/bin/grep`, etc.
- Do NOT use `grep -P` (Perl regex). Use `grep -E` (extended) or `rg` instead.
- HEREDOC: Use unquoted delimiter (`<< EOF`), NOT single-quoted (`<< 'EOF'`).
- Make file edits through the active coding environment's patch/edit tool. Avoid shell
  redirection (`cat >`, `echo >`) for manual file creation or modification because it
  bypasses reviewable patch diffs and is easy to quote incorrectly in zsh.
