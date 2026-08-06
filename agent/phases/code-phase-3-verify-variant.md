# Code Phase 3 — Verify + Variant

**Read-on-phase-entry.** When you ENTER Code Phase 3 (Verify + Variant), Read this doc before
dispatching the parallel `code-vuln-verifier` / `code-variant-hunter` pair, and re-read it on a
method re-anchor. It carries the coverage gate that must pass before Phase 3 starts, Agent A
(`code-vuln-verifier`) dispatch fields and the clean-file spot-check, Agent B (`code-variant-hunter`)
dispatch fields, the Multi-Perspective Voting protocol for conflicting dispositions, handling
spot-check findings, the on-return recording commands, pre-report deduplication (same-phase and
cross-phase), and the Phase 3 exit. Cross-phase machinery — the Core Loop, the Phased mindset flow
(code) (which scopes `code-vuln-verifier` to the verification-skeptic stance and `code-variant-hunter`
to the confirmed family's lens), the Agent Roster, and the Dispatch Context Template / Pre-Dispatch
Checklist — stays in `agent/operator-core-code.md`; this doc does not restate it.

### Phase 3: VERIFY + VARIANT

Phase 3 merges verification and variant scanning into a single parallel phase. Two agents run
simultaneously on independent objectives:

- **Agent A (code-vuln-verifier)**: TOB-style false positive elimination on all findings
- **Agent B (code-variant-hunter)**: systematic variant scanning for confirmed bug patterns

Both agents run in parallel because their work is independent: the verifier evaluates existing
findings, while the variant hunter scans for new instances of confirmed patterns.

**Hard transition readiness** -- must pass before proceeding:
```bash
vigil assess code-coverage --require-transition-ready verify-variant
# Must show current sealed source/index/threat identity, every admitted file accounted for,
# no needs-context, no pending work/triggers, and no structural uncovered-file blocker.
```

If readiness fails, resolve remaining items before proceeding:
- `needs-context` items: dispatch additional file batches to Phase 2 with targeted context
- Unaccounted admitted files: dispatch to Phase 2 (hunt), or record an evidence-based skip there
- Pending cross-file triggers: requeue and analyze the target files before verification
- Missing/stale source, structural index, or threat model: return to the owning Phase 0/1 step;
  identity blockers are not replaceable with a prose summary
- The readiness gate must pass before proceeding -- unresolved items become permanently invisible to
  the report

Review quality remains a separate advisory signal. Run `vigil assess code-coverage --cwe-matrix`
and route meaningful CWE-effort warnings through the Phase 2B re-dispatch loop;
`--require-gate-pass` is the optional strict exit-code form for that quality loop, not phase
authorization.

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md`.

Provide:
- All confirmed findings from Phase 2 (suspicious findings must be resolved by hunters
  before Phase 3 — see Phase 2 exit gate)
- The current Code Source Identity block, its matching structural-index manifest, and canonical
  file locations; verification reads the sealed snapshot and records/rebinds findings to that exact
  generation
- CWE pattern references matching each finding's defect family
- Build system configuration for compile-time flag evaluation (Makefiles, CMakeLists,
  configure scripts, feature flags)
- Complete current threat-model envelope from `vigil assess fetch
  "code/threat-model/<repo-id>"` (module product-surface profile, reachability basis, caller
  control, and trust boundaries for severity); require `current: true` and matching source
  identity. A clipped summary is supplemental only
- Instruction: run the FP & severity-downgrade gate (`agent/references/finding-fp-and-severity-gate.md`,
  C1–C7) on each finding, then author the report-ready story into `details`, before recording
  confirmed/downgraded

The verifier's job is precise FP elimination. False positives are expected in any
AI-assisted vulnerability pipeline, but so are wrongly killed real findings. A killed
finding is only a good outcome when the counter-evidence is as rigorous as the original
finding. When reviewing the verifier's kills, check whether each one cites specific code
evidence at the hunter's original rigor bar, or leans on circumstantial reasoning (a guard
"looks sufficient," a test "seems to cover it") -- the second pattern, not a raw kill count,
is the signal to re-open kills for a second look.

The verifier:
- Traces the full entry-to-sink path for each finding, reading source directly
- Evaluates whether guards actually prevent the claimed attack
- Checks compile-time flags that might disable the vulnerable path
- Applies `shared-constraints-code.md` §5 target-kind reachability: runtime entry for an
  application/service; supported public API sequence for a library/framework; shipped input for a
  CLI; registered host contract for a plugin/extension. Missing consumer context constrains
  attacker impact/severity rather than erasing a concrete supported-path defect
- Produces a disposition for each finding: confirmed, downgraded (with new severity),
  or killed (with detailed reasoning)

**Clean-file spot-check:** After processing all findings, the verifier samples 2-3 critical
files that have zero findings and no below-threshold cells in the current CWE matrix. The
verifier reads those files with CWE pattern references and checks whether the "clean"
assessment from Phase 2 holds. This catches systematic blind spots where the hunter's
analysis methodology consistently misses a pattern class. If the spot-check finds a missed
vulnerability, that file goes back to Phase 2B for re-analysis with the specific CWE
directive.

#### Agent B: Variant Scanning

Dispatch `code-variant-hunter` with `agent/skills/code-variant-analysis/SKILL.md`.

Before registering the dispatch, freeze the Phase 2 parent findings into one canonical sorted slug
list. Register that exact list on the dispatch and retain the numeric backend row ID printed by the
command:

```bash
vigil assess agent start --agent-id <agent-id> --role code-variant-hunter \
  --code-repo-id <repo-id> \
  --task "Scan assigned files for variants of the frozen Phase 2 parent set" \
  --dispatch-mode hypothesis-driven --skills code-variant-analysis \
  --finding-slugs CH-001,CH-004
```

The specialist's dispatch context must include both values exactly as registered:

```text
## Variant Receipt Authority
variant_dispatch_id: <numeric id returned by agent start>
parent_finding_slugs: [CH-001, CH-004]  # canonical sorted dispatch set
```

Provide:
- Every finding in the dispatch-registered `parent_finding_slugs` set, with its abstract bug
  pattern (CWE, taint-flow or operation/state/lifetime shape, guard failure type, code signature)
- The current Code Source Identity block and its matching structural-index manifest; a prior
  generation or summary cannot substitute for the bound index
- Candidate file list: every admitted same-language file plus any cross-language wrapper,
  configuration, template, generated implementation, or build path structurally capable of the
  same source/control/sink or operation/state/failing-use pattern, with each current numeric `file_id`, repo-relative path, and
  `file_sha256`. Classification orders work but never removes a plausible variant from eligibility
- CWE pattern references from `agent/references/code-vuln-patterns/` matching each
  finding's CWE
- Current threat-model envelope from `vigil assess fetch "code/threat-model/<repo-id>"`, with
  `current: true` and generation/digest equality; include a clipped trust-boundary summary only as
  supplemental navigation context

The variant hunter:
- Extracts the abstract pattern from each confirmed finding
- Searches the codebase for functions matching the same pattern shape
- Evaluates whether each candidate has the same guard failure
- Records variant findings with references back to the original

**Parallel dispatch**: Agent A and Agent B are dispatched simultaneously. They have no
data dependency on each other -- the verifier works from the Phase 2 finding list, and the
variant hunter works from the dispatch-frozen parent set plus the codebase. The verifier may change
live finding dispositions while the scan runs; Agent B repeats that same registered sorted parent
set in every receipt because rebuilding it from live state would detach the scan from its dispatch.

#### Evidence Adjudication

If the verifier and variant hunter produce conflicting assessments of a finding (one
confirms, the other produces evidence against), dispatch a third agent with both
perspectives, the current Code Source Identity/matching structural index, the complete current
threat-model envelope, and the sealed source paths. The third agent evaluates both arguments
against the code and produces a reasoned disposition. Evidence strength determines the outcome:
a complete source-to-sink trace, falsifiable guard analysis, or controlled runtime proof outweighs
unsupported confidence or two correlated opinions. If the conflict remains unresolved, record
`finding verify --disposition disputed` and retain both arguments; never convert uncertainty into
a false-positive kill by vote count.

This should be rare -- the verifier evaluates existing findings while the variant hunter
scans for new ones. Conflicts arise only when the variant hunter finds evidence that
contradicts a Phase 2 finding (e.g., discovers a guard the original hunter missed).

#### Handling spot-check findings

If the verifier's clean-file spot-check discovers a missed vulnerability:
1. Record the finding via `vigil assess finding record code-vuln-verifier <finding-json>`
2. Dispatch the file back to Phase 2B with a CWE directive targeting the missed class
3. After re-analysis completes, re-check the effort matrix for the affected file

#### On return from both agents:

```bash
# Record verification results (updates existing findings)
vigil assess finding verify <slug> --disposition <verdict> --reason "<rationale>"
# Rebind a stale/unbound finding only after independently reviewing the current sealed bytes.
# Substitute the current Code Source Identity values in this exact provenance shape.
vigil assess finding verify <slug> --disposition confirmed --reason "Re-reviewed current sealed source" \
  --source-name code-vuln-verifier \
  --provenance-inline '{"code_snapshot":{"repo_id":7,"repo_generation":3,"source_manifest_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}'
# Or pass the dedicated false-positive disposition when you already have the kill rationale
vigil assess finding verify <slug> --disposition false_positive --reason "<kill rationale>" --kill-reason "<specific guard or proof>" --kill-check <1-5>
# Batch-kill several FPs that share one root rationale (same payload/flags applied to every slug)
vigil assess finding verify <slug1> <slug2> <slug3> --disposition false_positive --reason "<shared kill rationale>" --kill-reason "<specific guard or proof>" --kill-check <1-5>
# Reopen a previously verified or false-positive finding when new evidence requires re-triage
vigil assess finding update <slug> --reason "<why the prior verdict no longer holds>" --status draft
# Record variant findings (new findings)
vigil assess finding record code-variant-hunter <variant-finding-json>
# Record one durable completion receipt for every assigned candidate file, including clean files.
# Each payload repeats variant_dispatch_id and the exact registered parent_finding_slugs set.
vigil assess contract code-record variant-check
vigil assess code-record variant-check <per-file-receipt-json>
```

Every new variant/spot-check file finding must follow `vigil assess contract finding record`,
including `provenance.code_snapshot` copied from the current Code Source Identity block. Generic
`finding update` cannot bind or rebind it.

**D4 killed-finding re-mint guard:** Agent A (killing FPs) and Agent B (minting variants) run in
parallel on overlapping files, so Agent B may `finding record` a candidate at a file the verifier
just killed. The backend's D4 guard refuses a net-new record that shares `defect_family` (technique)
and a normalized endpoint/canonical-location signal with a finding already killed as
`false_positive` — this is expected here, not a bug. On a 409: re-check the kill first (was it
rigorous, on the same code path as the new candidate?). If the kill was right and this is a
genuinely distinct bug at that file:line (different variable, different guard failure, different
sink), re-record with `--allow-remint` (alias `--force`). If the kill was wrong, `finding update
--status draft <slug>` on the killed finding instead of forcing the re-mint.

**Pre-report deduplication:**
Before dispatching report-writer, check for duplicates across hunter and variant-hunter prefixes.
Two findings are duplicates when they share a `defect_family` AND either: (a) the same
`canonical_location`, or (b) locations in the **same file within ~10 lines** — one root cause
reported at different points on a single taint path. Keep them distinct when they are different
vulnerability classes, involve different variables, or are independent bugs that merely sit near
each other. Merge the weaker into the stronger:
```bash
vigil assess finding merge <source-slug> <target-slug> "<reason>"
```

**Pre-report deduplication (cross-phase):**
Before dispatching report-writer, also check for duplicate findings between Phase 3 and Phase 4
(fuzz findings that confirm static findings):
```bash
vigil assess finding merge <source-slug> <target-slug> "<reason>"
```

**Phase 3 exit:**

First reconcile the assigned candidate file list against the backend receipts returned by
`code-record variant-check`. Every assigned file needs one current receipt; scan-result prose and a
handoff table do not substitute for this durable row. On resume, fetch the current rows with
`vigil assess fetch "code/variant-checks?repo_id=<repo-id>"`.

Next read only `agent/phases/code-phase-4-fuzz.md` **Pre-entry applicability decision**. Use its
bounded criteria and current findings/files/fuzzer inventory to persist one current-generation
`required` or `not_required` decision before asking whether Phase 4 entry is ready. This ordering
is load-bearing: readiness validates the receipt, so calling it before recording the receipt
deadlocks the transition. A codebase with no eligible target still records `not_required`; an
absent decision is not a skip.

```bash
vigil assess contract code-record fuzz-decision
vigil assess code-record fuzz-decision <decision-json-file>

vigil assess code-coverage --require-transition-ready fuzz
vigil assess transition-phase fuzz
```

Exit: All findings verified. Variant scan complete. If most of the verifier's kills lean on
circumstantial reasoning rather than code evidence at the hunter's rigor bar (the same check as
above), that pattern is the signal that Phase 2 hunter dispatch context (CWE pattern references,
threat model) needs tightening before the next batch. A `required` decision enters Phase 4 to run
campaigns. A `not_required` receipt enters the same lifecycle but skips compiler/fuzzer dispatch
and proceeds to terminal submission closeout; it does not bypass closeout or completion readiness.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-2-hunt.md`. Next: `agent/phases/code-phase-4-fuzz.md` (conditional; skip
campaign work through a current `not_required` receipt when the codebase has no eligible
memory-safety target; see that doc's bounded pre-entry section).
