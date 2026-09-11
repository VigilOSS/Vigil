# Code Phase 3 — Verify + Variant

**Read-on-phase-entry.** When you ENTER Code Phase 3 (Verify + Variant), Read this doc before
dispatching `code-vuln-verifier` and, when a non-empty parent set exists, the parallel
`code-variant-hunter`, and re-read it on a
method re-anchor. It carries the coverage gate that must pass before Phase 3 starts, Agent A
(`code-vuln-verifier`) dispatch fields and the clean-file spot-check, Agent B (`code-variant-hunter`)
dispatch fields, the independent evidence-adjudication protocol for conflicting dispositions, handling
spot-check findings, the on-return recording commands, pre-report deduplication (same-phase and
cross-phase), and the Phase 3 exit. Cross-phase machinery — the Core Loop, the Phased mindset flow
(code) (which scopes `code-vuln-verifier` to the verification-skeptic stance and `code-variant-hunter`
to the confirmed family's lens), the Agent Roster, and the Dispatch Context Template / Pre-Dispatch
Checklist — stays in `agent/operator-core-code.md`; this doc does not restate it.

### Phase 3: VERIFY + VARIANT

Phase 3 merges verification and applicable variant scanning into one phase. The verifier always
runs; the variant hunter runs in parallel only when the current Phase 2 root findings produce a
non-empty frozen parent set. That pre-verification set contains current-source findings in a
reportable workflow status, excludes `variant_of` children and blocked/false-positive dispositions,
and is frozen before either parallel worker changes live verification state:

- **Agent A (code-vuln-verifier)**: TOB-style false positive elimination on all findings
- **Agent B (code-variant-hunter, conditional)**: systematic scanning for variants of the frozen Phase 2 root patterns

When Agent B is applicable, both agents run in parallel because their work is independent: the
verifier evaluates existing findings, while the variant hunter scans for new instances of
confirmed patterns.

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

#### Agent B: Variant Scanning (conditional)

First derive the exact current Phase 2 root set for this repository and freeze its canonical sorted
slugs before verification starts. Include current-source findings in a reportable workflow status
even while unreviewed or disputed; exclude `variant_of` children and verification-blocked or
false-positive findings. If that set is empty, variant-pattern review is not applicable: do **not** dispatch
`code-variant-hunter`, create an empty-scope dispatch, or fabricate per-file receipts. Continue the
verifier path and the Phase 4 applicability decision. Complete/fuzz readiness derives this
non-applicability from the absence of current parent findings.

When the frozen set is non-empty, dispatch `code-variant-hunter` with
`agent/skills/code-variant-analysis/SKILL.md` under the role prompt's **Phase 3 receipt-bearing
mode** contract.

Before registering the dispatch, freeze the Phase 2 parent findings into one canonical sorted slug
list. Register that exact list on the dispatch and retain the numeric backend row ID printed by the
command:

```bash
vigil assess agent start --agent-id <agent-id> --role code-variant-hunter \
  --code-repo-id <repo-id> \
  --task "Scan assigned files for variants of the frozen Phase 2 parent set" \
  --dispatch-mode hypothesis-driven --skills code-variant-analysis \
  --finding-slugs CH-001,CH-004 --no-target-traffic \
  --prompt-context-json dispatch-context.json --emit-prompt
```

The specialist's dispatch context must include both values exactly as registered:

```text
## Variant Receipt Authority
variant_dispatch_id: <the dispatch_id agent start printed>
parent_finding_slugs: [CH-001, CH-004]  # canonical sorted dispatch set
```

Provide:
- Every finding in the dispatch-registered `parent_finding_slugs` set, with its abstract bug
  pattern (CWE, taint-flow or operation/state/lifetime shape, guard failure type, code signature)
- The current Code Source Identity block and its matching structural-index manifest; a prior
  generation or summary cannot substitute for the bound index
- Admitted-file list: every current admitted file, with each numeric `file_id`, repo-relative path,
  language, and `file_sha256`. Order same-language files and structurally capable cross-language
  wrappers/configuration/templates/generated implementations first, but retain every other file for
  a bounded pattern-inapplicability check and receipt. Classification orders work; it never removes
  a file from the backend's admitted-file receipt obligation
- CWE pattern references from `agent/references/code-vuln-patterns/` matching each
  finding's CWE
- Current threat-model envelope from `vigil assess fetch "code/threat-model/<repo-id>"`, with
  `current: true` and generation/digest equality; include a clipped trust-boundary summary only as
  supplemental navigation context

The variant hunter:
- Extracts the abstract pattern from each dispatch-frozen Phase 2 root finding
- Searches the codebase for functions matching the same pattern shape
- Evaluates whether each candidate has the same guard failure
- Records variant findings with references back to the original

**Parallel dispatch when applicable**: Agent A and Agent B are dispatched simultaneously. They have no
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
`finding verify --status disputed` and retain both arguments; never convert uncertainty into
a false-positive kill by reviewer count.

This should be rare -- the verifier evaluates existing findings while the variant hunter
scans for new ones. Conflicts arise only when the variant hunter finds evidence that
contradicts a Phase 2 finding (e.g., discovers a guard the original hunter missed).

#### Handling spot-check findings

If the verifier's clean-file spot-check discovers a missed vulnerability:
1. Record the finding via `vigil assess finding record code-vuln-verifier <finding-json> --agent-id <your-agent_id>`
2. Dispatch the file back to Phase 2B with a CWE directive targeting the missed class
3. After re-analysis completes, re-check the effort matrix for the affected file

#### On return from the applicable agent set:

```bash
# Record verification results (updates existing findings)
vigil assess finding verify <slug> --status <verdict> --reason "<rationale>"
# Rebind a stale/unbound finding only after independently reviewing the current sealed bytes.
# Substitute the current Code Source Identity values in this exact provenance shape.
vigil assess finding verify <slug> --status confirmed --reason "Re-reviewed current sealed source" \
  --proof-receipt-id <proof-receipt-id> \
  --source-name code-vuln-verifier \
  --provenance-inline '{"code_snapshot":{"repo_id":7,"repo_generation":3,"source_manifest_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}'
# Or pass the dedicated false-positive status with a completed counter-check
vigil assess finding verify <slug> --status false_positive --reason "<kill rationale>" --counter-check-file <counter-check.json>
# Reopen a previously verified or false-positive finding when new evidence requires re-triage
vigil assess finding update <slug> --reason "<why the prior verdict no longer holds>" --status draft
# Verification deliberately preserves draft workflow state. After review, every retained draft
# must be promoted explicitly; a confirmed-but-draft finding blocks fuzz and completion.
vigil assess finding update <slug> --reason "Verification retained this finding" --status active
# Record variant findings (new findings)
vigil assess finding record code-variant-hunter <variant-finding-json> --agent-id <your-agent_id>
# Record one durable completion receipt for every current admitted file, including quick non-matches.
# Set dispatch_id to variant_dispatch_id and repeat the exact registered parent_finding_slugs set.
vigil assess contract code-record variant-check
vigil assess code-record variant-check <per-file-receipt-json>
```

Every new variant/spot-check file finding must follow `vigil assess contract finding record`,
including `provenance.code_snapshot` copied from the current Code Source Identity block. Generic
`finding update` cannot bind or rebind it.

Reopening is not a terminal disposition. For every finding whose workflow status is `draft` after
verification, either promote the retained finding with `finding update --status active`, merge it
into its canonical target, or kill it through `finding verify --status false_positive` with a completed counter-check.
Fuzz/complete readiness rejects both unverified drafts and confirmed-but-draft records so an
ambiguous lifecycle state cannot disappear from the report queue.

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

When the frozen parent set was non-empty, first reconcile the complete current admitted-file list against
the backend receipts returned by `code-record variant-check`. Every admitted file needs one current
receipt, including a bounded non-match receipt for a file that cannot instantiate, route,
configure, or reach the pattern; scan-result prose and a handoff table do not substitute for this
durable row. On resume,
fetch the current rows with `vigil assess fetch
"code/variant-checks?repo_id=<repo-id>"`. If a new current Phase 2 root appeared after dispatch,
the old-scope receipts remain historical evidence but are non-covering; register a new dispatch with
the new exact set and repeat the file receipts. Killed, non-reportable, stale, and child findings do
not create current debt. When the parent set was empty, do not create receipts; readiness treats
variant review as not applicable until a current Phase 2 root finding exists.

For each applicable variant obligation, link the returned owning receipt through `vigil assess
run-audit code-receipt record <run-id> <link-json>`. The link names the exact target, obligation,
variant receipt, retained candidates, and shared proof. It resolves debt only when the receipt's
repository generation, source manifest, file path/hash, and obligation object all agree; receipt
prose is never copied into a second truth store.

Fuzz entry also requires every current Phase 2 root to leave unreviewed/disputed triage. A verified
`pending_runtime_proof` disposition may enter Phase 4 when the receipt and fuzz-decision gates pass;
it remains outside report-durable completion until runtime proof resolves it.

Next read only `agent/phases/code-phase-4-fuzz.md` **Pre-entry applicability decision**. Use its
bounded criteria and current findings/files/fuzzer inventory to persist one current-generation
`required` or `not_required` decision before asking whether Phase 4 entry is ready. This ordering
is load-bearing: readiness validates the receipt, so calling it before recording the receipt
deadlocks the transition. A codebase with no eligible target still records `not_required`; an
absent decision is not a skip.

```bash
vigil assess contract code-record fuzz-decision
vigil assess code-record fuzz-decision <decision-json-file>
vigil assess run-audit code-receipt record <run-id> <fuzz-decision-link-json>

vigil assess code-coverage --require-transition-ready fuzz
vigil assess transition-phase fuzz
```

Exit: All findings verified. Variant scan complete or explicitly not applicable because the
current parent set is empty. If most of the verifier's kills lean on
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
