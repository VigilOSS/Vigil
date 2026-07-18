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

**Coverage gate** -- must pass before proceeding:
```bash
vigil assess code-coverage --require-gate-pass
# Must show: all critical files analyzed, all high files analyzed, no needs-context, no pending triggers
```

If the gate fails, resolve remaining items before proceeding:
- `needs-context` items: dispatch additional file batches to Phase 2 with targeted context
- Unanalyzed critical files: dispatch to Phase 2 (hunt) first
- Pending cross-file triggers: requeue and analyze the target files before verification
- CWE effort gaps on critical files: run Phase 2B re-dispatch loop
- The gate must pass before proceeding -- unresolved items become permanently invisible to
  the report

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md`.

Provide:
- All confirmed findings from Phase 2 (suspicious findings must be resolved by hunters
  before Phase 3 — see Phase 2 exit gate)
- Source code paths for each finding (the canonical file locations)
- CWE pattern references matching each finding's defect family
- Build system configuration for compile-time flag evaluation (Makefiles, CMakeLists,
  configure scripts, feature flags)
- Threat model: `tools/analysis-state/threat-model.json` (trust boundaries for reachability
  tracing and severity grounding) — Agent B gets this below; the verifier needs it too
- Instruction: run the FP & severity-downgrade gate (`agent/references/finding-fp-and-severity-gate.md`,
  C1–C7) on each finding, then author the report-ready story into `details`, before recording
  confirmed/downgraded

The verifier's job is precise FP elimination. False positives are expected in any
AI-assisted vulnerability pipeline, but so are wrongly killed real findings. A killed
finding is only a good outcome when the counter-evidence is as rigorous as the original
finding. If the verifier kills >80% of findings, review whether kills are based on
specific code evidence or circumstantial reasoning.

The verifier:
- Traces the full entry-to-sink path for each finding, reading source directly
- Evaluates whether guards actually prevent the claimed attack
- Checks compile-time flags that might disable the vulnerable path
- Checks whether the function is reachable from an external entry point
- Produces a disposition for each finding: confirmed, downgraded (with new severity),
  or killed (with detailed reasoning)

**Clean-file spot-check:** After processing all findings, the verifier samples 2-3 critical
files that have zero findings but high effort scores (>= 70 across applicable classes). The
verifier reads those files with CWE pattern references and checks whether the "clean"
assessment from Phase 2 holds. This catches systematic blind spots where the hunter's
analysis methodology consistently misses a pattern class. If the spot-check finds a missed
vulnerability, that file goes back to Phase 2B for re-analysis with the specific CWE
directive.

#### Agent B: Variant Scanning

Dispatch `code-variant-hunter` with `agent/skills/code-variant-analysis/SKILL.md`.

Provide:
- Confirmed findings with their abstract bug patterns (CWE, taint path shape, guard
  failure type, code pattern signature)
- Candidate file list: same language, classification `medium` or above
- CWE pattern references from `agent/references/code-vuln-patterns/` matching each
  finding's CWE
- Threat model summary (trust boundaries for quick reachability checks)

The variant hunter:
- Extracts the abstract pattern from each confirmed finding
- Searches the codebase for functions matching the same pattern shape
- Evaluates whether each candidate has the same guard failure
- Records variant findings with references back to the original

**Parallel dispatch**: Agent A and Agent B are dispatched simultaneously. They have no
data dependency on each other -- the verifier works from the Phase 2 finding list, and the
variant hunter works from confirmed findings plus the codebase.

#### Multi-Perspective Voting

If the verifier and variant hunter produce conflicting assessments of a finding (one
confirms, the other produces evidence against), dispatch a third agent with both
perspectives and the source code. The third agent evaluates both arguments against the
code and produces a reasoned disposition. Majority vote (2 of 3) determines the final
disposition.

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
# Or pass the dedicated false-positive disposition when you already have the kill rationale
vigil assess finding verify <slug> --disposition false_positive --reason "<kill rationale>" --kill-reason "<specific guard or proof>" --kill-check <1-5>
# Batch-kill several FPs that share one root rationale (same payload/flags applied to every slug)
vigil assess finding verify <slug1> <slug2> <slug3> --disposition false_positive --reason "<shared kill rationale>" --kill-reason "<specific guard or proof>" --kill-check <1-5>
# Reopen a previously verified or false-positive finding when new evidence requires re-triage
vigil assess finding update <slug> --reason "<why the prior verdict no longer holds>" --status draft
# Record variant findings (new findings)
vigil assess finding record code-variant-hunter <variant-finding-json>
```

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
```bash
vigil assess transition-phase fuzz
```

Exit: All findings verified. Variant scan complete. If the verifier killed >80% of the findings
dispatched to it, review whether Phase 2 hunter dispatch context (CWE pattern references, threat
model) needs tightening before the next batch — a high kill rate this far past hunt is a dispatch
signal, not just an FP-elimination stat. Transition to Phase 4 (Fuzz) if the codebase is C/C++
with memory-safety targets, otherwise skip directly to report.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-2-hunt.md`. Next: `agent/phases/code-phase-4-fuzz.md` (conditional; skip
directly to report when the codebase has no C/C++ memory-safety targets — see that doc's entry gate).
