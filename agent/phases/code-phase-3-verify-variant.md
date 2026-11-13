# Code Phase 3 — Verify + Variant

**Read-on-phase-entry.** Read this doc before dispatching `code-vuln-verifier` (and, for a
non-empty parent set, `code-variant-hunter`), and re-read it on a method re-anchor. Cross-phase
machinery (Core Loop, mindset flow, roster, Dispatch) stays in `agent/operator-core-code.md`.

### Phase 3: VERIFY + VARIANT

- **Agent A (`code-vuln-verifier`)** always runs: false-positive elimination on every finding.
- **Agent B (`code-variant-hunter`, conditional)** scans for variants of the frozen Phase 2 root
  patterns, only when that parent set is non-empty.

The parent set is the current-source Phase 2 root findings in a reportable workflow status,
excluding explicit `variant_of` children and verification-blocked or false-positive dispositions,
frozen before either worker changes live verification state. The two agents have no data
dependency, so dispatch them simultaneously. The verifier may change dispositions while the scan
runs; Agent B repeats the registered sorted parent set in every receipt because rebuilding it from
live state would detach the scan from its dispatch.

Entry readiness (`code-coverage --require-transition-ready verify-variant`) passed at the Phase 2
exit. If it fails on a resumed session, return each blocker to its owner: `needs-context` items,
unaccounted files, and pending triggers to Phase 2; missing or stale source, index, or threat model
to Phase 0/1. An identity blocker cannot be replaced by a prose summary, and an item left
unresolved at this entry never reaches the report. Review quality stays advisory: route meaningful
`code-coverage --cwe-matrix` warnings through the Phase 2B loop.

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md` and:
- every confirmed Phase 2 finding (suspicious ones were resolved by hunters at the Phase 2 exit);
- current Code Source Identity, its matching structural-index manifest, canonical file locations,
  and the complete current threat-model envelope (`current: true`, matching identity) including
  the trusted-inputs set; a clipped summary is supplemental only;
- build configuration paths for compile-time flag evaluation (Makefiles, CMakeLists, configure
  scripts, feature flags);
- the instruction to run the FP & severity-downgrade gate
  (`agent/references/finding-fp-and-severity-gate.md`, C1–C7) on each finding and author the
  report-ready story into `details` before recording confirmed/downgraded;
- the **clean-file spot-check**: after the findings, sample 2-3 critical files with zero findings
  and no below-threshold cells in the current CWE matrix, and check whether Phase 2's clean
  assessment holds. This catches systematic blind spots in the hunter's method.

**Reviewing kills.** Wrongly killed real findings are as real as false positives, so a kill is a
good outcome only when its counter-evidence matches the original finding's rigor. Each kill names
in `details.kill_reason` which check falsified the claim, and may record in `details.kill_check` the
number of the Five-Check Protocol check that produced it (`code-finding-verification` skill). Check whether each kill cites specific code evidence or leans on
circumstantial reasoning (a guard "looks sufficient", a test "seems to cover it"). That pattern, not
a raw kill count, is the signal to reopen a kill for a second look (`finding update <slug> --status
draft --reason "<why the prior verdict no longer holds>"`); when most kills lean that way, tighten
the Phase 2 hunter dispatch context (CWE pattern references, threat model) before the next batch.

#### Agent B: Variant Scanning (conditional)

Before verification starts, read and freeze the parent set's canonical sorted slugs:
`vigil assess fetch "code/readiness?target_phase=fuzz"` prints it as `variant_parent_finding_slugs`
on the repository's `variant_checks_incomplete` blocker, and the report blocker
`finding_variant_receipts_incomplete` carries the same field. Its `slugs` list only the
report-durable subset that creates the debt; never freeze that as the dispatch scope. Unreviewed and
disputed roots are included. Children are visible in each finding's `finding get` `links` and a
parent's `inbound_links`; a row with `retired_at` set is history, not a live child. A rejected
`agent start` names the expected set.

If no current root exists, variant review is not applicable: dispatch no `code-variant-hunter`,
create no empty-scope dispatch, and fabricate no per-file receipts. Continue the verifier path and
the Phase 4 applicability decision; complete/fuzz readiness derives the non-applicability from the
absence of current parents.

Variant relationships use the `links` array in `code-variant-analysis` Step 4: a same-class
independent finding uses `related` and stays a root, and naming a parent only in
`details.variant_of` does not establish child ancestry. A root added or promoted after the freeze
needs covering work for the new scope: inspect `vigil assess fetch --paginate
"code/variant-checks?include_stale=true"` currency diagnostics and the blocker's
`variant_parent_finding_slugs`, and preserve the frozen dispatch and its old receipts.

When the frozen set is non-empty, dispatch under the role's **Phase 3 receipt-bearing mode**,
registering the frozen sorted slugs with `--finding-slugs` (the packet's Variant Receipt Authority
block comes from that registration; `agent/operator-core-code.md` "Dispatch"):

```bash
vigil assess agent start --agent-id <agent-id> --role code-variant-hunter \
  --code-repo-id <repo-id> \
  --task "Scan assigned files for variants of the frozen Phase 2 parent set" \
  --dispatch-mode hypothesis-driven --skills code-variant-analysis \
  --finding-slugs CH-001,CH-004 --no-target-traffic \
  --prompt-context-json dispatch-context.json
```

Provide:
- every registered parent finding with its abstract bug pattern (CWE, taint-flow or
  operation/state/lifetime shape, guard failure type, code signature);
- current Code Source Identity and its matching structural-index manifest (a prior generation or
  summary cannot substitute), and the current threat-model envelope;
- every current admitted file with its numeric `file_id`, repo-relative path, language, and
  `file_sha256`. Order same-language files and structurally capable cross-language
  wrappers, configuration, templates, and generated implementations first, but keep every other
  file for a bounded pattern-inapplicability check and receipt: classification orders work and
  never removes a file from the receipt obligation;
- CWE pattern references from `agent/references/code-vuln-patterns/` for each parent's CWE.

#### Evidence Adjudication

When the verifier and variant hunter conflict on a finding (one confirms, the other produces
evidence against, such as a guard the original hunter missed), dispatch a third agent with both
arguments, the bound Code Source Identity and structural index, the complete current threat-model
envelope, and the sealed source paths. Evidence strength decides: a complete source-to-sink trace,
falsifiable guard analysis, or controlled runtime proof outweighs unsupported confidence or two
correlated opinions. If the conflict stays unresolved, record `finding verify --status disputed`
with both arguments retained; reviewer count never converts uncertainty into a false-positive kill.

#### Handling spot-check findings

When the verifier's spot-check records a missed vulnerability (its own `finding record`), send that
file back to Phase 2B with a CWE directive for the missed class, and re-check the effort matrix for
it after re-analysis.

#### On return from the applicable agent set:

The verifier records each verdict, promotes retained drafts, and records chains and spot-check
findings in its closing sequence; the variant hunter records its findings and one
`code-record variant-check` receipt per current admitted file. Your side:

- **Drafts.** Verification preserves `draft` workflow status, and fuzz/complete readiness rejects
  unverified drafts and confirmed-but-draft records. Each remaining draft is promoted (`finding
  update <slug> --status active --reason "Verification retained this finding"`), merged into its
  canonical target, or killed by a verifier counter-check. Reopening is not a terminal disposition.
- **Source binding.** `finding record` binds every new variant or spot-check finding to the current
  snapshot. A stale or unbound finding is rebound only by the verifier's `finding verify` after it
  re-reviews the current sealed bytes (`vigil assess contract finding verify` shows the rebind
  shape); `finding update` cannot bind or rebind.

**D4 killed-finding re-mint guard:** Agent B may `finding record` a candidate at a file the verifier
just killed, and the backend's D4 guard refuses a net-new record sharing `defect_family` and a
normalized endpoint/canonical-location signal with a `false_positive` finding. That 409 is expected
here. Re-check the kill first (rigorous, and on the same code path?). If it was right and this is a
genuinely distinct bug at that location (different variable, guard failure, or sink), re-record
with `--allow-remint`; if the kill was wrong, reopen the killed finding with `finding update
--status draft <slug>` instead.

**Pre-report deduplication:** before dispatching report-writer, check for duplicates across hunter
and variant-hunter prefixes, and between Phase 3 and Phase 4 (fuzz findings that confirm static
ones). Two findings are duplicates when they share a `defect_family` and either (a) the same
`canonical_location` or (b) locations in the same file within ~10 lines, one root cause reported at
different points on a single taint path. Keep them distinct when they are different classes,
involve different variables, or are independent bugs that merely sit close. Merge the weaker into
the stronger:
```bash
vigil assess finding merge <source-slug> <target-slug> "<reason>"
```
The target keeps its severity, CVSS, CWE, and verdict. A stronger source value applies only through
the explicit `finding update` the merge warning names, which invalidates the verdict and needs a
fresh proof run.

**Operator-authority terminal verdict.** When the fact that settles a code finding lies outside the
sealed snapshot by design (a deployment configuration, a vendor statement), record the verdict on
your own evidence with `vigil assess finding verify <slug> --status <terminal> --operator-authority
--intel-id <id> --reason "<what that evidence establishes>"`; the command states what else it
needs. The verdict renders as operator-authority rather than dispatch-verified: ADR 0019 lets you
weaken your own gate, and the stamp keeps that visible. It is the operator's flag only;
`code-vuln-verifier` still owes a receipt from its own independent run.

**Phase 3 exit:**

When the frozen parent set was non-empty, reconcile the complete current admitted-file list against
the `code-record variant-check` receipts. Every admitted file needs one current receipt, including a
bounded non-match for a file that cannot instantiate, route, configure, or reach the pattern;
scan prose and handoff tables do not substitute for the durable row. On resume, read every row with
`vigil assess fetch --paginate "code/variant-checks?repo_id=<repo-id>"` (without `--paginate` the
read is one bounded page). If a new current root appeared after dispatch, the old receipts stay as
historical, non-covering evidence: register a new dispatch with the new exact set and repeat the
file receipts. Killed, non-reportable, stale, and child findings create no current debt. When the
parent set was empty, create no receipts.

For run-accounted work, link each applicable variant obligation's owning receipt with `vigil assess
run-audit code-receipt record <run-id> <link-json>`, naming the exact target, obligation, variant
receipt, retained candidates, and shared proof. It resolves debt only when the receipt's repository
generation, source manifest, file path/hash, and obligation all agree; receipt prose is never copied
into a second truth store.

Fuzz entry also requires every current Phase 2 root to leave unreviewed/disputed triage. A verified
`pending_runtime_proof` disposition may enter Phase 4 when the receipt and fuzz-decision gates pass;
it stays outside report-durable completion until runtime proof resolves it.

Next read only `agent/phases/code-phase-4-fuzz.md` **Pre-entry applicability decision** and record
its current-generation `required` or `not_required` decision before asking whether Phase 4 entry is
ready. Readiness validates that receipt, so checking readiness first deadlocks the transition. A
codebase with no eligible target still records `not_required`; an absent decision is not a skip.

Exit: all findings verified; the variant scan complete, or not applicable because the parent set is
empty. A `required` decision enters Phase 4 to run campaigns. A `not_required` receipt enters the
same lifecycle, skips compiler/fuzzer dispatch, and proceeds to terminal submission closeout; it
does not bypass closeout or completion readiness.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-2-hunt.md`. Next: `agent/phases/code-phase-4-fuzz.md`.
