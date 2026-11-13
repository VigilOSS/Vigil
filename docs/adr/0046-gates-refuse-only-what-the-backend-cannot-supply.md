# ADR 0046 — Gates refuse only what the backend cannot supply or the operator cannot see

- Status: Accepted — implemented in report readiness, the phase transition, code queue
  closeout and code readiness, the submission export, and the finding, handoff and
  client-binding write paths
- Date: 2026-11-14
- Amends: [ADR 0033](0033-verify-before-exploit-with-gated-sibling-and-chain-passes.md), whose
  chain pass is now an advisory.

## Context

An engagement review counted the refusals an operator or specialist hit on the way to a
report. Several refused something the backend could have filled in itself, or a judgment
no record could settle, and each cost a round trip that changed nothing:

- A severity that departs from its CVSS band blocked report readiness until a fresh
  verification carried a five-field `severity_variance`, four of whose fields (the band,
  the chosen severity, the verifier and a decision receipt) the verification already
  determines. Only the reason is a human judgment.
- The chain-construction gate refused `report` until any `exploit-developer` dispatch had
  completed. Any dispatch satisfied it, so it proved nothing about chains, and an
  engagement whose confirmed findings are genuinely independent had to force through it.
- `collect`, `consume-test` and `verify` refused on an empty state (no services, an empty
  work buffer, no active findings). Each is a fact worth reading, never a reason to stop:
  the next phase is where the operator acts on it.
- A critical or high code closeout that named fewer `cwe_coverage` families than the file
  owes was refused, so lanes padded the payload with hand-written `effort: 0` entries that
  carried no more information than the refusal.
- The terminal `complete` edge reported a bare `report_not_ready` instead of the readiness
  blockers, a walk across `report` and `complete` ran the terminal checks twice, and an
  ungraded reportable finding was listed twice in readiness.
- Report readiness, code readiness and `agent handoff` judged agent-written notes and handoff
  summaries with a phrase detector: a severity word beside a vuln class or CWE, with no
  recorded slug on the line or in the heading above, was reported as an unrecorded finding.
- Finding and handoff writes refused values the rest of the write already stated: a verify
  reason its structured check states, a kill or block reason the verify reason states, a
  CVSS score its vector computes to, a handoff role its dispatch registered, and a client
  binding identical to the current one.

## Decision

1. **Severity versus CVSS band is an advisory.** Readiness reports an unattributed
   divergence as `severity_cvss_mismatch` and an attributed one as
   `severity_cvss_band_divergence`, both advisories, so the operator and submission QC still
   see it. A CVSS arithmetic error (`cvss_vector_invalid`, `cvss_vector_score_mismatch`)
   stays a blocker. On a terminal verification the backend derives every variance field the
   verification determines; the author supplies only the reason, and an authored field that
   contradicts the verification is still refused. The variance's actor is the verifier
   dispatch whose receipts decide the verification; an authored actor may name it by agent
   id or by dispatch id (stored as the agent id), and any other actor is refused. A
   verification without a variance records the verdict, and readiness names the
   divergence. `export submission` carries both advisories for its finding into the
   rendered OPERATOR DETAILS and the submission context, which is what submission QC
   reviews. A variance attaches on a fresh verification, or, reason only, to the current
   verification through a `severity_variance` decision (`vigil assess agent decision --kind
   severity_variance`): the verdict does not change, so no fresh proof is needed. The decision
   derives the band, the chosen severity, the verifier and the decision receipt from that
   receipt-backed confirmed or downgraded verification, refuses an authored value that
   contradicts them, and refuses a finding with no band departure or with a variance already on
   its current verification. `finding update` has no path that attaches one.
2. **The chain pass is an advisory.** With two or more confirmed high or critical active
   findings, the `report` and `complete` transitions name each one that no recorded attack
   chain links (`chain_construction_unchained`), count the completed `exploit-developer`
   dispatches, and point at `vigil assess chain list`. Whether a chain exists is an operator
   and exploit-developer judgment; the advisory keeps it in view at the edge where it matters.
   The sibling (variant) pass of ADR 0033 stays a blocker, because it reads which findings a
   variant-rotation dispatch listed, a structured record of the pass that ran.
3. **Empty-state edges are advisories.** `no_services`, `empty_work_buffer` and
   `no_active_findings` print the count and the command that inspects it, and the phase
   advances. A read that fails behind one of these checks, behind the verify edge's
   consumption advisory, or behind the chain pass is reported as an advisory
   `precondition_check_failed` that says the check was not evaluated; a check that can
   block still fails closed on a failed read.
4. **The backend records the families a critical/high closeout left out, and a shortfall
   below the depth floor is Phase 2B work.** Each applicable family the closeout named no
   entry for is stored as an `effort: 0` entry marked `recorded_by: closeout`, and the `done`
   response returns them as `unreviewed_families_recorded` with the basis of the required
   set. Any reviewed entry for the family, an effort or a `not_applicable` disposition, takes
   precedence over the recorded one whichever is read first. A replayed `done` and a
   `code-record analysis --supersede` correction of a done row record and return the same
   list. Missing slot types or an empty applicable set still refuse: that is the architect's
   durable record being incomplete, not a shortfall the backend can measure.

   The closeout is never refused for its effort numbers: they are the reviewer's own record
   (ADR 0001 decision 3), and refusing them taught lanes to pad the payload. A critical or
   high closeout that leaves an applicable family at effort 0 or below the tier's floor
   (critical 70, high 50), merged with the file's current receipts as the coverage harness
   merges them, instead raises a pending `depth_floor` trigger on the file itself
   (`code_analysis_triggers.origin`), returned as `depth_floor_triggers`. The existing trigger
   machinery carries it: `code-dispatch requeue-triggers` sends a directed pass that answers
   for the families it carries, and `code-dispatch resolve-triggers` records why another pass
   would not move one, which is the deferral-with-reason ADR 0001 decision 2 asks of a block;
   `reviewed_at_sufficient_depth`, accepted on a depth-floor trigger only and with the note
   every resolution needs, records that the file was read at depth although its recorded
   effort is below the floor. Only depth answers one: unlike a cross-file hypothesis, which a
   review answers by carrying it or by scoring its class at all, a depth-floor trigger is
   settled by a review only when that attempt's merged effort for the family reaches the
   tier's floor (or marks it not applicable). `requeue-triggers` therefore sends the directed
   pass after a review that scored the family short, a directed pass that closes short leaves
   the same trigger owed rather than resolving it and raising another (its dry run reports
   the same), and the status sync that re-derives every bound trigger keeps a resolution a
   `--supersede` correction earned by reaching the floor. One live trigger is kept per file
   and family; a closeout that reaches the floor resolves the family's pending one, a
   `--supersede` correction is judged again against the corrected coverage, and a settled one
   is not raised again in that source generation. The coverage gate and code readiness
   (`depth_floor_triggers`, overrideable like `pending_triggers`) name them until then.
   A family the closeout marks not applicable never raises one, and settles a pending one,
   whatever a receipt scored for it: the review has said the family cannot occur in that file
   (a server-side family on a browser bundle). A close recorded before the backend raised
   these triggers is not given them retroactively. Doing so once at startup raised several
   hundred blocking triggers on one engagement's history, mostly server-side families on
   browser bundles that the old review could not mark not applicable, and the operator
   re-reviewed all of them. Those families are named instead as `untriggered_depth_shortfalls`
   on the coverage gate and code readiness, grouped by tier and family with sample paths and
   the verbs that act on one, and they never block.
   The effort warnings themselves stay advisory, and a number that overstates the review
   is not detected: the trigger routes the shortfall a closeout
   admits, it does not measure depth. `transition-phase --track code complete` still cannot
   be forced past durable debt.
5. **Terminal transitions name what they read.** `complete` prints each report-readiness
   blocker by kind and subject, as `report` does, and groups readiness advisories per kind
   with a count, a few subjects and the readiness command that lists them all. A walk that
   crosses `report` and `complete` runs the terminal checks once, under `complete`, and an
   identical item is printed once. An ungraded reportable finding on a web engagement is one
   `unreviewed_findings` item, the one that says how to grade it.
6. **Agent prose is not judged by phrase matching.** The notes and hunter-handoff
   finding-prose advisories, the `agent handoff` summary warning and the scan-status
   advisories that reported when the detector could not load are removed. A keyword shape on
   free text missed rewordings and flagged lines that were not findings, so neither its
   presence nor its silence was evidence. Whether notes or handoffs hold a finding nobody
   recorded is a judgment the report-boundary `phase-qc` pass makes by reading them.
   Structured signals stay: a suspicious queue result blocks `verify-variant`, and a handoff
   names what it found in `finding_slugs`. The same holds for code-file obligations: the
   families a file's job adds beyond its slot types come from the architect's structured
   `context_tags`, never from words in its free-text `role` label. A classification that
   records no tags (every file classified before tags existed, or one that omits the field
   on a file that records none) is not read as "no tag applies": coverage and code readiness name each such file as
   `context_tags_unrecorded`, with the read that lists them all and the re-classify that
   records the tags, and an explicit empty list records that none apply. The read is the
   pointer's own set, scoped to the same repository, so its count and the files it lists
   agree. A re-classification that omits the field keeps the tags the file already records
   and names each kept value on the response's `derived` list: an omitted field is not an
   instruction to forget what the architect recorded. Owing every tag's families on an
   untagged file was rejected: it would put a dozen imprecise obligations, and with
   decision 4 a dozen depth-floor triggers, on every legacy critical/high file.
7. **A write fills what the rest of the write states, and names each fill.** Every value
   below is stored on the caller's behalf and listed on the response's `derived` list, and
   a finding write's transition metadata names the same fields:
   - A verify with no `reason_text` takes it from this write's own payload: its
     confirm_check (`confirmed`, `downgraded`), its counter_check or `details.kill_reason`
     (`false_positive`), its next_test (`pending_runtime_proof`) or `details.block_reason`
     (`blocked`). A kill or block reason already stored on the finding is never reused as
     the reason: it describes the verdict that stored it, so a `blocked` verify that carries
     neither a reason nor a fresh `details.block_reason`, including a revision of a block
     the finding still holds, is refused. The reason stays required where it is the only
     record of why: `disputed`, an operator-authority verdict, a terminal verdict walked
     back to an open status, and a killed finding (`false_positive` verdict or workflow)
     revived to any other verdict, because the new check proves the claim without saying
     what the kill got wrong.
   - A kill with no `details.kill_reason` stores the verify reason, or a summary of its
     counter_check. A stored kill reason is kept only while it belongs to the kill being
     recorded: the finding still holds that kill, has never been killed, or the reason
     was written (by `finding update`) after the finding last left its earlier kill.
     Otherwise the new kill stores its own, and its `derived` entry names the stored
     reason it replaced. A `blocked` verify treats a stored block reason the same way.
     `finding merge` never fills the target's `kill_reason`, `kill_check`,
     `block_reason`, `unblock_requirements` or `withdrawal_reason` from the source: they
     explain the source's own verdict or submission, which the target does not take, and
     they stay on the merged source. `details.kill_check` is optional and not derived. A kill
     that names its settling test in
     `details.required_followup` is repeated by report readiness as
     `killed_finding_settling_test_outstanding`, because a `false_positive` leaves every
     report projection.
   - The phrase-matched `kill_reason_reads_untestable` advisory, added on 2026-08-28
     because verifiers killed findings whose experiment could not run (no second
     organization for a cross-tenant check), is removed, and nothing structural replaces
     it. The requirement that `false_positive` carry a counter_check with `completed: true`
     and proof receipts from completed runs, and the `blocked` status for an experiment
     that could not run, predate this decision; they were in force while the advisory
     fired. Removing the phrase list is therefore a net removal of a check. It is accepted
     because the list both missed rewordings and flagged kills that had run, so neither
     its presence nor its silence was evidence. The backstops are the verifier's
     independence (the backend refuses the dispatch that originated the finding as its
     verifier) and the operator's and QC's reading of the kill reason and counter-check; a
     kill recorded as `false_positive` whose experiment never ran is not caught by any
     structural check.
   - `confirmed` with a `new_severity` below the current band is recorded as `downgraded`,
     so the band movement lands on a `verified_downgraded` transition; it still needs the
     confirm_check every confirmed or downgraded verdict needs, and the refusal names it.
   - A `blocked` verify with no `details.block_reason` stores the verify reason there,
     within the block reason's 500-character cap, and a move to submission status
     `withdrawn` with no `details.withdrawal_reason` stores the write's reason there.
   - A vector with no score stores the score the vector computes to, when the finding
     holds no score. A stored score the new vector does not compute to is a recorded value
     the write contradicts, so it is refused naming both, and the write sends the score
     with the vector.
   - A handoff with no role stores its dispatch's registered role. A different role
     contradicts the dispatch the handoff names and is refused (409).
   - A re-classification with no `context_tags` keeps the tags the file records (decision
     6); a file that records none stays unrecorded, which is not a fill.
   - A client binding identical to the dispatch's current binding writes nothing and
     returns the current binding with `already_bound` and HTTP 200.

Across these fills the rule is the same: derive what a write leaves out, refuse what it
contradicts. A self-reported value (an effort number, a `completed` flag) is the
reporter's claim, never a measurement the backend confirms.

## Consequences

- A report can be exported with a severity that departs from its CVSS band and no recorded
  reason. The divergence is still named in readiness and reaches submission QC, which judges
  whether the stated severity is defensible.
- A report can be entered without any exploit-developer pass. The advisory names the
  findings no chain links, which is a sharper prompt than the dispatch count it replaces.
- A code file can close with families nobody reviewed. They are recorded as zero-effort gaps
  rather than hidden, the `--cwe-matrix` view lists every one, and on a critical or high
  file each is a depth-floor trigger the phase exit names until a directed pass that
  reaches the floor or a recorded resolution settles it.
- A file classified without context tags owes only its slot-type and language families
  until the architect tags it; coverage and readiness name every such file.
- Grouped readiness and coverage output keeps its size bounded by groups rather than by
  files, and each grouped line names what it leaves out and the read that lists it.
- A finding written only into notes or a handoff summary raises no readiness item. The
  report-boundary `phase-qc` pass reads the notes and handoffs for one, as a reviewer would.

## Alternatives considered

- **Keep the refusals and improve their messages.** Rejected: a precise refusal still costs a
  round trip for a value the backend already holds.
- **Derive the variance reason as well.** Rejected: why a severity departs from its band is
  the one part of the record that is a human judgment; a generated reason would read as one.
- **Satisfy the chain pass from recorded chains instead of dispatches.** Rejected as a gate:
  an engagement with independent findings records no chain, so the gate would still have to
  be forced; as an advisory the same signal steers without refusing.
