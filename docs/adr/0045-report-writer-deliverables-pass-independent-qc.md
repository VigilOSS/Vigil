# ADR 0045 — Report-writer deliverables pass independent QC before publication

- Status: Accepted — implemented in the decision recorder, final submission export, the
  `complete` phase transition, the submissions desk and the `agent decision` contract
- Date: 2026-11-13
- Amends: [ADR 0025](0025-final-external-communications-are-versioned-and-immutable.md), whose
  final export now also binds an independent QC review to the exported package.

## Context

Submission checklist QA was recorded by the editing writer as `pass1_qa_verdict`. The auditor
could be the writer or the finding author, the verdict gated nothing, and only Medium-or-above
findings ever received an independent review (blind triage). A Low or Informational submission
therefore reached final export reviewed only by the dispatch that wrote it, and the internal
`report.md` had no independent review at all.

Two ordering defects compounded this. The blind-triage blocker ran on the edge INTO `report`,
yet phase 8 is where those verdicts are produced, so a forward walk to `report` demanded
evidence that could not exist yet. The repro-rehearsal advisory printed a command the backend
refused (it lacked `proof_mode` and `verifier_dispatch_agent_id`) and reported `equivalent`,
which final export accepts, as a failure.

## Decision

Every report-writer deliverable is reviewed by a separate report-writer dispatch before final
export or publication. The reviewer only reviews; fixes go back to the writer.

- **`submission_qc_verdict`** (every severity) names `finding_slug`, the triage `packet_id`,
  `reviewer_dispatch_agent_id`, `writer_dispatch_agent_id`, `verdict` (`pass` | `blocked`) and
  `failed_rows` (`{row, quote}`; required when blocked, empty when passing). The recorder
  requires two distinct recorded report-writer dispatches, a reviewer who is neither the finding
  author, nor any dispatch recorded as editing the finding (`finding update --agent-id` lands on
  the transition), nor any dispatch that registered a version of the finding's submission
  workspace (`export submission --agent-id` attributes each render's registration), and a
  verified triage packet that belongs to the finding.
- **`report_qc_verdict`** binds the same review to the registered `report.md`: its artifact id
  and sha256, whose bytes on disk must still match the registration; the reviewer also differs
  from every agent that has registered `report.md`, and the reviewed bytes must have been
  registered with the writer's attribution (`artifact register report.md --agent-id <writer>`).
  A registration whose bytes the index kept (the file was missing) joins the producer history
  but does not become the producer of those bytes. Every `--agent-id` on `artifact register`
  and `export submission` must name a recorded dispatch; without it the registration is the
  operator's and carries no producer.
- **Gates.** Final export of an offensive engagement requires the latest submission QC verdict to
  pass on a packet matching the exported body, platform, platform fields, recipient guidance,
  attachments and program brief, rechecked at finalization like blind triage. Blue engagements
  are exempt. The web and code `complete` transitions block (`missing_submission_qc`) on any
  submittable verified finding with a registered submission whose latest QC does not pass, and,
  when `report.md` is registered (looked up by its exact path), (`missing_report_qc`) unless the
  file is present and the latest report QC passes for that artifact and its current bytes. Both
  are overridable with `--force`, which records a `forced_transition_override` decision naming
  each blocker and the `--reason` text when one is given (the reason is optional; an override
  without one is recorded as having none). On the code track they are the only `complete`
  blockers `--force` opens, because the code seal asserts coverage, not review. Blind triage
  gates web `complete` only.
- **Ordering.** Blind triage and QC are checked at `complete`, never on entry to `report`.
- **Flow.** Writer authors, renders `--draft`, runs the checklist unrecorded, builds the triage
  packet and hands back; the QC report-writer records `submission_qc_verdict`; a verifier records
  `repro_rehearsal` from a cold start, then `claim_equivalence` when pending; Medium-or-above
  findings get blind triage on the same packet; final export runs; the finding is marked
  `reported` only after final export exits 0.
- **History.** Stored `pass1_qa_verdict` rows remain readable data. New ones are refused with a
  422 naming `submission_qc_verdict`, because a self-recorded checklist verdict satisfies nothing.

## Consequences

- No submission, at any severity, is exported having been reviewed only by its writer.
- Any content change after review needs a new packet and a new QC verdict, exactly as it already
  needed a new blind-triage verdict.
- The independence check attributes dispatches; it does not prove that native clients gave the
  reviewer a separate context window (the same limit blind triage documents).
- A code-only engagement closes behind the same deliverable reviews as a web one; its Medium-or-
  above blind triage is enforced at final export, not at code `complete`.
- `content_producer_agent_id` is not backfilled: a `report.md` registered before this decision has
  no current-bytes producer, so report QC refuses it until the writer re-registers the current
  bytes with `artifact register report.md --kind report --agent-id <writer>`. Submission
  workspaces registered without `--agent-id` likewise name no writer, so only the finding author
  and editors are excluded from reviewing them until a render is attributed.
- Findings whose only checklist record is a stored `pass1_qa_verdict` row have no QC verdict:
  each needs a separate report-writer to record `submission_qc_verdict` on a current packet
  before its next final export.
- Findings delivered before this decision carry no QC verdict, so an engagement that still holds
  them as submittable reports `missing_submission_qc` at `complete`; it clears with an
  independent QC of their packets or a recorded `--force` override, ideally with a `--reason`.
- The report QC check requires report.md's current bytes to carry a producer and the reviewer not
  to be one of its producers; it does not compare the producer with `writer_dispatch_agent_id`.
- Attribution of a render without `--agent-id` reads dispatch state, not the caller: no launch
  path exports an identity into a specialist's shell, so an operator render while exactly one
  report-writer dispatch is in scope is credited to that writer. Render as the operator before
  dispatching the writer or after closing it.
