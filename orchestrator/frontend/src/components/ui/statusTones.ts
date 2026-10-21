// One status vocabulary for the operator UI: for every domain status value,
// the sentence-case label, the tone (color + glyph shape, see StatusPill) and,
// where it is not obvious, a one-line meaning. Tabs render statuses through
// <StatusPill domain value>; they do not keep their own label or color maps.
//
// Stored values are owned by the backend; each domain names its owner. A value
// a domain does not list still renders (humanized label, neutral tone) so a
// new backend value is never hidden. The listed order is the domain's urgency
// order, used for chip order and "sort by status": problems first, then work
// in flight, then work waiting its turn, with settled values last. The backend
// status sorts of the command and coverage ledgers mirror those two orders.

/**
 * What a status asks of the operator. Each tone has its own color and glyph,
 * so status never relies on hue alone.
 *
 * - `danger`   failed, blocked, exploited: something is broken or stopped
 * - `warning`  needs the operator's attention or judgment
 * - `paused`   intentionally postponed or held
 * - `progress` being worked or in flight
 * - `pending`  not started, waiting its turn
 * - `info`     settled, actionable next step (ready, downgraded)
 * - `success`  done and good
 * - `neutral`  out of play: not applicable, archived, merged, ignored
 */
export type StatusTone = "danger" | "warning" | "paused" | "progress" | "pending" | "info" | "success" | "neutral";

export type StatusEntry = { label: string; tone: StatusTone; meaning?: string };

type Vocabulary = Readonly<Record<string, StatusEntry>>;

const entry = (label: string, tone: StatusTone, meaning?: string): StatusEntry => (meaning ? { label, tone, meaning } : { label, tone });

const VOCABULARIES = {
  /** Finding workflow (`state_manager/_common.py` WorkflowStatus). */
  "finding-workflow": {
    blocked: entry("Blocked", "danger", "Work on the finding cannot continue until a blocker clears."),
    exploited: entry("Exploited", "danger", "Exploitation was demonstrated."),
    active: entry("Active", "progress", "A current finding under assessment."),
    draft: entry("Draft", "pending", "Recorded but not yet an active finding."),
    contained: entry("Contained", "paused", "The incident is contained; eradication has not finished."),
    eradicated: entry("Eradicated", "success", "The cause was removed."),
    recovered: entry("Recovered", "success", "Affected systems are back in normal operation."),
    reported: entry("Reported", "success", "Included in a delivered report."),
    false_positive: entry("False positive", "neutral", "Judged not to be a real issue; excluded from current findings."),
    merged: entry("Merged", "neutral", "Folded into another finding; excluded from current findings."),
  },
  /** Finding verification (`_common.py` VerificationStatus). */
  "finding-verification": {
    blocked: entry("Blocked", "danger", "Verification cannot proceed until a blocker clears."),
    disputed: entry("Disputed", "warning", "A verifier disagrees with the claim; it needs a decision."),
    pending_runtime_proof: entry("Pending runtime proof", "progress", "Waiting on a live proof run before a verdict."),
    unreviewed: entry("Unreviewed", "pending", "No verifier has judged the claim yet."),
    downgraded: entry("Downgraded", "info", "Confirmed at a lower severity than claimed."),
    confirmed: entry("Verified", "success", "A verifier confirmed the claim with evidence."),
    false_positive: entry("False positive", "neutral", "A verifier judged the claim not real."),
  },
  /** External-program submission (`_common.py` SubmissionStatus). */
  "finding-submission": {
    rejected: entry("Rejected", "danger"),
    needs_info: entry("Needs info", "warning", "The program asked for more information."),
    submitted: entry("Submitted", "progress", "Filed with the program; awaiting triage."),
    accepted: entry("Accepted", "success"),
    none: entry("Not submitted", "neutral"),
    duplicate: entry("Duplicate", "neutral", "The program marked it a duplicate of an earlier report."),
    withdrawn: entry("Withdrawn", "neutral", "The submission was withdrawn."),
  },
  /** Code finding's binding to the source under review (`state_manager/finding_snapshots.py` finding_code_snapshot_status). */
  "finding-source-snapshot": {
    stale: entry("Source stale", "warning", "Bound to an older repository generation than the one under review."),
    unbound: entry("Source unbound", "pending", "A file finding with no recorded binding to a repository generation."),
    current: entry("Source current", "success", "Bound to the repository generation under review."),
    not_applicable: entry("Source not applicable", "neutral", "Not tied to a source file."),
  },
  /** Assessment run ledger (`state_manager/run_accounting.py`). */
  run: {
    failed: entry("Failed", "danger"),
    interrupted: entry("Interrupted", "danger", "Stopped before it finished."),
    partial: entry("Partial", "warning", "Ended with part of its work unfinished."),
    running: entry("Running", "progress"),
    queued: entry("Queued", "pending", "Waiting to start."),
    completed: entry("Completed", "success"),
    canceled: entry("Canceled", "neutral"),
  },
  /** Run health as the Runs view derives it (`lib/runAudit.ts` runHealth). */
  "run-health": {
    failed: entry("Failed or stopped", "danger"),
    attention: entry("Needs attention", "warning", "Finished with open work: blockers, unhealthy receipts, or a partial end."),
    running: entry("Running", "progress"),
    healthy: entry("Healthy", "success", "Completed with nothing left open."),
  },
  /** Dispatch ledger (`_common.py` DispatchStatus). */
  dispatch: {
    blocked: entry("Blocked", "danger"),
    failed: entry("Failed", "danger"),
    "in-progress": entry("In progress", "progress"),
    completed: entry("Completed", "success"),
    aborted: entry("Aborted", "neutral"),
  },
  /** Background jobs (`_common.py` job status). */
  job: {
    stop_failed: entry("Stop failed", "danger", "A stop was requested and did not take effect."),
    failed: entry("Failed", "danger"),
    killed: entry("Killed", "warning", "Stopped before it finished."),
    lost: entry("Lost", "warning", "Its runner stopped reporting."),
    running: entry("Running", "progress"),
    queued: entry("Queued", "pending"),
    completed: entry("Completed", "success"),
  },
  /** Command runs (`_common.py` CommandRunStatus). */
  command: {
    failed: entry("Failed", "danger", "Finished unsuccessfully."),
    timed_out: entry("Timed out", "warning", "Stopped at its time limit."),
    killed: entry("Killed", "warning", "Stopped before it finished."),
    lost: entry("Lost", "warning", "Its runner stopped reporting."),
    running: entry("Running", "progress", "Still running."),
    queued: entry("Queued", "pending", "Waiting to start."),
    completed: entry("Completed", "success"),
  },
  /** Coverage items (`state_manager/coverage.py` CoverageStatus). */
  coverage: {
    blocked: entry("Blocked", "danger", "Can't be tested with the current access or conditions."),
    deferred: entry("Deferred", "paused", "Intentionally postponed."),
    pending: entry("Pending", "pending", "Not yet tested."),
    queued: entry("Queued", "progress", "Scheduled for a test run."),
    covered: entry("Covered", "success", "Tested."),
    not_applicable: entry("Not applicable", "neutral", "Doesn't apply to this target."),
  },
  /** Attack surfaces (`state_manager/coverage_readiness.py` SurfaceStatus; note the hyphens). */
  surface: {
    discovered: entry("Discovered", "pending", "Found; testing has not started."),
    "partially-covered": entry("Partially covered", "progress", "Some of its tests have run."),
    deferred: entry("Deferred", "paused", "Intentionally postponed."),
    covered: entry("Covered", "success", "Its tests have run."),
    not_applicable: entry("Not applicable", "neutral", "Doesn't apply to this target."),
    "administratively-closed": entry("Administratively closed", "neutral", "Closed by an operator decision rather than by testing."),
  },
  /** Intel leads (`_common.py` LeadStatus). */
  "intel-lead": {
    open: entry("Open", "pending", "Not yet followed up."),
    in_progress: entry("In progress", "progress"),
    resolved: entry("Resolved", "success"),
    ruled_out: entry("Ruled out", "neutral"),
  },
  /** CVE validation (`api/intel_schemas.py`). */
  "intel-cve": {
    exploited: entry("Exploited", "danger", "Exploitation was demonstrated against the target."),
    attempted_blocked: entry("Attempted, blocked", "danger", "An exploitation attempt was blocked."),
    poc_available_unverified: entry("PoC available, unverified", "warning", "A public proof of concept exists; not tried here."),
    version_match: entry("Version match", "warning", "The target's version is in the affected range."),
    unverified: entry("Unverified", "pending"),
    ruled_out: entry("Ruled out", "neutral"),
  },
  /** Technology confidence (`api/intel_schemas.py`). */
  "intel-confidence": {
    confirmed: entry("Confirmed", "success"),
    high: entry("High confidence", "info"),
    medium: entry("Medium confidence", "info"),
    low: entry("Low confidence", "pending"),
    "": entry("Confidence not recorded", "neutral"),
  },
  /** Host liveness (`state_manager/host_liveness.py`; `stale` is computed on read). */
  liveness: {
    blackholed: entry("Blackholed", "warning", "Requests are silently dropped."),
    stale: entry("Stale", "pending", "Last checked too long ago to trust."),
    live: entry("Live", "success"),
    dead: entry("Dead", "neutral"),
  },
  /** Credentials (`api/credentials.py` verdict and stored state). */
  credential: {
    missing: entry("Missing", "warning"),
    stale: entry("Stale", "pending"),
    unknown: entry("Unknown", "pending"),
    available: entry("Available", "success"),
    live: entry("Live", "success"),
    dead: entry("Dead", "neutral"),
  },
  /** OAST probes (`state_manager/oob.py`). */
  oast: {
    fired: entry("Callback received", "warning", "The probe's unique OAST host was contacted at least once. Review the callbacks to judge whether the target made them."),
    pending: entry("Awaiting callback", "pending", "The payload was planted and no callback has been observed yet."),
    confirmed: entry("Operator confirmed", "success", "An operator verdict that the callback came from the target."),
    expired: entry("Expired", "neutral", "Retired before any callback: the probe was minted without an OAST client binding, so a later callback could not be attributed to it."),
    ignored: entry("Ignored", "neutral", "An operator verdict that the callback is not worth pursuing."),
  },
  /** HTTP response status class (`response_status` hundreds digit); pills show the code itself. */
  "http-response": {
    "5xx": entry("Server error", "danger", "Server error"),
    "4xx": entry("Client error", "warning", "Client error: the server refused the request"),
    "1xx": entry("Informational", "pending", "Informational response"),
    "3xx": entry("Redirect", "info", "Redirect response"),
    "2xx": entry("Success", "success", "Success response"),
  },
  /** Code analysis result dispositions (`services/code_analysis.py`). */
  "code-disposition": {
    finding: entry("Finding", "danger", "The reviewer recorded a vulnerability."),
    suspicious: entry("Suspicious", "warning", "Looks risky; needs a verdict."),
    needs_context: entry("Needs context", "pending", "The reviewer could not decide without more context."),
    clean: entry("Clean", "success"),
    skipped: entry("Skipped", "neutral"),
  },
  /** Code review queue jobs (`services/code_analysis.py`). */
  "code-queue": {
    error: entry("Error", "danger"),
    needs_context: entry("Waiting on context", "paused"),
    pending: entry("Queued", "pending"),
    processing: entry("Running", "progress"),
    done: entry("Done", "success"),
  },
  /** Code file review state (`db_code_analysis_schema.py` code_files.analysis_status). */
  "code-file": {
    needs_context: entry("Waiting on context", "paused"),
    in_progress: entry("In review", "progress"),
    queued: entry("Queued", "pending"),
    classified: entry("Risk-ranked, not queued", "pending"),
    pending: entry("Not yet risk-ranked", "pending"),
    analyzed: entry("Reviewed", "success"),
  },
  /** Repository and module review state (`db_code_analysis_schema.py` code_repos.analysis_status). */
  "code-repo": {
    in_progress: entry("In review", "progress"),
    queued: entry("Queued", "pending"),
    context_built: entry("Context built", "pending"),
    classified: entry("Risk-ranked", "pending"),
    ingested: entry("Ingested", "pending"),
    analyzed: entry("Reviewed", "success"),
    complete: entry("Complete", "success"),
  },
  /** Submission desk queue state (`services/submission_versions.py` LISTING_STATES). */
  submission: {
    blocked: entry("Blocked", "danger", "Rendered, but at least one export gate fails. Open Readiness for the fix."),
    ready: entry("Ready to export", "info", "Final render passes every gate for its reviewed attachments."),
    needs_draft: entry("Needs draft", "pending", "Verified and reportable, but no submission has been rendered yet."),
    exported: entry("Exported", "progress", "The current body is already captured as an immutable version; file it on the platform."),
    filed: entry("Filed", "success", "The finding records an external submission status."),
    not_candidate: entry("Not eligible", "neutral", "Not confirmed/downgraded or not in a reportable workflow status."),
  },
  /** Submission package versions (`db.py` submission version CHECK). */
  "submission-version": {
    failed: entry("Failed", "danger"),
    staging: entry("Staged", "progress"),
    complete: entry("Complete", "success"),
  },
  /** Proof-work queue state (`state_manager/proof_work.py`). */
  "proof-work": {
    needs_approval: entry("Needs approval", "warning", "A live test waits for your explicit approval."),
    blocked: entry("Blocked", "danger", "Waiting on a prerequisite, an approval, or recovery of an ended worker."),
    stale: entry("Stale", "warning", "The finding, plan, source, or scope changed since it was prepared."),
    ready: entry("Ready to claim", "info", "Prepared and waiting for a verifier to claim it."),
    unprepared: entry("Unprepared", "pending", "No test prepared yet."),
    in_progress: entry("In progress", "progress", "A verifier owns it and is gathering evidence."),
    done: entry("Done", "success", "Finished or resolved; the verifier decides the finding."),
  },
  /** Stored proof-work status (`db_proof_work_schema.py`). */
  "proof-work-status": {
    blocked: entry("Blocked", "danger"),
    stale: entry("Stale", "warning"),
    prepared: entry("Prepared", "info"),
    claimed: entry("Claimed", "progress"),
    finished: entry("Finished", "success"),
    resolved: entry("Resolved", "success"),
  },
  /** Proof receipt evidence health (`state_manager/proofs.py`). */
  "receipt-health": {
    missing: entry("Missing", "warning", "The receipt's evidence file is gone."),
    stale: entry("Stale", "warning", "The evidence no longer matches its recorded digest."),
    tombstoned: entry("Tombstoned", "warning", "The evidence was deliberately retired."),
    healthy: entry("Healthy", "success"),
  },
  /** Engagement lifecycle (`services/engagements.py`, from scope.json). */
  engagement: {
    in_progress: entry("In progress", "progress"),
    unknown: entry("Unknown", "pending", "The lifecycle status is not recorded."),
    completed: entry("Completed", "success", "Every enabled track finished."),
    archived: entry("Archived", "neutral", "Closed out and kept for reference."),
  },
  /** Remediation cases (`services/remediation.py` TRANSITIONS). */
  remediation: {
    review: entry("In review", "warning", "Waiting for a reviewer's approval."),
    baseline: entry("Baseline", "progress", "Reproducing the issue before the fix."),
    fixing: entry("Fixing", "progress"),
    pr_draft: entry("PR draft", "progress"),
    development: entry("Development", "progress"),
    intake: entry("Intake", "pending"),
    paused: entry("Paused", "paused"),
    approved: entry("Approved", "info"),
    verified: entry("Verified", "success"),
    closed: entry("Closed", "neutral"),
  },
  /** Remediation human verification (`api/remediation.py`). */
  "remediation-verification": {
    failed: entry("Failed", "danger"),
    blocked: entry("Blocked", "danger"),
    passed: entry("Passed", "success"),
  },
} satisfies Record<string, Vocabulary>;

export type StatusDomain = keyof typeof VOCABULARIES;

/** "pending_runtime_proof" → "Pending runtime proof"; "" → "Not recorded". */
export function humanizeStatus(value: string | null | undefined): string {
  const words = (value ?? "").replace(/[_-]+/g, " ").trim();
  if (!words) return "Not recorded";
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Label, tone and meaning for a domain status; unlisted values stay visible as neutral. */
export function statusEntry(domain: StatusDomain, value: string | null | undefined): StatusEntry {
  const vocabulary: Vocabulary = VOCABULARIES[domain];
  const key = value ?? "";
  return Object.prototype.hasOwnProperty.call(vocabulary, key)
    ? vocabulary[key]
    : { label: humanizeStatus(value), tone: "neutral" };
}

export function statusLabel(domain: StatusDomain, value: string | null | undefined): string {
  return statusEntry(domain, value).label;
}

export function statusTone(domain: StatusDomain, value: string | null | undefined): StatusTone {
  return statusEntry(domain, value).tone;
}

/** The domain's values most urgent first (chip order, status sort). */
export function statusOrder(domain: StatusDomain): string[] {
  return Object.keys(VOCABULARIES[domain]);
}

/** Most-urgent-first comparator; unlisted values sort after listed ones, alphabetically. */
export function compareStatus(domain: StatusDomain, a: string | null | undefined, b: string | null | undefined): number {
  const order = statusOrder(domain);
  const rank = (value: string | null | undefined) => {
    const index = order.indexOf(value ?? "");
    return index < 0 ? order.length : index;
  };
  return rank(a) - rank(b) || (a ?? "").localeCompare(b ?? "");
}
