// Scoped live refresh. The engagement WebSocket names what changed
// (`type` plus `record_type`); this maps each message to the data it can make
// stale, so a refresh pass re-reads only that data. An activity note never
// re-downloads the finding ledger.
//
// Every message also refreshes Activity (the audit log records every
// mutation). A message this module does not know, a polling pass, a tab
// coming back into view, and a reconnect refresh everything: an unknown
// change must never leave a view stale.

/** A family of data a view or badge reads. */
export type LiveScope =
  | "summary"
  | "findings"
  | "readiness"
  | "proof"
  | "submissions"
  | "runs"
  | "commands"
  | "oast"
  | "coverage"
  | "surfaces"
  | "http"
  | "intel"
  | "code"
  | "activity"
  | "files";

export const ALL_LIVE_SCOPES: readonly LiveScope[] = [
  "summary", "findings", "readiness", "proof", "submissions", "runs", "commands", "oast",
  "coverage", "surfaces", "http", "intel", "code", "activity", "files",
];

const FINDING_CHANGE: readonly LiveScope[] = ["findings", "submissions", "proof", "readiness", "summary", "surfaces"];
const RUN_CHANGE: readonly LiveScope[] = ["runs", "proof", "readiness", "summary"];
const COVERAGE_CHANGE: readonly LiveScope[] = ["coverage", "surfaces", "readiness", "summary"];
const ARTIFACT_CHANGE: readonly LiveScope[] = ["files", "runs", "readiness", "summary"];
const HTTP_CHANGE: readonly LiveScope[] = ["http", "coverage", "summary"];

// `assessment.updated` record types (api/assessment.py, assessment_operator.py,
// submissions.py). An empty list refreshes only Activity: no view reads that
// record, and the audit log records it.
const ASSESSMENT_RECORD_SCOPES: Readonly<Record<string, readonly LiveScope[]>> = {
  finding: FINDING_CHANGE,
  finding_patch: FINDING_CHANGE,
  finding_merge: FINDING_CHANGE,
  finding_root_cause: FINDING_CHANGE,
  finding_verify: FINDING_CHANGE,
  finding_link: FINDING_CHANGE,
  attack_chain: ["findings", "readiness", "summary"],
  submission_version: ["submissions", "findings", "readiness"],
  sent_reply: ["submissions", "findings", "readiness"],
  submission_recovery: ["submissions", "findings", "readiness"],
  assessment_run: RUN_CHANGE,
  proof_receipt: [...RUN_CHANGE, "findings"],
  probe_run: [...RUN_CHANGE, "coverage"],
  dispatch: RUN_CHANGE,
  dispatch_decision: RUN_CHANGE,
  dispatch_handoff: RUN_CHANGE,
  operator_checkpoint: [],
  job: ["runs", "proof"],
  command_run: ["commands"],
  oob_probe: ["oast"],
  coverage_item: COVERAGE_CHANGE,
  coverage_item_bulk: COVERAGE_CHANGE,
  blocked_technique: COVERAGE_CHANGE,
  surface: ["surfaces", "http", "readiness", "summary"],
  surface_request_variant_link: ["surfaces", "http"],
  request_observation: HTTP_CHANGE,
  request_observation_bulk: HTTP_CHANGE,
  http_flow: HTTP_CHANGE,
  http_flow_import: HTTP_CHANGE,
  // Governs future captures only; the HTTP view's policy control writes it and
  // keeps the saved result itself.
  capture_policy: [],
  // Intel lists credentials; the summary counts credentials and access records.
  credential: ["intel", "summary"],
  credential_test: [],
  access_record: ["summary"],
  artifact: ARTIFACT_CHANGE,
  artifact_bulk: ARTIFACT_CHANGE,
  artifact_refresh: ARTIFACT_CHANGE,
  artifact_scratch: ARTIFACT_CHANGE,
  artifact_scratch_bulk: ARTIFACT_CHANGE,
};

// Code-review queue traffic that only moves jobs between lanes.
const CODE_QUEUE_CHURN = new Set(["queue_heartbeat", "queue_fetch", "queue_adopt_lease"]);

function withActivity(scopes: readonly LiveScope[]): LiveScope[] {
  return scopes.includes("activity") ? [...scopes] : [...scopes, "activity"];
}

/** The scopes a WebSocket message can make stale; every scope when unrecognized. */
export function scopesForMessage(message: unknown): LiveScope[] {
  if (!message || typeof message !== "object") return [...ALL_LIVE_SCOPES];
  const { type, record_type: recordType } = message as { type?: unknown; record_type?: unknown };
  const record = typeof recordType === "string" ? recordType : "";
  switch (type) {
    case "activity.updated":
      return ["activity"];
    case "event.created":
      return ["activity", "runs"];
    case "intel.updated":
      return withActivity(["intel", "readiness"]);
    case "code_analysis.updated":
      return withActivity(CODE_QUEUE_CHURN.has(record) ? ["code"] : ["code", "readiness"]);
    case "assessment.updated": {
      const scopes = ASSESSMENT_RECORD_SCOPES[record];
      return scopes ? withActivity(scopes) : [...ALL_LIVE_SCOPES];
    }
    default:
      return [...ALL_LIVE_SCOPES];
  }
}

/** For each scope, the number of the last refresh pass that touched it (0: none yet). */
export type ScopeVersions = Readonly<Record<LiveScope, number>>;

export const INITIAL_SCOPE_VERSIONS: ScopeVersions = Object.fromEntries(ALL_LIVE_SCOPES.map((scope) => [scope, 0])) as Record<LiveScope, number>;

/** Records a refresh pass (numbered after every earlier one) over the named scopes. */
export function bumpScopes(versions: ScopeVersions, scopes: Iterable<LiveScope>): ScopeVersions {
  const pass = Math.max(...Object.values(versions)) + 1;
  const next: Record<LiveScope, number> = { ...versions };
  for (const scope of scopes) next[scope] = pass;
  return next;
}

/**
 * One refresh counter for a reader of several scopes: the last pass that
 * touched any of them. It changes exactly when one of them was refreshed and
 * never goes back.
 */
export function scopeVersion(versions: ScopeVersions, scopes: readonly LiveScope[]): number {
  return scopes.reduce((latest, scope) => Math.max(latest, versions[scope]), 0);
}
