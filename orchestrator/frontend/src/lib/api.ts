import type { AuditBlocker, AuditPage, RunAuditSection, RunComparison } from "./runAudit";
export type { AuditBlocker, AuditPage, RunAuditSection, RunComparison } from "./runAudit";

export type Engagement = {
  id: number;
  key: string;
  engagement_type?: string | null;
  target: string;
  status: string;
  engagement_root: string;
  current_phase: string;
  code_phase?: string | null;
  track_state?: Record<string, { phase: string; complete: boolean; repair_required?: boolean }>;
  aggregate_complete?: boolean;
  exploit_policy: string;
  exploit_review_state: string;
  approved_targets: string[];
  created_at: string;
  updated_at: string;
  session_count: number;
};

export type EngagementSession = {
  id: number;
  session_id: string;
  session_path: string;
  status: string;
  merge_state: string;
  assigned_targets: string[];
  created_at: string;
  updated_at: string;
  merged_at: string | null;
};

export type EventRecord = {
  id: number;
  event_type: string;
  phase: string;
  task_name: string;
  agent_name: string;
  summary: string;
  created_at: string;
};

export type SurfaceStatus =
  | "discovered"
  | "covered"
  | "not_applicable"
  | "deferred"
  | "partially-covered"
  | "administratively-closed";

export type AssessmentSurface = {
  id: number;
  surface_type: string;
  target_descriptor: string;
  source_name: string;
  rationale: string;
  evidence_ref: string;
  status: SurfaceStatus;
  followup_condition?: string;
  updated_at: string;
  vendor_saas?: boolean;
  // The ARCHITECTURE axis, orthogonal to `surface_type`'s security meaning: how
  // the host framework discovers and runs the code. Empty for an ordinary
  // target-facing web surface, which is why it is optional here. Mirrors the
  // backend `SurfaceRecordRequest.framework_registration` literal set
  // (app/api/assessment.py) and agent/scripts/assess/lib/contracts.py.
  framework_registration?: string;
};

export type VendorSaasPendingDecision = {
  host: string;
  vendor: string;
};

export type EgressStatus = {
  blocked_pct: number;
  pattern: string;
  samples_total?: number;
  samples_blocked?: number;
  checked_at?: string | null;
};

export type AssessmentFinding = {
  slug: string;
  title: string;
  severity: string;
  workflow_status: string;
  // External-program submission state, ORTHOGONAL to workflow_status: a finding
  // can be workflow_status=reported AND submission_status=accepted at once.
  // One of: none (default) | submitted | accepted | needs_info | rejected |
  // duplicate. Typed as string to match workflow_status above.
  submission_status: string;
  verification_status: string;
  canonical_location: string;
  summary: string;
  source_name: string;
  updated_at: string;
};

export type FindingPocRequest = {
  method?: string;
  url?: string;
  headers?: Record<string, string> | string;
  body?: string;
};

export type FindingPocResponse = {
  status?: number | string;
  headers?: Record<string, string> | string;
  body?: string;
};

export type FindingReference = string | { url?: string; title?: string; id?: string };

export type FindingProvenance = {
  agent_name?: string;
  artifact_ref?: string;
  captured_at?: string;
  evidence_quote?: string;
  code_snapshot?: {
    repo_id: number;
    repo_generation: number;
    source_manifest_digest: string;
  };
  [key: string]: unknown;
};

export type FindingDetails = {
  // Core metadata already rendered today.
  discovered_by?: string;
  owasp_category?: string;
  cwe_id?: string;
  parameter?: string;
  request_method?: string;
  evidence?: string;
  kill_reason?: string;
  kill_check?: number;
  impact?: string;
  attack_scenario?: string;
  cvss_vector?: string;
  cvss_score?: number;
  remediation?: string;
  // Authored either as one block (the preferred shape — the author owns the
  // numbering, and other sections cite those numbers) or as a list of steps.
  // `toStringArray` in FindingsTab normalizes both before render.
  steps_to_reproduce?: string | string[];
  // Chain context panel.
  chain_required?: boolean;
  chain_rationale?: string;
  required_followup?: string | string[];
  block_reason?: string;
  unblock_requirements?: Record<string, unknown>;
  attempts_summary?: string;
  // Proof-of-concept panel.
  poc_code?: string;
  poc_language?: string;
  poc_request?: FindingPocRequest | string;
  poc_response?: FindingPocResponse | string;
  references?: FindingReference[];
  related_intel_ids?: Array<string | number>;
  // Code analysis panel.
  slot_type?: string;
  entry_point?: string;
  sink?: string;
  taint_path?: string | string[];
  guards_evaluated?: string | string[] | Record<string, unknown>;
  // Variant panel.
  variant_of?: string;
  original_pattern?: string;
  // Catch-all for any additional custom fields.
  [key: string]: unknown;
};

export type AssessmentFindingDetail = AssessmentFinding & {
  id: number;
  row_version: number;
  evidence_ref: string;
  evidence_artifact_id?: number | null;
  notes: string;
  defect_family: string;
  root_cause_key: string;
  auth_context: string;
  // The backend returns these PARSED, under the same names the writer used.
  // There is no `details_json` / `provenance_json` string twin: emitting both
  // would leave every reader guessing which one is authoritative.
  details: FindingDetails;
  provenance: FindingProvenance;
  code_snapshot_status?: "current" | "stale" | "unbound" | "not_applicable";
  code_snapshot_status_before?: string;
  submission_platform?: string;
  submission_ref?: string;
  submission_url?: string;
  merged_into_slug?: string | null;
  verification_audit?: AssessmentVerificationAudit;
  evidence_type?: string | null;
  proof_receipts?: AssessmentProofReceipt[];
};

export type AssessmentProofReceipt = {
  id: number;
  run_id: number;
  evidence_kind: string;
  evidence_health: string;
  created_at: string;
  evidence_ref?: string | null;
  evidence_sha256?: string | null;
  producer_dispatch_id?: number | null;
  source_read_id?: number | null;
  command_run_id?: number | null;
  artifact_id?: number | null;
  request_variant_id?: number | null;
  http_exchange_id?: number | null;
  oob_probe_id?: number | null;
  oob_event_id?: number | null;
};

export type SubmissionFindingSummary = {
  id: number;
  slug: string;
  title: string;
  severity: string;
  workflow_status: string;
  verification_status: string;
  submission_status: string;
  submission_platform: string;
  submission_ref: string;
  submission_url: string;
  row_version: number;
  version_count: number;
  latest_version_number: number | null;
  staging_version_count: number;
  failed_version_count: number;
};

export type SubmissionVersion = {
  id: number;
  finding_id: number;
  version_number: number;
  status: "complete";
  platform: "bugcrowd" | "hackerone" | "direct";
  package_format: "markdown" | "zip";
  actor_surface: "vigil-assess" | "web-ui";
  relative_path: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  submission_sha256: string;
  source_finding_row_version: number;
  source_finding_updated_at: string;
  attachment_ids: number[];
  attachment_count: number;
  artifact_id: number | null;
  created_at: string;
  completed_at: string | null;
  stale: boolean;
  idempotent_replay: boolean;
};

export type SubmissionAttachment = {
  id: number;
  relative_path: string;
  kind: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  present: boolean;
};

export type SubmissionAttachmentPage = {
  offset: number;
  limit: number;
  returned: number;
  total: number;
  has_more: boolean;
  next_offset: number | null;
};

export type SubmissionOrphanPage = {
  limit: number;
  returned: number;
  has_more: boolean;
  next_after: string | null;
};

export type SubmissionWorkspace = {
  present: boolean;
  submission_path: string;
  context_path: string;
  markdown: string;
  submission_sha256: string;
  external_body_sha256?: string;
  context: Record<string, unknown>;
  final_ready: boolean;
  blockers: string[];
};

export type SubmissionPendingVersion = {
  id: number;
  finding_slug: string;
  version_number: number;
  status: "staging" | "failed";
  failure_reason: string;
  staging_relative_path: string;
  relative_path: string;
};

export type SubmissionDetail = {
  finding: AssessmentFindingDetail;
  workspace: SubmissionWorkspace;
  eligible_attachments: SubmissionAttachment[];
  eligible_attachments_page: SubmissionAttachmentPage;
  versions: SubmissionVersion[];
  versions_page: SubmissionAttachmentPage;
  pending_version_count: number;
  pending_versions: SubmissionPendingVersion[];
  pending_versions_page: SubmissionAttachmentPage;
};

export type SubmissionListing = {
  findings: SubmissionFindingSummary[];
  findings_page: SubmissionAttachmentPage;
  staging_count: number;
  failed_count: number;
};

export type SubmissionExportInput = {
  platform: "bugcrowd" | "hackerone" | "direct";
  submission_path: string;
  context_path: string;
  attachment_ids: number[];
  actor_surface: "vigil-assess" | "web-ui";
};

export type SubmissionRecoveryResult = {
  actor_surface: "vigil-assess" | "web-ui";
  recovered_version_ids: number[];
  failed_version_ids: number[];
  failed_versions: SubmissionPendingVersion[];
  failed_versions_page: SubmissionAttachmentPage;
  orphaned_staging_paths: string[];
  orphaned_staging_page: SubmissionOrphanPage;
};

export type AssessmentFindingCounterCheck = {
  id: number;
  transition_id: number;
  verifier_dispatch_id: number;
  method: string;
  expected_result: string;
  observed_result: string;
  falsified_claim: string;
  completed: boolean;
  proof_receipt_ids: number[];
  created_at: string;
};

export type AssessmentFindingSeverityVariance = {
  id: number;
  transition_id: number;
  normal_band: string;
  chosen_severity: string;
  actor: string;
  reason: string;
  proof_receipt_id: number;
  created_at: string;
};

export type AssessmentVerificationAudit = {
  proof_receipt_ids: number[];
  proof_receipt_total: number;
  counter_checks: AssessmentFindingCounterCheck[];
  counter_check_total: number;
  severity_variances: AssessmentFindingSeverityVariance[];
  severity_variance_total: number;
  claim_review_pending?: boolean;
  claim_transition_id?: number | null;
  current_claim_sha256?: string;
  record_limit: number;
  truncated: boolean;
};

export type AssessmentConfirmCheck = {
  method: string;
  attempted_falsification: string;
  expected_result: string;
  observed_result: string;
  completed: boolean;
  proof_receipt_ids: number[];
};

export type AssessmentFindingTransition = {
  id: number;
  actor: string;
  action: string;
  from_workflow_status: string | null;
  to_workflow_status: string;
  from_verification_status: string | null;
  to_verification_status: string;
  verification_event_version: number;
  from_severity: string | null;
  to_severity: string;
  from_canonical_location?: string | null;
  to_canonical_location?: string | null;
  details_before_json?: string | null;
  details_after_json?: string | null;
  notes_before_json?: string | null;
  notes_after_json?: string | null;
  reason_code: string;
  reason_text: string;
  artifact_ref: string;
  metadata_json: string;
  created_at: string;
  verification_audit: AssessmentVerificationAudit;
};

export type AssessmentFindingTransitionSummary = Pick<
  AssessmentFindingTransition,
  | "id"
  | "actor"
  | "action"
  | "from_workflow_status"
  | "to_workflow_status"
  | "from_verification_status"
  | "to_verification_status"
  | "verification_event_version"
  | "from_severity"
  | "to_severity"
  | "from_canonical_location"
  | "to_canonical_location"
  | "reason_code"
  | "created_at"
> & {
  reason_preview: string;
  reason_word_count: number;
  reason_truncated: boolean;
  has_snapshot: boolean;
};

export type AssessmentFindingLink = {
  id: number;
  finding_slug: string;
  link_kind: string;
  target_kind: string;
  target_id?: number | null;
  target_ref: string;
  notes: string;
  provenance_json?: string;
  updated_at: string;
};

export type AssessmentFindingGroupMember = AssessmentFindingDetail & {
  root_cause_slug?: string;
  root_cause_note?: string;
  root_cause_effect?: "eliminates_finding" | "eliminates_attack_path";
  sibling_order?: number | null;
  root_cause_link_id?: number;
};

export type AssessmentFindingGroup = {
  root: AssessmentFindingDetail;
  siblings: AssessmentFindingGroupMember[];
  sibling_count: number;
  residual_path_count: number;
  highest_severity: string;
};

export type ReportReadinessBlocker = {
  kind: string;
  slug?: string;
  slugs?: string[];
  detail?: string;
};

export type PerHostOutcome = {
  met: boolean;
  evidence: string[];
  deferred: boolean;
};

export type PerHostCoverageDeferral = {
  id: number;
  kind: string;
  payload: Record<string, unknown>;
  created_at?: string | null;
};

export type PerHostCoverageHost = {
  host: string;
  outcomes: Record<string, PerHostOutcome>;
  unmet_objectives: string[];
  deferred_objectives: string[];
  deferrals: PerHostCoverageDeferral[];
};

export type PerHostCoverage = {
  objectives: string[];
  hosts: PerHostCoverageHost[];
  engagement_signals: Record<string, number | undefined>;
  // P1#3 — raw scope.json `hosts` entries (bare host / url / wildcard
  // forms preserved). Used by the Readiness panel to render a
  // scope-literals-only toggle. Empty list = backend has no scope.json
  // or the engagement is pre-migration.
  scope_hosts?: string[];
};

export type ReportReadiness = {
  ready: boolean;
  blocker_count: number;
  blockers: ReportReadinessBlocker[];
  // C58 — backend embeds the C40 per-host coverage projection here so the
  // Readiness panel renders both Definition-of-Done gates and per-host
  // outcomes from one fetch.
  per_host_coverage?: PerHostCoverage;
};

export type AssessmentProbe = {
  result_status: string;
  attack_family: string;
  signal_type: string;
  agent_name: string;
  evidence_ref: string;
  created_at: string;
};

export type AssessmentProbeDetail = AssessmentProbe & {
  id: number;
  auth_context: string;
  input_slot: string;
  payload_family: string;
  tool_name: string;
  notes: string;
  observed_http_status?: number | null;
};

export type AssessmentCoverageGap = {
  status: string;
  input_slot: string;
  attack_family: string;
  auth_context: string;
  updated_at: string;
  method?: string;
  canonical_url?: string;
  service_endpoint?: string;
};

export type AssessmentAttackChain = {
  chain_key: string;
  title: string;
  status: string;
  severity: string;
  narrative: string;
  updated_at: string;
};

export type AssessmentAttackChainDetail = AssessmentAttackChain & {
  id: number;
  evidence_ref: string;
  evidence_artifact_id?: number | null;
};

export type AssessmentAttackChainLink = {
  id: number;
  chain_key: string;
  relation: string;
  entity_kind: string;
  entity_id: number | null;
  entity_ref: string;
  notes: string;
  updated_at: string;
};

export type AssessmentServiceGap = {
  endpoint: string;
  service: string;
  coverage_status: string;
  updated_at: string;
};

export type AssessmentSummary = {
  target_count: number;
  service_count: number;
  request_variant_count: number;
  request_observation_count: number;
  coverage_count: number;
  probe_count: number;
  finding_count: number;
  // Severity rollup over the same findings counted by finding_count
  // (merged/false_positive excluded), so the donut total equals finding_count.
  // Optional to tolerate older backend payloads that predate the field.
  finding_severities?: Record<string, number>;
  open_surface_count: number;
  credential_count: number;
  access_count: number;
  pivot_count: number;
  tunnel_count: number;
  blocked_technique_count: number;
  attack_chain_count: number;
  exploit_candidate_count: number;
  coverage_blocker_count: number;
  report_blocker_count: number;
  coverage_statuses: Record<string, number>;
  finding_workflow_statuses: Record<string, number>;
  finding_verification_statuses: Record<string, number>;
  top_surfaces: AssessmentSurface[];
  top_findings: AssessmentFinding[];
  recent_probes: AssessmentProbe[];
  open_coverage_items: AssessmentCoverageGap[];
  attack_chains: AssessmentAttackChain[];
  service_coverage_gaps: AssessmentServiceGap[];
  vendor_saas_hosts_pending_decision?: VendorSaasPendingDecision[];
  egress_status?: EgressStatus;
};

export type AssessmentRunLifecycleEvent = {
  id?: number;
  from_status?: string | null;
  to_status: string;
  actor?: string;
  reason?: string;
  created_at?: string;
  [key: string]: unknown;
};

export type AssessmentRunSeal = {
  requested_status?: string;
  effective_status?: string;
  counts?: Record<string, number>;
  blockers?: AuditBlocker[];
  [key: string]: unknown;
};

export type AssessmentRun = {
  id: number;
  run_uuid: string;
  run_kind: "code" | "web" | "blue" | "shared";
  run_purpose?: string;
  status: string;
  target_identity?: Record<string, unknown>;
  source_generations?: Record<string, unknown>[];
  exclusions?: Record<string, unknown>[];
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  updated_at?: string;
  producer_dispatch_id?: number;
  producer_dispatch_agent_id?: string;
  producer_dispatch_agent_role?: string;
  requested_model?: string;
  actual_model?: string;
  requested_reasoning?: string;
  actual_reasoning?: string;
  launcher_effective_model?: string | null;
  launcher_effective_reasoning?: string | null;
  launcher_effective_source?: string | null;
  client_name?: string;
  requested_client?: string;
  launcher_effective_client?: string;
  provider_observed_client?: string;
  source_revision?: string;
  operator_instruction_path?: string;
  operator_instruction_sha256?: string;
  specialist_instruction_path?: string;
  specialist_instruction_sha256?: string;
  instruction_identity_status?: string;
  instructions_stale?: boolean | null;
  counts?: Record<string, number>;
  proof_health?: Record<string, number | string | boolean | null>;
  lifecycle_history?: AssessmentRunLifecycleEvent[];
  seal?: AssessmentRunSeal | null;
  blockers?: AuditBlocker[];
  seal_sha256?: string | null;
  observed_cost?: number | null;
  finding_slugs?: string[];
  warnings?: string[];
  resumed_from_run_id?: number | null;
};

export type AssessmentRunChild = {
  id?: number | string;
  [key: string]: unknown;
};

export type Artifact = {
  name: string;
  relative_path: string;
  media_type: string;
  exists: boolean;
};

export type ArtifactContent = Artifact & {
  content: string;
};

function appBaseUrl(): URL {
  const pathname = window.location.pathname.endsWith("/")
    ? window.location.pathname
    : `${window.location.pathname}/`;
  return new URL(pathname, window.location.origin);
}

function resolveAppUrl(path: string): string {
  const relativePath = path.replace(/^\/+/, "");
  return new URL(relativePath, appBaseUrl()).toString();
}

// FastAPI / Pydantic shape for a single 422 entry:
//   { loc: ["body", "payload", "reason"], msg: "Field required", type: "..." }
// We pretty-print these into a human-readable list rather than dumping
// the raw JSON, so operators hitting a backend validation error (e.g.
// the FU2 coverage_deferral validator) get an actionable message
// instead of an unreadable [object Object]-style blob.
type PydanticErrorEntry = {
  loc?: unknown;
  msg?: unknown;
  type?: unknown;
};

function isPydanticErrorList(value: unknown): value is PydanticErrorEntry[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (entry) =>
        entry !== null &&
        typeof entry === "object" &&
        "msg" in (entry as Record<string, unknown>),
    )
  );
}

function formatPydanticErrors(entries: PydanticErrorEntry[]): string {
  const lines = entries.map((entry) => {
    const locParts = Array.isArray(entry.loc)
      ? (entry.loc as unknown[])
          // The first segment is conventionally "body" / "query" / "path"
          // / "header" — useful when debugging but noise for end users.
          .filter((segment, idx) => idx > 0 || segment !== "body")
          .map((segment) => String(segment))
      : [];
    const path = locParts.length ? locParts.join(".") : "request";
    const msg = typeof entry.msg === "string" ? entry.msg : "validation error";
    return `${path}: ${msg}`;
  });
  return lines.join("\n");
}

// Error thrown by request() on a non-ok response. Extends Error (so existing
// `error instanceof Error` / `error.message` callers keep working unchanged)
// and additionally exposes the HTTP `status` and the parsed JSON `body`, so
// callers can branch on the numeric status instead of regexing the message.
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// Reads a non-ok response once, returning both the human-readable message and
// the parsed JSON body (or undefined if the body was empty / not JSON).
async function readError(response: Response): Promise<{ message: string; body: unknown }> {
  const text = await response.text();
  if (!text) {
    return { message: `Request failed: ${response.status}`, body: undefined };
  }

  try {
    const payload = JSON.parse(text) as { detail?: unknown };
    if (typeof payload.detail === "string") {
      return { message: payload.detail, body: payload };
    }
    if (isPydanticErrorList(payload.detail)) {
      return { message: formatPydanticErrors(payload.detail), body: payload };
    }
    return { message: text, body: payload };
  } catch {
    // Fall back to raw body.
  }

  return { message: text, body: undefined };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(resolveAppUrl(path), { ...init, headers });
  if (!response.ok) {
    const { message, body } = await readError(response);
    throw new ApiError(message, response.status, body);
  }
  return response.json() as Promise<T>;
}

export function listEngagements() {
  return request<Engagement[]>("/engagements");
}

export function getEngagement(engagementKey: string) {
  return request<Engagement>(`/engagements/${engagementKey}`);
}

export type RemediationEvidence = {
  id: number;
  kind: string;
  method: string;
  environment: string | null;
  outcome?: string | null;
  command: string;
  observed: string;
  proved: string;
  artifact_path: string | null;
  artifact_sha256: string | null;
  created_at?: string;
  revision?: string | null;
  execution?: "executed" | "reasoned" | "unavailable" | null;
  executed_revision?: string | null;
  executed_directory?: string | null;
  shared_environment?: string | null;
  runtime_revision?: string | null;
};

export type RemediationCase = {
  id: number;
  source_type: string;
  source_key: string;
  title: string;
  status: string;
  snapshot: Record<string, unknown>;
  linked_findings: LinkedRemediationFinding[];
  duplicate_hints: number[];
  duplicate_hint_details?: Array<{ case_id: number; reasons: string[] }>;
  worktree_path: string | null;
  worktree_branch?: string | null;
  worktree_revision: string | null;
  base_branch?: string | null;
  base_revision?: string | null;
  source_resolved?: boolean;
  review_policy?: Record<string, unknown> | null;
  verification_requirements?: {
    requirements: Array<{ kind: string; methods: string[]; outcome: string; revision: "current" | "ancestor"; execution: "executed" | "reasoned"; rationale: string; shared_environment?: string | null; runtime_identity_required?: boolean; browser_purpose?: "happy-path" | "bad-path" | "other" | null; legitimate_use_control?: boolean }>;
    alternatives_reason: string;
  } | null;
  verification_plan: string;
  baseline: Partial<RemediationBaseline>;
  release_plan: Partial<RemediationReleasePlan>;
  evidence: RemediationEvidence[];
  approvals: Array<Record<string, unknown>>;
  transitions: Array<Record<string, unknown>>;
  human_verifications: Array<{ id: number; deployment_id: number; actor: string; result: "passed" | "failed" | "blocked"; observed_revision: string; notes: string; created_at?: string }>;
  deployment: { environment: string; workflow: string; run_id: string; expected_revision: string; observed_revision: string } | null;
  approval_current: boolean;
  review_evidence_ready: boolean;
  review_evidence_missing: string[];
  review_digest: string;
};

export type RemediationBaseline = {
  outcome: "runtime_reproduced" | "code_test_confirmed" | "unreproduced";
  method: string;
  proved: string;
  owner_decision?: "proceed" | "pause" | null;
  owner_actor?: string | null;
  owner_reason?: string | null;
};

export type RemediationReleasePlan = {
  production_canary_decision: "required" | "not_required" | "defer";
  production_canary_rationale: string;
  safe_procedure: string;
  monitoring?: string;
};

export type LinkedRemediationFinding = {
  id: number;
  engagement_key: string;
  slug: string;
  title: string;
  severity: string;
  verification_status: string;
  root_cause_key: string | null;
};

export type RemediationCaseSummary = Pick<RemediationCase, "id" | "source_type" | "source_key" | "title" | "status" | "linked_findings"> & {
  duplicate_hints: number[];
  duplicate_hint_details?: Array<{ case_id: number; reasons: string[] }>;
  worktree_revision?: string | null;
  baseline_outcome?: string | null;
  approval_recorded?: boolean;
};

export type FindingRemediationSummary = {
  id: number;
  engagement_key: string;
  title: string;
  status: string;
  worktree_path: string | null;
  worktree_branch: string | null;
  worktree_revision: string | null;
  latest_deployment: RemediationCase["deployment"];
  linked_findings: LinkedRemediationFinding[];
};

function remediationBase(engagementKey: string): string {
  return `/engagements/${encodeURIComponent(engagementKey)}/remediation`;
}

export function getFindingRemediationCases(engagementKey: string, slug: string) {
  return request<FindingRemediationSummary[]>(`${remediationBase(engagementKey)}/findings/${encodeURIComponent(slug)}/cases`);
}

export function createRemediationFromFinding(engagementKey: string, slug: string, input: { remediation_engagement_key: string; title?: string }) {
  return request<RemediationCase & { engagement_key: string }>(`${remediationBase(engagementKey)}/findings/${encodeURIComponent(slug)}/cases`, { method: "POST", body: JSON.stringify(input) });
}

export function listRemediationCases(engagementKey: string) {
  return request<RemediationCaseSummary[]>(`${remediationBase(engagementKey)}/cases`);
}

export function getRemediationCase(engagementKey: string, caseId: number) {
  return request<RemediationCase>(`${remediationBase(engagementKey)}/cases/${caseId}`);
}

export function updateRemediationFindings(engagementKey: string, caseId: number, findingIds: number[]) {
  return request<RemediationCase>(`${remediationBase(engagementKey)}/cases/${caseId}`, { method: "PATCH", body: JSON.stringify({ finding_ids: findingIds }) });
}

export type RemediationDiff = {
  text: string;
  truncated: boolean;
  bytes_total: number;
  base_revision: string;
  head_revision: string;
  review_digest: string;
};

export function getRemediationDiff(engagementKey: string, caseId: number) {
  return request<RemediationDiff>(`${remediationBase(engagementKey)}/cases/${caseId}/diff`);
}

export function updateRemediationVerificationPlan(engagementKey: string, caseId: number, verificationPlan: string) {
  return request<RemediationCase>(`${remediationBase(engagementKey)}/cases/${caseId}/verification-plan`, {
    method: "PATCH",
    body: JSON.stringify({ verification_plan: verificationPlan }),
  });
}

export function updateRemediationBaseline(engagementKey: string, caseId: number, baseline: RemediationBaseline) {
  return request<RemediationCase>(`${remediationBase(engagementKey)}/cases/${caseId}/baseline`, {
    method: "PATCH",
    body: JSON.stringify(baseline),
  });
}

export function updateRemediationReleasePlan(engagementKey: string, caseId: number, releasePlan: RemediationReleasePlan) {
  return request<RemediationCase>(`${remediationBase(engagementKey)}/cases/${caseId}/release-plan`, {
    method: "PATCH",
    body: JSON.stringify(releasePlan),
  });
}

export function approveRemediationCase(engagementKey: string, caseId: number, reviewer: string, expectedReviewDigest: string, approvalMethod: "ui" | "cli_instruction") {
  return request<{ id: number; reviewer: string; review_digest: string }>(`${remediationBase(engagementKey)}/cases/${caseId}/approve`, {
    method: "POST",
    body: JSON.stringify({ reviewer, expected_review_digest: expectedReviewDigest, approval_method: approvalMethod }),
  });
}

export type RemediationHumanVerificationInput = {
  actor: string;
  result: "passed" | "failed" | "blocked";
  observed_revision: string;
  notes: string;
};

export function recordRemediationHumanVerification(engagementKey: string, caseId: number, input: RemediationHumanVerificationInput) {
  return request<{ id: number; actor: string; result: RemediationHumanVerificationInput["result"]; observed_revision: string; notes: string }>(`${remediationBase(engagementKey)}/cases/${caseId}/human-verification`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function remediationEvidenceFileUrl(engagementKey: string, caseId: number, evidenceId: number): string {
  return resolveAppUrl(`${remediationBase(engagementKey)}/cases/${caseId}/evidence/${evidenceId}/file`);
}

// ── Cross-engagement dashboard summary ──────────────────
// Mirrors DashboardSummaryResponse in orchestrator/backend/app/api/dashboard.py.
// Read-only aggregate across ALL engagements in the single DB. Optional on the
// caller side: an older backend without /dashboard/summary 404s, so the landing
// page must tolerate the fetch failing and hide the dashboard sections.

export type DashboardEngagementCounts = {
  total: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  by_phase: Record<string, number>;
};

export type DashboardFindingTotals = {
  total: number;
  by_severity: Record<string, number>;
};

export type DashboardEngagement = {
  key: string;
  target: string;
  status: string;
  current_phase: string;
  engagement_type: string | null;
  customer: string | null;
  updated_at: string;
  finding_count: number;
  finding_severities: Record<string, number>;
};

export type DashboardActivity = {
  id: number;
  engagement_key: string;
  actor_kind: string;
  actor_name: string;
  title: string;
  action: string;
  result: string;
  occurred_at: string;
  created_at: string;
};

export type DashboardSummary = {
  engagement_counts: DashboardEngagementCounts;
  finding_totals: DashboardFindingTotals;
  engagements: DashboardEngagement[];
  recent_activity: DashboardActivity[];
};

export function getDashboardSummary() {
  return request<DashboardSummary>("/dashboard/summary");
}

export function deleteEngagement(engagementKey: string) {
  const qs = new URLSearchParams({ confirm: engagementKey }).toString();
  return request<{ deleted: boolean; key: string; id: number }>(
    `/engagements/${encodeURIComponent(engagementKey)}?${qs}`,
    { method: "DELETE" },
  );
}

export function listEngagementSessions(engagementKey: string) {
  return request<EngagementSession[]>(`/engagements/${engagementKey}/sessions`);
}

export function listEvents(engagementKey: string, limit = 200) {
  const query = new URLSearchParams({ limit: String(limit) });
  return request<EventRecord[]>(`/engagements/${engagementKey}/events?${query.toString()}`);
}

export function getAssessmentSummary(engagementKey: string) {
  return request<AssessmentSummary>(`/engagements/${engagementKey}/assessment/summary`);
}

function assessmentRunsPath(engagementKey: string): string {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/assessment-runs`;
}

export function listAssessmentRuns(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const suffix = query.size ? `?${query.toString()}` : "";
  return request<AssessmentRun[]>(`${assessmentRunsPath(engagementKey)}${suffix}`);
}

export function getAssessmentRun(engagementKey: string, runId: number) {
  return request<AssessmentRun>(`${assessmentRunsPath(engagementKey)}/${runId}`);
}

export function listAssessmentRunChildren(
  engagementKey: string,
  runId: number,
  section: RunAuditSection,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const suffix = query.size ? `?${query.toString()}` : "";
  return request<AuditPage<AssessmentRunChild>>(
    `${assessmentRunsPath(engagementKey)}/${runId}/${section}${suffix}`,
  );
}

export function getAssessmentRunComparison(
  engagementKey: string,
  runId: number,
  baselineRunId?: number,
) {
  const query = new URLSearchParams();
  if (baselineRunId != null) query.set("baseline_run_id", String(baselineRunId));
  const suffix = query.size ? `?${query.toString()}` : "";
  return request<RunComparison>(
    `${assessmentRunsPath(engagementKey)}/${runId}/comparison${suffix}`,
  );
}

export function getReportReadiness(engagementKey: string) {
  return request<ReportReadiness>(`/engagements/${engagementKey}/assessment/report-readiness`);
}

export function listAssessmentSurfaces(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<AssessmentSurface[]>(
    `/engagements/${engagementKey}/assessment/surfaces${qs ? `?${qs}` : ""}`,
  );
}

export type SurfaceRequestVariantLink = {
  id: number;
  engagement_id: number;
  surface_id: number;
  request_variant_id: number;
  relation: string;
  evidence_ref: string;
  created_at: string;
  updated_at: string;
};

export function listSurfaceRequestVariantLinks(engagementKey: string, surfaceId: number) {
  return request<SurfaceRequestVariantLink[]>(
    `/engagements/${engagementKey}/assessment/surface-request-variant-links/by-surface/${surfaceId}`,
  );
}

export function listAssessmentFindings(engagementKey: string) {
  return request<AssessmentFindingDetail[]>(`/engagements/${engagementKey}/assessment/findings`);
}

export function getAssessmentFinding(engagementKey: string, findingSlug: string) {
  return request<AssessmentFindingDetail>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/findings/${encodeURIComponent(findingSlug)}`,
  );
}

export function listSubmissions(
  engagementKey: string,
  params: { findingOffset?: number; findingLimit?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.findingOffset != null) query.set("finding_offset", String(params.findingOffset));
  if (params.findingLimit != null) query.set("finding_limit", String(params.findingLimit));
  const qs = query.toString();
  return request<SubmissionListing>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions${qs ? `?${qs}` : ""}`,
  );
}

export function getSubmissionDetail(
  engagementKey: string,
  findingSlug: string,
  params: {
    attachmentOffset?: number;
    attachmentLimit?: number;
    versionOffset?: number;
    versionLimit?: number;
    pendingVersionOffset?: number;
    pendingVersionLimit?: number;
    selectedAttachmentIds?: number[];
  } = {},
) {
  const query = new URLSearchParams();
  if (params.attachmentOffset != null) {
    query.set("attachment_offset", String(params.attachmentOffset));
  }
  if (params.attachmentLimit != null) {
    query.set("attachment_limit", String(params.attachmentLimit));
  }
  if (params.versionOffset != null) query.set("version_offset", String(params.versionOffset));
  if (params.versionLimit != null) query.set("version_limit", String(params.versionLimit));
  if (params.pendingVersionOffset != null) {
    query.set("pending_version_offset", String(params.pendingVersionOffset));
  }
  if (params.pendingVersionLimit != null) {
    query.set("pending_version_limit", String(params.pendingVersionLimit));
  }
  for (const attachmentId of params.selectedAttachmentIds ?? []) {
    query.append("attachment_id", String(attachmentId));
  }
  const qs = query.toString();
  return request<SubmissionDetail>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions/` +
      `${encodeURIComponent(findingSlug)}${qs ? `?${qs}` : ""}`,
  );
}

export function exportSubmissionVersion(
  engagementKey: string,
  findingSlug: string,
  input: SubmissionExportInput,
) {
  return request<SubmissionVersion>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions/` +
      `${encodeURIComponent(findingSlug)}/exports`,
    { method: "POST", body: JSON.stringify(input) },
  );
}

export function recoverSubmissionExports(
  engagementKey: string,
  actorSurface: "vigil-assess" | "web-ui",
  params: {
    failedVersionOffset?: number;
    failedVersionLimit?: number;
    orphanAfter?: string;
    orphanLimit?: number;
  } = {},
) {
  return request<SubmissionRecoveryResult>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions/recover`,
    {
      method: "POST",
      body: JSON.stringify({
        actor_surface: actorSurface,
        ...(params.failedVersionOffset != null
          ? { failed_version_offset: params.failedVersionOffset }
          : {}),
        ...(params.failedVersionLimit != null
          ? { failed_version_limit: params.failedVersionLimit }
          : {}),
        ...(params.orphanAfter != null ? { orphan_after: params.orphanAfter } : {}),
        ...(params.orphanLimit != null ? { orphan_limit: params.orphanLimit } : {}),
      }),
    },
  );
}

export function submissionVersionDownloadUrl(
  engagementKey: string,
  findingSlug: string,
  versionNumber: number,
) {
  return resolveAppUrl(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions/` +
      `${encodeURIComponent(findingSlug)}/versions/${versionNumber}/download`,
  );
}

const FINDING_HISTORY_PAGE_SIZE = 500;

export async function listAssessmentFindingTransitions(
  engagementKey: string,
  findingSlug: string,
) {
  const transitions: AssessmentFindingTransitionSummary[] = [];
  let offset = 0;
  while (true) {
    const page = await request<AssessmentFindingTransitionSummary[]>(
      `/engagements/${engagementKey}/assessment/findings/${encodeURIComponent(findingSlug)}` +
        `/transitions?projection=summary&limit=${FINDING_HISTORY_PAGE_SIZE}&offset=${offset}`,
    );
    transitions.push(...page);
    if (page.length < FINDING_HISTORY_PAGE_SIZE) return transitions;
    offset += page.length;
  }
}

export function getAssessmentFindingTransition(
  engagementKey: string,
  findingSlug: string,
  transitionId: number,
) {
  return request<AssessmentFindingTransition>(
    `/engagements/${engagementKey}/assessment/findings/${encodeURIComponent(findingSlug)}` +
      `/transitions/${transitionId}`,
  );
}

export function listAssessmentFindingLinks(engagementKey: string) {
  return request<AssessmentFindingLink[]>(`/engagements/${engagementKey}/assessment/finding-links`);
}

export function listAssessmentFindingGroups(engagementKey: string) {
  return request<AssessmentFindingGroup[]>(`/engagements/${engagementKey}/assessment/finding-groups`);
}

export function listAssessmentProbes(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<AssessmentProbeDetail[]>(
    `/engagements/${engagementKey}/assessment/probe-runs${qs ? `?${qs}` : ""}`,
  );
}

export function listAssessmentAttackChains(engagementKey: string) {
  return request<AssessmentAttackChainDetail[]>(`/engagements/${engagementKey}/assessment/attack-chains`);
}

export function listAssessmentAttackChainLinks(engagementKey: string) {
  return request<AssessmentAttackChainLink[]>(`/engagements/${engagementKey}/assessment/attack-chain-links`);
}

export function listArtifacts(engagementKey: string) {
  return request<Artifact[]>(`/engagements/${engagementKey}/artifacts`);
}

export function readArtifact(engagementKey: string, artifactName: string) {
  return request<ArtifactContent>(`/engagements/${engagementKey}/artifacts/${artifactName}`);
}

// ── Single-file report export ───────────────────────────

export type ReportExportMode = "draft" | "final";

export type ReportExportResult = {
  artifact_id: number;
  relative_path: string;
  mode: ReportExportMode;
  size_bytes: number;
};

// Generate a single-file HTML report and register it as an engagement
// artifact. mode=final enforces the same report-readiness gate as
// report-findings and returns 409 (readiness payload as the error) when the
// engagement is not ready.
export function exportReport(engagementKey: string, mode: ReportExportMode = "draft") {
  return request<ReportExportResult>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/report-export`,
    { method: "POST", body: JSON.stringify({ mode }) },
  );
}

// Absolute, app-relative URL for the report download route. Used to point a
// hidden <a download> at the file so the browser saves it directly (the
// endpoint serves Content-Disposition: attachment).
export function reportDownloadUrl(engagementKey: string, artifactId: number): string {
  return resolveAppUrl(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/report-export/${artifactId}/download`,
  );
}

// ── Coverage & discovery types ──────────────────────────

export type AssessmentTarget = {
  id: number;
  identity: string;
  kind: string;
  host: string;
  ip_address: string | null;
  hostname: string | null;
  notes: string;
  discovered_by: string;
  created_at: string;
  updated_at: string;
  vendor_saas?: boolean;
};

export type AssessmentService = {
  id: number;
  target_id: number;
  endpoint: string;
  port: number | null;
  protocol: string;
  service: string;
  state: string;
  coverage_status: string;
  banner: string;
  notes: string;
  discovered_by: string;
  created_at: string;
  updated_at: string;
};

export type AssessmentCoverageItem = {
  id: number;
  request_variant_id: number | null;
  service_id: number | null;
  auth_context: string;
  input_slot: string;
  attack_family: string;
  status: string;
  notes: string;
  created_at: string;
  updated_at: string;
  method: string | null;
  canonical_url: string | null;
  service_endpoint: string | null;
  service_name: string | null;
};

export function listAssessmentTargets(engagementKey: string) {
  return request<AssessmentTarget[]>(`/engagements/${engagementKey}/assessment/targets`);
}

export function listAssessmentServices(engagementKey: string) {
  return request<AssessmentService[]>(`/engagements/${engagementKey}/assessment/services`);
}

export function listAssessmentCoverageItems(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<AssessmentCoverageItem[]>(
    `/engagements/${engagementKey}/assessment/coverage-items${qs ? `?${qs}` : ""}`,
  );
}

// ── Assessment command runs ─────────────────────────────
// Schema mirrors `assessment_command_runs` + `_serialize_command_run` in the
// backend: list rows elide the preview text (preview_chars counts + hashes
// remain so callers can decide whether to request the detail endpoint with
// full output).
export type CommandRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "timed_out"
  | "killed"
  | "lost";

export type AssessmentCommandRun = {
  id: number;
  engagement_id: number;
  run_uuid: string;
  command: string;
  argv: string[];
  tool_name: string;
  tool_bin: string;
  route: string;
  agent_name: string;
  phase: string;
  audit_source: string;
  status: CommandRunStatus;
  return_code: number | null;
  timed_out: boolean;
  success: boolean;
  started_at: string;
  completed_at: string;
  output_recovery_observed_at: string | null;
  duration_ms: number;
  command_hash: string;
  stdout_sha256: string;
  stderr_sha256: string;
  stdout_preview: string;
  stderr_preview: string;
  // Listings: always "" with preview_chars populated. Detail: full text.
  stdout_preview_chars?: number;
  stderr_preview_chars?: number;
  output_retention_status: string; // retained | artifact | suppressed | suppression_pending | suppression_deferred | preview_only | partially_measured | measurement_conflict | unmeasured | untrusted | integrity_failure | empty
  output_cleanup_status: string;
  output_cleanup_warning: string;
  output_integrity_status: string;
  output_integrity_warning: string;
  stdout_suppression_reason: string;
  stderr_suppression_reason: string;
  stdout_artifact_ref: string;
  stderr_artifact_ref: string;
  stdout_bytes: number;
  stderr_bytes: number;
  stdout_spill_device?: number | null;
  stdout_spill_inode?: number | null;
  stderr_spill_device?: number | null;
  stderr_spill_inode?: number | null;
  indexed_for_embeddings_at: string | null;
  notes: string;
  created_at: string;
  working_dir?: string | null;
  scope_version?: string | null;
  auth_context?: string | null;
  target_host?: string;
  superseded_by_id?: number | null;
  timeout_seconds_requested?: number | null;
  partial_results?: boolean;
  finding_id?: number | null;
  finding_slug?: string | null;
  // Command-metadata audit fields. All nullable — pre-migration rows
  // and calls that don't set the X-* headers land as null.
  technique?: string | null;
  intent?: string | null;
  probe_kind?: string | null;
  destructive?: boolean | null;
};

// Detail fetch returns the retained preview text (include_output=true server-side).
// Artifact refs remain the authority for output that spilled beyond that preview.
export type AssessmentCommandRunDetail = AssessmentCommandRun;

export type ListAssessmentCommandRunsParams = {
  q?: string;
  agent_name?: string;
  phase?: string;
  tool_name?: string;
  tool_bin?: string;
  audit_source?: string;
  // Backend currently only exposes success + timed_out (no `failed` param).
  // Rows where success=false && !timed_out are the "failed" bucket;
  // consumers derive that client-side.
  success?: boolean;
  timed_out?: boolean;
  // Command-metadata filter axes. Technique + probe_kind are exact matches.
  // intent_q runs an FTS5-scoped `intent:` match server-side. destructive
  // is a tri-state: undefined = don't filter; true/false = exact match.
  technique?: string;
  probe_kind?: string;
  destructive?: boolean;
  intent_q?: string;
  include_output?: boolean;
  limit?: number;
  offset?: number;
};

export function listAssessmentCommandRuns(
  engagementKey: string,
  params: ListAssessmentCommandRunsParams = {},
) {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.agent_name) query.set("agent_name", params.agent_name);
  if (params.phase) query.set("phase", params.phase);
  if (params.tool_name) query.set("tool_name", params.tool_name);
  if (params.tool_bin) query.set("tool_bin", params.tool_bin);
  if (params.audit_source) query.set("audit_source", params.audit_source);
  if (params.success != null) query.set("success", params.success ? "true" : "false");
  if (params.timed_out != null) query.set("timed_out", params.timed_out ? "true" : "false");
  if (params.technique) query.set("technique", params.technique);
  if (params.probe_kind) query.set("probe_kind", params.probe_kind);
  if (params.destructive != null)
    query.set("destructive", params.destructive ? "true" : "false");
  if (params.intent_q) query.set("intent_q", params.intent_q);
  if (params.include_output) query.set("include_output", "true");
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<AssessmentCommandRun[]>(
    `/engagements/${engagementKey}/assessment/command-runs${qs ? `?${qs}` : ""}`,
  );
}

export function getAssessmentCommandRun(engagementKey: string, commandRunId: number) {
  return request<AssessmentCommandRunDetail>(
    `/engagements/${engagementKey}/assessment/command-runs/${commandRunId}`,
  );
}

// ── HTTP traffic types ──────────────────────────────────
// Mirrors `assessment_request_variants` / `assessment_request_observations`
// in orchestrator/backend/app/db.py. The list endpoints return raw row
// dicts (state_manager.list_request_variants / list_request_observations);
// the schema_json fields are JSON-encoded strings the frontend parses for
// pretty display. All read-only — no mutation routes exist for these.

export type RequestVariant = {
  id: number;
  engagement_id: number;
  auth_context: string;
  scheme: string;
  host: string;
  port: number;
  method: string;
  normalized_path: string;
  path_template: string;
  canonical_url: string;
  content_type_family: string;
  query_schema_json: string;
  body_schema_json: string;
  path_schema_json: string;
  cookie_schema_json: string;
  header_schema_json: string;
  params_schema_hash: string;
  body_schema_hash: string;
  discovery_source: string;
  notes: string;
  first_seen_at: string;
  last_seen_at: string;
};

export type RequestObservation = {
  id: number;
  engagement_id: number;
  request_variant_id: number;
  observed_url: string;
  source_name: string;
  response_status: number | null;
  evidence_ref: string;
  raw_payload: string;
  created_at: string;
};

export function listRequestVariants(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<RequestVariant[]>(
    `/engagements/${engagementKey}/assessment/request-variants${qs ? `?${qs}` : ""}`,
  );
}

export function listRequestObservations(
  engagementKey: string,
  params: { limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<RequestObservation[]>(
    `/engagements/${engagementKey}/assessment/request-observations${qs ? `?${qs}` : ""}`,
  );
}

// ── OAST (out-of-band) types ────────────────────────────
// Mirrors `assessment_oob_probes` / `assessment_oob_interactions` in
// orchestrator/backend/app/db.py. The list endpoint embeds a derived
// `interaction_count` + `last_interaction_at` per probe (LEFT JOIN rollup);
// the detail endpoint (by nonce) additionally returns the full
// `interactions[]` history. Read-only — `vigil oob mint`/`poll` own writes.

export type OobProbe = {
  id: number;
  engagement_id: number;
  nonce: string;
  target_url: string;
  param: string;
  technique: string;
  probe_kind: string;
  request_hash: string;
  oob_domain: string;
  client_name: string;
  client_payload_host: string;
  notes: string;
  status: string; // pending | fired | confirmed | expired | ignored
  created_at: string;
  updated_at: string;
  // Derived by list_oob_probes (not stored). Detail-by-nonce omits these.
  interaction_count?: number;
  last_interaction_at?: string;
};

export type OobInteraction = {
  id: number;
  engagement_id: number;
  probe_id: number;
  protocol: string;
  remote_address: string;
  query_type: string;
  raw_request: string;
  interaction_hash: string;
  observed_at: string;
  created_at: string;
};

export type OobProbeDetail = OobProbe & {
  interactions: OobInteraction[];
};

export function listOobProbes(engagementKey: string, status?: string) {
  const qs = status ? `?${new URLSearchParams({ status }).toString()}` : "";
  return request<OobProbe[]>(
    `/engagements/${engagementKey}/assessment/oob-probes${qs}`,
  );
}

export function getOobProbe(engagementKey: string, nonce: string) {
  return request<OobProbeDetail>(
    `/engagements/${engagementKey}/assessment/oob-probes/${encodeURIComponent(nonce)}`,
  );
}

// ── Phase-5 canonical HTTP flows ────────────────────────
// Mirrors `assessment_http_flows` in orchestrator/backend/app/db.py and the
// GET /http-flows serializer: header maps are parsed to objects and the
// *_truncated / host_mismatch INTEGER columns come back as booleans. Raw
// bodies are NOT inlined here — they live as engagement-local artifacts
// (request_body_artifact_path / response_body_artifact_path) and are only
// materialised through the HAR export. The row therefore carries body
// *metadata* (sha256 / byte size / truncation flag) which the flow drawer
// renders as the body "preview".
export type HttpFlow = {
  id: number;
  engagement_id: number;
  request_variant_id: number | null;
  flow_uid: string;
  method: string;
  scheme: string;
  host: string;
  port: number | null;
  url: string;
  path: string;
  response_status: number | null;
  request_content_type: string;
  response_content_type: string;
  content_type_family: string;
  auth_context: string;
  request_body_sha256: string;
  response_body_sha256: string;
  request_body_bytes: number;
  response_body_bytes: number;
  request_body_truncated: boolean;
  response_body_truncated: boolean;
  request_body_capture_status: string;
  response_body_capture_status: string;
  request_body_capture_error: string;
  response_body_capture_error: string;
  request_body_artifact_path: string | null;
  response_body_artifact_path: string | null;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  host_mismatch: boolean;
  url_authority: string;
  host_header: string;
  sni: string;
  timing_ms: number | null;
  started_at: string;
  created_at: string;
};

// Server-side filter axes for GET /http-flows + GET /http-flows/export-har.
// Names are kept 1:1 with the backend query params. `truncated` matches a
// flow truncated on EITHER side; `q` is a LIKE substring over url/path/host.
export type HttpFlowFilters = {
  flow_uid?: string;
  host?: string;
  method?: string;
  response_status?: number;
  content_type_family?: string;
  auth_context?: string;
  truncated?: boolean;
  q?: string;
  limit?: number;
  offset?: number;
};

// Per-engagement capture policy. Raw-body capture is OFF by default (the
// backend returns this shape from GET /capture-policy even when unset, and
// embeds the same object on each /engagements list row). content_type_allow /
// content_type_deny are the serialized forms of the *_json columns.
export type CapturePolicy = {
  enabled: boolean;
  capture_request_bodies: boolean;
  capture_response_bodies: boolean;
  max_body_bytes: number;
  content_type_allow: string[];
  content_type_deny: string[];
  retention: "until_engagement_deletion";
};

// PUT /capture-policy takes an all-optional partial (extra=forbid server-side),
// so keep the update payload strictly to known keys.
export type CapturePolicyUpdate = Partial<Omit<CapturePolicy, "retention">>;

function httpFlowParams(filters: HttpFlowFilters): URLSearchParams {
  const query = new URLSearchParams();
  if (filters.flow_uid) query.set("flow_uid", filters.flow_uid);
  if (filters.host) query.set("host", filters.host);
  if (filters.method) query.set("method", filters.method);
  if (filters.response_status != null)
    query.set("response_status", String(filters.response_status));
  if (filters.content_type_family)
    query.set("content_type_family", filters.content_type_family);
  if (filters.auth_context) query.set("auth_context", filters.auth_context);
  if (filters.truncated != null) query.set("truncated", filters.truncated ? "true" : "false");
  if (filters.q) query.set("q", filters.q);
  if (filters.limit != null) query.set("limit", String(filters.limit));
  if (filters.offset != null) query.set("offset", String(filters.offset));
  return query;
}

export function listHttpFlows(engagementKey: string, filters: HttpFlowFilters = {}) {
  const qs = httpFlowParams(filters).toString();
  return request<HttpFlow[]>(
    `/engagements/${engagementKey}/assessment/http-flows${qs ? `?${qs}` : ""}`,
  );
}

export function getHttpFlow(engagementKey: string, flowUid: string) {
  return request<HttpFlow>(
    `/engagements/${engagementKey}/assessment/http-flows/${encodeURIComponent(flowUid)}`,
  );
}

// App-relative URL for the HAR export honouring the active filter set. The
// endpoint serves the reconstructed HAR 1.2 document (bodies inlined from the
// engagement-local sidecars); a hidden <a download> points here so the browser
// saves the file directly.
export function exportHarUrl(engagementKey: string, filters: HttpFlowFilters = {}): string {
  const qs = httpFlowParams(filters).toString();
  return resolveAppUrl(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/http-flows/export-har${qs ? `?${qs}` : ""}`,
  );
}

export function getCapturePolicy(engagementKey: string) {
  return request<CapturePolicy>(`/engagements/${engagementKey}/assessment/capture-policy`);
}

export function setCapturePolicy(engagementKey: string, patch: CapturePolicyUpdate) {
  return request<CapturePolicy>(
    `/engagements/${engagementKey}/assessment/capture-policy`,
    { method: "PUT", body: JSON.stringify(patch) },
  );
}

export function engagementWebSocketUrl(engagementKey: string): string {
  const url = new URL(`ws/engagements/${encodeURIComponent(engagementKey)}`, appBaseUrl());
  url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

// ── Code analysis types ─────────────────────────────────

export type CodeRepo = {
  id: number;
  repo_key: string;
  name: string;
  language: string;
  repo_path: string;
  total_files: number;
  analyzable_files: number;
  total_loc: number;
  commit_hash: string;
  branch: string;
  active_generation: number;
  source_origin_path: string;
  source_kind: "git" | "directory" | "legacy";
  snapshot_manifest_path: string;
  snapshot_digest: string;
  source_manifest_version: string;
  source_manifest_digest: string;
  source_snapshot_quality: "verified" | "legacy-unverified";
  // `reference` repositories are readable for cross-file context but are never
  // handed analysis work and never enter the coverage denominator, so the UI
  // must say which a repo is rather than showing an empty analysis card.
  repo_role: "analysis" | "reference";
  worktree_dirty: boolean | null;
  lsp_config: {
    ctags?: {
      available?: boolean;
      tags_path?: string;
      universal?: boolean;
      repo_generation?: number;
      source_manifest_digest?: string;
    };
  };
  structural_index_schema: string;
  structural_index_generation: number | null;
  structural_index_manifest_path: string;
  structural_degraded_files: number;
  structural_degraded_file_paths: string[];
  structural_artifact_truncated_files: number;
  structural_artifact_truncated_file_paths: string[];
  structural_analysis_status_counts: {
    complete?: number;
    degraded?: number;
    unsupported?: number;
  };
  threat_model_generation: number | null;
  analysis_status: string;
  // Hydrated (parsed) fields — the backend also returns *_json raw strings but
  // these parsed objects are what the frontend should use.
  threat_model: Record<string, unknown>;
  git_churn: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type CodeFile = {
  id: number;
  repo_id: number;
  file_path: string;
  language: string;
  loc: number;
  file_hash: string;
  classification: string;
  role: string;
  slot_types: string[];
  analysis_priority: number;
  analysis_status: string;
  analysis_depth: string;
  skip_reason: string;
  variant_check_status: string;
  module_id: number | null;
  git_churn_score: number;
  has_past_cve_fix: boolean;
  header_snippet: string;
  notes: string;
  structural_analysis_status: "pending" | "complete" | "degraded" | "unsupported";
  structural_analysis_mode:
    | ""
    | "tree_sitter"
    | "lightweight_regex"
    | "streaming_security_fallback"
    | "none";
  structural_degradation_reason: string;
  structural_source_size: number;
  structural_bytes_scanned: number;
  structural_unavailable_dimensions: string[];
  structural_artifact_truncated: boolean;
  structural_truncated_dimensions: string[];
  structural_signal_counts: {
    entry_points?: number;
    imports?: number;
    security_sinks?: number;
    security_sources?: number;
  };
  created_at: string;
  updated_at: string;
};

export type CodeModule = {
  id: number;
  repo_id: number;
  module_key: string;
  name: string;
  description: string;
  trust_boundary: string;
  file_count: number;
  critical_file_count: number;
  analysis_status: string;
  created_at: string;
  updated_at: string;
};

export type CodeQueueStats = {
  pending: number;
  processing: number;
  done: number;
  error: number;
  needs_context: number;
  total: number;
  historical_total: number;
  superseded_history: number;
  invalid_active_identity: number;
  invalid_active_history: number;
  // Rows the counts above leave out: a reference repository is never handed
  // work, so its rows can never drain. Named, not dropped.
  reference_repo_items: Array<{
    repo_id: number;
    repo_key: string;
    name: string;
    queue_items: number;
  }>;
};

export type CodeQueueStatus = "pending" | "processing" | "done" | "error" | "needs_context";

export type CodeQueueItem = {
  id: number;
  file_id: number;
  file_path: string;
  classification: string;
  analysis_priority: number;
  repo_id: number;
  repo_key: string;
  repo_role: "analysis" | "reference";
  status: CodeQueueStatus;
  queue_mode: "initial" | "reanalysis" | "trigger" | "metadata-refresh";
  priority: number;
  batch_theme: string;
  slot_types: string[];
  guidance_hypotheses: string[];
  cross_file_triggers: Array<Record<string, unknown>>;
  agent_name: string;
  lease_token: string;
  repo_generation: number;
  disposition: string;
  skip_reason: string;
  reanalysis_of_queue_item_id: number | null;
  consumed_at: string | null;
  last_heartbeat_at: string | null;
  lease_activity_at: string | null;
  heartbeat_age_seconds: number | null;
  current_result_count: number;
  adopted_leases: Array<{ agent_name: string; lease_token: string }>;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type CodeQueuePage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  item_ids: number[];
  items: CodeQueueItem[];
};

export type CodeCoverage = {
  total_files: number;
  // The repositories deliberately excluded from every count in this object.
  // Named so a shrunken denominator is never a silent one — and unlike
  // `CodeQueueStats.reference_repo_items`, this lists a reference repo even
  // when it has no queue rows at all, which is the normal case.
  reference_repos: Array<{
    repo_id: number;
    repo_key: string;
    name: string;
    admitted_files: number;
  }>;
  by_classification: Record<string, { count: number; analyzed: number }>;
  by_status: Record<string, number>;
  findings_summary: {
    total_code_findings: number;
    by_severity: Record<string, number>;
    variant_count: number;
  };
  confidence: {
    critical_coverage_pct: number;
    high_coverage_pct: number;
    overall_loc_analyzed: number;
    unresolved_needs_context: number;
    active_queue_items: number;
    invalid_active_history: number;
    unprocessed_triggers: number;
    skip_reasons: Record<string, number>;
  };
  gate: {
    passed: boolean;
    reasons: string[];
    effort_warnings?: string[];
    coverage_integrity?: Array<{
      file_path?: string;
      warnings?: string[];
    }>;
  };
};

export type CodeReadinessTarget =
  | "classify-map"
  | "hunt"
  | "verify-variant"
  | "fuzz"
  | "complete";

export type CodeReadiness = {
  target_phase: CodeReadinessTarget;
  transition_ready: boolean;
  structural_debt_count?: number;
  structural_debt?: Array<{ repo_id: number; file_path: string }>;
  blockers: Array<{
    code: string;
    message: string;
    overrideable: boolean;
    repo_id?: number;
  }>;
  quality_gate: {
    passed: boolean;
    warnings: string[];
  };
};

export type CodeAnalysisResult = {
  id: number;
  queue_item_id: number | null;
  file_id: number;
  file_path?: string | null;
  agent_name: string;
  receipt_kind: "file" | "call_chain";
  receipt_binding_status: string;
  callable_refs: Array<{
    callable_key: string;
    file_id: number;
    file_path: string;
    name: string;
    qualified_name: string;
    start_line: number;
    end_line: number;
  }>;
  reviewed_spans: Array<{
    file_id: number;
    file_path: string;
    start_line: number;
    end_line: number;
    label: string;
  }>;
  function_name: string;
  hypothesis: string;
  evidence: string;
  disposition: string;
  confidence: string;
  finding_slug: string;
  cwe_id: string;
  slot_type: string;
  notes: string;
  finding_workflow_status?: string | null;
  finding_verification_status?: string | null;
  audit_metadata: Record<string, unknown>;
  created_at: string;
};

export type CodeFilePage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CodeFile[];
};

// ── Code analysis API functions ─────────────────────────

export function listCodeRepos(engagementKey: string) {
  return request<CodeRepo[]>(`/engagements/${engagementKey}/assessment/code/repos`);
}

export function listCodeFiles(
  engagementKey: string,
  params?: { repo_id?: number; classification?: string; limit?: number; offset?: number },
) {
  const query = new URLSearchParams();
  if (params?.repo_id != null) query.set("repo_id", String(params.repo_id));
  if (params?.classification) query.set("classification", params.classification);
  if (params?.limit != null) query.set("limit", String(params.limit));
  if (params?.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<CodeFilePage>(`/engagements/${engagementKey}/assessment/code/files${qs ? `?${qs}` : ""}`);
}

export function listCodeModules(engagementKey: string, repoId?: number) {
  const qs = repoId != null ? `?repo_id=${repoId}` : "";
  return request<CodeModule[]>(`/engagements/${engagementKey}/assessment/code/modules${qs}`);
}

export function getCodeQueueStats(engagementKey: string) {
  return request<CodeQueueStats>(`/engagements/${engagementKey}/assessment/code/analysis-queue/stats`);
}

export function listCodeQueueItems(
  engagementKey: string,
  params: { status?: CodeQueueStatus; limit?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.limit != null) query.set("limit", String(params.limit));
  const qs = query.toString();
  return request<CodeQueuePage>(
    `/engagements/${engagementKey}/assessment/code/analysis-queue${qs ? `?${qs}` : ""}`,
  );
}

export function getCodeCoverage(engagementKey: string, repoId?: number) {
  const qs = repoId != null ? `?repo_id=${repoId}` : "";
  return request<CodeCoverage>(`/engagements/${engagementKey}/assessment/code/coverage${qs}`);
}

export function getCodeReadiness(engagementKey: string, targetPhase: CodeReadinessTarget) {
  const query = new URLSearchParams({ target_phase: targetPhase, include_debt_paths: "true" });
  return request<CodeReadiness>(
    `/engagements/${engagementKey}/assessment/code/readiness?${query.toString()}`,
  );
}

export function listCodeAnalysisResults(engagementKey: string, params?: { file_id?: number; disposition?: string }) {
  const query = new URLSearchParams();
  if (params?.file_id != null) query.set("file_id", String(params.file_id));
  if (params?.disposition) query.set("disposition", params.disposition);
  const qs = query.toString();
  return request<CodeAnalysisResult[]>(`/engagements/${engagementKey}/assessment/code/analysis-results${qs ? `?${qs}` : ""}`);
}

// ── Intel types ─────────────────────────────────────────
// Every interface below mirrors an orchestrator response model in
// `orchestrator/backend/app/api/intel_schemas.py`. Keep these in lock-step
// with the pydantic response classes; the JSON schemas under
// `agent/schemas/intel-*.schema.json` are the request-side view of the
// same contract. The Phase B1 fetchers below are implemented, not stubs.

export type IntelProvenance = {
  agent_name?: string;
  artifact_ref?: string;
  captured_at?: string;
  evidence_quote?: string;
};

type IntelRowBase = {
  id: number;
  engagement_id: number;
  source_name: string;
  notes: string;
  provenance: IntelProvenance;
  // Populated when this row was replaced by a newer record via
  // `vigil assess supersede-intel`. The IntelTab renders superseded rows
  // distinctly (struck-through, link to the superseder).
  superseded_by_id: number | null;
  superseded_at: string | null;
  // Leaf of the supersede chain. Equal to ``id`` when this row is the
  // canonical record; otherwise points to the latest replacement so the
  // UI can chase to current state in a single hop.
  canonical_id: number | null;
  created_at: string;
  updated_at: string;
};

export type IntelTechComponent = IntelRowBase & {
  component: string;
  version: string;
  confidence: string;
  evidence_ref: string;
  first_seen_at: string;
  last_seen_at: string;
};

export type IntelPerson = IntelRowBase & {
  name: string;
  role: string;
  organization: string;
  email: string;
};

export type IntelEmail = IntelRowBase & {
  address: string;
  role_hint: string;
  linked_person_id: number | null;
};

export type IntelDomain = IntelRowBase & {
  identity: string;
  kind: "subdomain" | "ip" | "asn" | "nameserver" | "mx" | "ptr" | "domain";
  value: string;
  live_status: string;
};

export type IntelCve = IntelRowBase & {
  cve_id: string;
  affected_component: string;
  affected_version_range: string;
  cvss_score: number | null;
  cvss_vector: string;
  cwe_id: string;
  poc_available: boolean;
  validation_status: "unverified" | "version_match" | "ruled_out" | "exploited";
  linked_finding_slug: string;
};

export type IntelDnsRecord = IntelRowBase & {
  record_type: string;
  name: string;
  value: string;
  first_seen: string;
  last_seen: string;
};

export type IntelSocialProfile = IntelRowBase & {
  subject_kind: "person" | "org";
  subject_ref: string;
  platform: string;
  handle: string;
  url: string;
};

export type IntelBreachRecord = IntelRowBase & {
  subject: string;
  breach_name: string;
  breach_date: string;
  data_types: string;
};

export type IntelOrgFact = IntelRowBase & {
  fact_key: string;
  fact_value: string;
  authored_by: string;
  scope: string;
  validity_context: string;
};

export type IntelNote = IntelRowBase & {
  title: string;
  body_markdown: string;
  source_agent: string;
  tags: string[];
  lead_status: IntelLeadStatus | null;
  authored_by: string;
  scope: string;
  validity_context: string;
};

export type IntelLeadStatus = "open" | "in_progress" | "resolved" | "ruled_out";

export type IntelEntityType =
  | "tech_component"
  | "person"
  | "email"
  | "domain"
  | "cve"
  | "dns_record"
  | "social_profile"
  | "breach_record"
  | "org_fact"
  | "note";

export type IntelRecord =
  | IntelTechComponent
  | IntelPerson
  | IntelEmail
  | IntelDomain
  | IntelCve
  | IntelDnsRecord
  | IntelSocialProfile
  | IntelBreachRecord
  | IntelOrgFact
  | IntelNote;

export type ListIntelResponse<T = IntelRecord> = {
  entity_type: IntelEntityType;
  total: number;
  items: T[];
};

export type IntelSearchHit = {
  entity_type: IntelEntityType;
  source_id: number;
  key: string;
  body: string;
  source_name: string;
  rank: number | null;
  record: Record<string, unknown>;
};

export type IntelResolutionMatch = {
  id: number;
  entity_type: IntelEntityType;
  title: string;
  summary: string;
  status: string;
};

export type IntelResolutionResult = {
  requested_id: string | number;
  resolution: "resolved" | "missing" | "dangling" | "ambiguous" | "unsupported";
  matches: IntelResolutionMatch[];
};

export type IntelSummary = {
  counts: Record<string, number>;
};

export type IntelReadinessCve = {
  id: number;
  cve_id: string;
  cvss_score: number | null;
  affected_component: string;
  validation_status?: string;
};

export type IntelReadinessLead = {
  id: number;
  title: string;
  lead_status: IntelLeadStatus;
};

export type IntelReadinessDanglingLink = {
  id: number;
  cve_id: string;
  linked_finding_slug: string;
  reason: string;
  workflow_status: string | null;
};

export type IntelReadiness = {
  applicable: boolean;
  engagement_type: string;
  open_high_cves: IntelReadinessCve[];
  open_leads: IntelReadinessLead[];
  exploited_unlinked_cves: IntelReadinessCve[];
  dangling_links: IntelReadinessDanglingLink[];
};

export type IntelByUrlResponse = {
  domains: IntelDomain[];
  services: Record<string, unknown>[];
  surfaces: Record<string, unknown>[];
  request_variants: Record<string, unknown>[];
};

// ── Activity log types ──────────────────────────────────

export type ActivityEntry = {
  id: number;
  engagement_id: number;
  occurred_at: string;
  actor_kind: "operator" | "agent" | "hook" | "system";
  actor_name: string;
  title: string;
  action: string;
  result: string;
  artifact_ref: string;
  body_markdown: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ListActivityEntriesResponse = {
  total: number;
  items: ActivityEntry[];
};

// ── Intel & Activity fetchers ───────────────────────────
// The backend bodies these call are implemented in `app/api/intel.py`; an
// engagement with no intel returns 200 with zero counts, not an error. Callers
// still catch, so one failing intel fetch cannot block the rest of a refresh.

export function getIntelSummary(engagementKey: string) {
  return request<IntelSummary>(`/engagements/${engagementKey}/intel/summary`);
}

export function getIntelReadiness(engagementKey: string) {
  return request<IntelReadiness>(`/engagements/${engagementKey}/intel/readiness`);
}

const INTEL_LIST_PAGE_SIZE = 500;

async function listAllIntelPages<T>(
  path: string,
  baseQuery: URLSearchParams = new URLSearchParams(),
): Promise<T[]> {
  const items: T[] = [];
  let offset = 0;

  while (true) {
    const query = new URLSearchParams(baseQuery);
    query.set("limit", String(INTEL_LIST_PAGE_SIZE));
    query.set("offset", String(offset));
    const page = await request<unknown>(`${path}?${query.toString()}`);
    if (!Array.isArray(page)) {
      throw new Error(`Expected ${path} to return a JSON array`);
    }
    items.push(...(page as T[]));
    if (page.length < INTEL_LIST_PAGE_SIZE) return items;
    offset += page.length;
  }
}

export async function listIntel(
  engagementKey: string,
  entityType: IntelEntityType,
): Promise<ListIntelResponse> {
  const path = intelEntityPath(entityType);
  // Reader endpoints return bounded bare lists (see api/intel.py). Traverse
  // every page before publishing an exact total to the Intel cache.
  const items = await listAllIntelPages<IntelRecord>(
    `/engagements/${engagementKey}/intel/${path}`,
  );
  return { entity_type: entityType, total: items.length, items };
}

export function listIntelCredentials(engagementKey: string) {
  // Credentials are a thin alias over assessment_credentials; shape is
  // "list of dict" at the contract layer — keep it loose.
  return listAllIntelPages<Record<string, unknown>>(
    `/engagements/${engagementKey}/intel/credentials`,
  );
}

export function searchIntel(
  engagementKey: string,
  params: { q?: string; entity_type?: IntelEntityType | ""; limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.entity_type) query.set("entity_type", params.entity_type);
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  const path = `/engagements/${engagementKey}/intel/search`;
  if (params.limit == null && params.offset == null) {
    return listAllIntelPages<IntelSearchHit>(path, query);
  }
  return request<IntelSearchHit[]>(
    `${path}${qs ? `?${qs}` : ""}`,
  );
}

export function chunkIntelResolutionIds(
  ids: Array<string | number>,
  size = 100,
): Array<Array<string | number>> {
  const batches: Array<Array<string | number>> = [];
  for (let offset = 0; offset < ids.length; offset += size) {
    batches.push(ids.slice(offset, offset + size));
  }
  return batches;
}

export async function resolveIntelIds(engagementKey: string, ids: Array<string | number>) {
  const results: IntelResolutionResult[] = [];
  for (const batch of chunkIntelResolutionIds(ids)) {
    const query = new URLSearchParams();
    batch.forEach((id) => query.append("ids", String(id)));
    results.push(...await request<IntelResolutionResult[]>(
      `/engagements/${engagementKey}/intel/resolve?${query.toString()}`,
    ));
  }
  return results;
}

export function intelByUrl(engagementKey: string, url: string) {
  const qs = new URLSearchParams({ url }).toString();
  return request<IntelByUrlResponse>(
    `/engagements/${engagementKey}/intel/by-url?${qs}`,
  );
}

export function listActivityEntries(
  engagementKey: string,
  params: { q?: string; actor_kind?: string; since?: string; until?: string; limit?: number; offset?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.q) query.set("q", params.q);
  if (params.actor_kind) query.set("actor_kind", params.actor_kind);
  if (params.since) query.set("since", params.since);
  if (params.until) query.set("until", params.until);
  if (params.limit != null) query.set("limit", String(params.limit));
  if (params.offset != null) query.set("offset", String(params.offset));
  const qs = query.toString();
  return request<ListActivityEntriesResponse>(
    `/engagements/${engagementKey}/activity-entries${qs ? `?${qs}` : ""}`,
  );
}

// `listSurfaces` is an alias over the existing assessment endpoint; the
// SurfacesTab imports this name for parity with §3b.
export const listSurfaces = listAssessmentSurfaces;

// ── Mutation helpers (CLI parity) ───────────────────────

export type SurfacePatchPayload = {
  status?: SurfaceStatus;
  rationale?: string;
  source_name?: string;
  evidence_ref?: string;
  followup_condition?: string;
};

export function patchAssessmentSurface(
  engagementKey: string,
  surfaceId: number,
  payload: SurfacePatchPayload,
) {
  return request<AssessmentSurface>(
    `/engagements/${engagementKey}/assessment/surfaces/${surfaceId}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
  );
}

export function patchIntelRecord(
  engagementKey: string,
  entityType: IntelEntityType,
  intelId: number,
  patch: Record<string, unknown>,
) {
  const path = intelEntityPath(entityType);
  return request<IntelRecord>(
    `/engagements/${engagementKey}/intel/${path}/${intelId}`,
    {
      method: "PATCH",
      body: JSON.stringify({ payload: patch }),
    },
  );
}

export type IntelSupersedeResult = {
  superseded: IntelRecord;
  current: IntelRecord;
};

export function supersedeIntelRecord(
  engagementKey: string,
  entityType: IntelEntityType,
  intelId: number,
  newPayload: Record<string, unknown>,
  rationale: string = "",
) {
  const path = intelEntityPath(entityType);
  return request<IntelSupersedeResult>(
    `/engagements/${engagementKey}/intel/${path}/${intelId}/supersede`,
    {
      method: "POST",
      body: JSON.stringify({ payload: newPayload, rationale }),
    },
  );
}

function intelEntityPath(entityType: IntelEntityType): string {
  switch (entityType) {
    case "tech_component":
      return "tech-components";
    case "person":
      return "people";
    case "email":
      return "emails";
    case "domain":
      return "domains";
    case "cve":
      return "cves";
    case "dns_record":
      return "dns-records";
    case "social_profile":
      return "social-profiles";
    case "breach_record":
      return "breach-records";
    case "org_fact":
      return "org-facts";
    case "note":
      return "notes";
  }
}

/** Backend-derived readiness of one proof-work item or owed entry. */
export type ProofWorkQueueState = "unprepared" | "ready" | "needs_approval" | "in_progress" | "blocked" | "stale" | "done";
/** Verifier-authored runtime proof plan; untrusted text that grants no scope or approval. */
export type ProofNextTest = {
  hypothesis: string;
  confirm_if: string;
  falsify_if: string;
  route_hint: "local" | "live" | "unknown";
  prerequisites?: string | null;
};
export type ProofWork = {
  id: number;
  finding_slug: string;
  route: "code" | "web";
  objective: string;
  target_hosts: string[];
  status: "prepared" | "claimed" | "blocked" | "finished" | "stale" | "resolved";
  current: boolean;
  owed: boolean;
  approved: boolean;
  approval_required: boolean;
  owner_agent_id: string | null;
  owner_dispatch_id: number | null;
  owner_dispatch_status: string | null;
  blocker: string;
  run_ids: number[];
  queue_state: ProofWorkQueueState;
  next_test: ProofNextTest | null;
  created_at: string;
  updated_at: string;
};
export type ProofWorkList = {
  reverification_required: Array<{finding_slug: string; finding_id: number; invalidating_transition_id: number; next_action: string; work_ids: number[]}>;
  owed: Array<{finding_slug: string; finding_id: number; title: string; canonical_location: string; work_ids: number[]; queue_state: ProofWorkQueueState; next_test: ProofNextTest | null}>;
  items: ProofWork[];
};
export type ProofWorkPreparation = {finding_slug: string; route: "code" | "web"; objective: string; target_hosts: string[]};

export function listProofWork(engagementKey: string) {
  return request<ProofWorkList>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work`);
}
export function prepareProofWork(engagementKey: string, payload: ProofWorkPreparation) {
  return request<ProofWork>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work`, {method: "POST", body: JSON.stringify(payload)});
}
export type ProofWorkEvent = {id: number; action: string; created_at: string; details_json: string};
export function getProofWork(engagementKey: string, workId: number) {
  return request<ProofWork & {events: ProofWorkEvent[]}>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work/${workId}`);
}
export function approveProofWork(engagementKey: string, workId: number, approved: boolean, reason?: string) {
  return request<ProofWork>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work/${workId}/approval`, {method: "POST", body: JSON.stringify({approved, actor: "ui", human_confirmation: approved ? "Approved in the Vigil UI" : null, reason: approved ? null : reason})});
}
export function reconcileProofWork(engagementKey: string, workId: number) {
  return request<ProofWork>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work/${workId}/reconcile`, {method: "POST", body: "{}"});
}
export function releaseProofWork(engagementKey: string, workId: number, reason: string) {
  return request<ProofWork>(`/engagements/${encodeURIComponent(engagementKey)}/assessment/proof-work/${workId}/release`, {method: "POST", body: JSON.stringify({reason})});
}
