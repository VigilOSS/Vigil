export type Engagement = {
  id: number;
  key: string;
  target: string;
  status: string;
  engagement_root: string;
  current_phase: string;
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

export type AssessmentSurface = {
  id: number;
  surface_type: string;
  target_descriptor: string;
  source_name: string;
  rationale: string;
  evidence_ref: string;
  status: string;
  updated_at: string;
  vendor_saas?: boolean;
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

export type AssessmentPhaseWorker = {
  phase: string;
  title: string;
  workers: {
    agent: string;
    responsibility: string;
  }[];
  active_agents: string[];
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
  verification_state: string;
  verification_disposition: string;
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
  // Proof-of-concept panel.
  poc_code?: string;
  poc_language?: string;
  poc_request?: FindingPocRequest | string;
  poc_response?: FindingPocResponse | string;
  references?: FindingReference[];
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
  evidence_ref: string;
  evidence_artifact_id?: number | null;
  notes: string;
  defect_family: string;
  root_cause_key: string;
  auth_context: string;
  details_json: string;
  provenance_json?: string;
  merged_into_slug?: string | null;
};

export type AssessmentFindingTransition = {
  id: number;
  actor: string;
  action: string;
  from_workflow_status: string | null;
  to_workflow_status: string;
  from_verification_state: string | null;
  to_verification_state: string;
  from_verification_disposition: string | null;
  to_verification_disposition: string;
  from_severity: string | null;
  to_severity: string;
  reason_code: string;
  reason_text: string;
  artifact_ref: string;
  metadata_json: string;
  created_at: string;
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
  finding_verification_states: Record<string, number>;
  finding_verification_dispositions: Record<string, number>;
  top_surfaces: AssessmentSurface[];
  top_findings: AssessmentFinding[];
  recent_probes: AssessmentProbe[];
  open_coverage_items: AssessmentCoverageGap[];
  attack_chains: AssessmentAttackChain[];
  service_coverage_gaps: AssessmentServiceGap[];
  phase_workers: AssessmentPhaseWorker[];
  vendor_saas_hosts_pending_decision?: VendorSaasPendingDecision[];
  egress_status?: EgressStatus;
};

export type Artifact = {
  name: string;
  relative_path: string;
  media_type: string;
  sensitive: boolean;
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

export function listEvents(engagementKey: string) {
  return request<EventRecord[]>(`/engagements/${engagementKey}/events`);
}

export function getAssessmentSummary(engagementKey: string) {
  return request<AssessmentSummary>(`/engagements/${engagementKey}/assessment/summary`);
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

export function listAssessmentFindings(engagementKey: string) {
  return request<AssessmentFindingDetail[]>(`/engagements/${engagementKey}/assessment/findings`);
}

export function listAssessmentFindingTransitions(engagementKey: string, findingSlug: string) {
  return request<AssessmentFindingTransition[]>(
    `/engagements/${engagementKey}/assessment/findings/${encodeURIComponent(findingSlug)}/transitions`,
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
  return_code: number | null;
  timed_out: boolean;
  success: boolean;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  command_hash: string;
  stdout_sha256: string;
  stderr_sha256: string;
  stdout_preview: string;
  stderr_preview: string;
  // Listings: always "" with preview_chars populated. Detail: full text.
  stdout_preview_chars?: number;
  stderr_preview_chars?: number;
  output_retention_status: string; // retained | suppressed | artifact | empty
  stdout_suppression_reason: string;
  stderr_suppression_reason: string;
  stdout_artifact_ref: string;
  stderr_artifact_ref: string;
  stdout_bytes: number;
  stderr_bytes: number;
  indexed_for_embeddings_at: string | null;
  notes: string;
  created_at: string;
  // Command-metadata audit fields. All nullable — pre-migration rows
  // and calls that don't set the X-* headers land as null.
  technique?: string | null;
  intent?: string | null;
  probe_kind?: string | null;
  destructive?: boolean | null;
};

// Detail fetch always returns preview text (include_output=true server-side).
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
  notes: string;
  status: string; // pending | fired | confirmed | expired | ignored | unmatched
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
  request_body_artifact_path: string | null;
  response_body_artifact_path: string | null;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  redaction_status: string;
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
  redaction_profile: string;
};

// PUT /capture-policy takes an all-optional partial (extra=forbid server-side),
// so keep the update payload strictly to known keys.
export type CapturePolicyUpdate = Partial<CapturePolicy>;

function httpFlowParams(filters: HttpFlowFilters): URLSearchParams {
  const query = new URLSearchParams();
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
};

export type CodeCoverage = {
  total_files: number;
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
    skip_reasons: Record<string, number>;
  };
  gate: {
    passed: boolean;
    reasons: string[];
    effort_warnings?: string[];
  };
};

export type CodeAnalysisResult = {
  id: number;
  queue_item_id: number | null;
  file_id: number;
  file_path?: string | null;
  agent_name: string;
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
  finding_verification_state?: string | null;
  finding_verification_disposition?: string | null;
  audit_metadata: Record<string, unknown>;
  created_at: string;
};

// ── Code analysis API functions ─────────────────────────

export function listCodeRepos(engagementKey: string) {
  return request<CodeRepo[]>(`/engagements/${engagementKey}/assessment/code/repos`);
}

export function listCodeFiles(engagementKey: string, params?: { repo_id?: number; classification?: string; limit?: number }) {
  const query = new URLSearchParams();
  if (params?.repo_id != null) query.set("repo_id", String(params.repo_id));
  if (params?.classification) query.set("classification", params.classification);
  if (params?.limit != null) query.set("limit", String(params.limit));
  const qs = query.toString();
  return request<CodeFile[]>(`/engagements/${engagementKey}/assessment/code/files${qs ? `?${qs}` : ""}`);
}

export function listCodeModules(engagementKey: string, repoId?: number) {
  const qs = repoId != null ? `?repo_id=${repoId}` : "";
  return request<CodeModule[]>(`/engagements/${engagementKey}/assessment/code/modules${qs}`);
}

export function getCodeQueueStats(engagementKey: string) {
  return request<CodeQueueStats>(`/engagements/${engagementKey}/assessment/code/analysis-queue/stats`);
}

export function getCodeCoverage(engagementKey: string, repoId?: number) {
  const qs = repoId != null ? `?repo_id=${repoId}` : "";
  return request<CodeCoverage>(`/engagements/${engagementKey}/assessment/code/coverage${qs}`);
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
// same contract. Fetcher functions land in Phase B1.

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
};

export type IntelNote = IntelRowBase & {
  title: string;
  body_markdown: string;
  source_agent: string;
  tags: string[];
};

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

export type IntelSummary = {
  counts: Record<string, number>;
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
// These hit the route stubs wired by Phase B1. Until the backend bodies
// land, each endpoint 501s — callers therefore must always handle the
// error path and fall back to an empty-state render.

export function getIntelSummary(engagementKey: string) {
  return request<IntelSummary>(`/engagements/${engagementKey}/intel/summary`);
}

export function listIntel(
  engagementKey: string,
  entityType: IntelEntityType,
): Promise<ListIntelResponse> {
  const path = intelEntityPath(entityType);
  // Reader endpoints currently return a bare list (see api/intel.py); the
  // typed `ListIntelResponse` shape is what A1 froze, so normalise here.
  return request<IntelRecord[] | ListIntelResponse>(
    `/engagements/${engagementKey}/intel/${path}`,
  ).then((payload) => {
    if (Array.isArray(payload)) {
      return { entity_type: entityType, total: payload.length, items: payload };
    }
    return payload;
  });
}

export function listIntelCredentials(engagementKey: string) {
  // Credentials are a thin alias over assessment_credentials; shape is
  // "list of dict" at the contract layer — keep it loose.
  return request<Record<string, unknown>[]>(
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
  return request<IntelSearchHit[]>(
    `/engagements/${engagementKey}/intel/search${qs ? `?${qs}` : ""}`,
  );
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
  status?: "covered" | "deferred" | "discovered" | "not_applicable";
  rationale?: string;
  source_name?: string;
  evidence_ref?: string;
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
