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
  verification_state: string;
  verification_disposition: string;
  canonical_location: string;
  summary: string;
  source_name: string;
  updated_at: string;
};

export type FindingDetails = {
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
  steps_to_reproduce?: string[];
  chain_required?: boolean;
  chain_rationale?: string;
  required_followup?: string[];
};

export type AssessmentFindingDetail = AssessmentFinding & {
  id: number;
  evidence_ref: string;
  notes: string;
  defect_family: string;
  root_cause_key: string;
  auth_context: string;
  details_json: string;
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
  target_ref: string;
  notes: string;
  updated_at: string;
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

async function readError(response: Response): Promise<string> {
  const text = await response.text();
  if (!text) {
    return `Request failed: ${response.status}`;
  }

  try {
    const payload = JSON.parse(text) as { detail?: unknown };
    if (typeof payload.detail === "string") {
      return payload.detail;
    }
  } catch {
    // Fall back to raw body.
  }

  return text;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(resolveAppUrl(path), { ...init, headers });
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return response.json() as Promise<T>;
}

export function listEngagements() {
  return request<Engagement[]>("/engagements");
}

export function getEngagement(engagementKey: string) {
  return request<Engagement>(`/engagements/${engagementKey}`);
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

export function listAssessmentSurfaces(engagementKey: string) {
  return request<AssessmentSurface[]>(`/engagements/${engagementKey}/assessment/surfaces`);
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

export function listAssessmentProbes(engagementKey: string) {
  return request<AssessmentProbeDetail[]>(`/engagements/${engagementKey}/assessment/probe-runs`);
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

export function listAssessmentCoverageItems(engagementKey: string) {
  return request<AssessmentCoverageItem[]>(`/engagements/${engagementKey}/assessment/coverage-items`);
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
