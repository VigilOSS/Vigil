export type Engagement = {
  id: number;
  key: string;
  target: string;
  status: string;
  engagement_root: string;
  current_phase: string;
  exploit_policy: string;
  exploit_review_state: string;
  approved_findings: string[];
  active: boolean;
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
  assigned_findings: string[];
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
  status: string;
  canonical_location: string;
  summary: string;
  source_name: string;
  updated_at: string;
};

export type AssessmentFindingDetail = AssessmentFinding & {
  id: number;
  evidence_ref: string;
  notes: string;
  defect_family: string;
  root_cause_key: string;
  auth_context: string;
  merged_into_slug?: string | null;
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
  coverage_statuses: Record<string, number>;
  finding_statuses: Record<string, number>;
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

export function engagementWebSocketUrl(engagementKey: string): string {
  const url = new URL(`ws/engagements/${encodeURIComponent(engagementKey)}`, appBaseUrl());
  url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}
