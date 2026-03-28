export type AuthResponse = {
  access_token: string;
  token_type: string;
  user: {
    id: number;
    username: string;
  };
};

export type Project = {
  id: number;
  name: string;
  slug: string;
  root_path: string;
};

export type Run = {
  id: number;
  target: string;
  status: string;
  engagement_root: string;
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

export type WebSocketTicketResponse = {
  ticket: string;
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
    if (Array.isArray(payload.detail) && payload.detail.length > 0) {
      const first = payload.detail[0] as { loc?: unknown[]; msg?: string };
      const field = Array.isArray(first.loc) ? first.loc[first.loc.length - 1] : undefined;
      if (typeof field === "string" && typeof first.msg === "string") {
        return `${field}: ${first.msg}`;
      }
      if (typeof first.msg === "string") {
        return first.msg;
      }
    }
    if (typeof payload.detail === "string") {
      return payload.detail;
    }
  } catch {
    // Fall back to the raw body below.
  }

  return text;
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(resolveAppUrl(path), {
    ...init,
    headers,
  });

  if (!response.ok) {
    throw new Error(await readError(response));
  }

  return response.json() as Promise<T>;
}

export function login(username: string, password: string) {
  return request<AuthResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function register(username: string, password: string) {
  return request<{ id: number; username: string }>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function listProjects(token: string) {
  return request<Project[]>("/projects", {}, token);
}

export function createProject(token: string, name: string) {
  return request<Project>("/projects", {
    method: "POST",
    body: JSON.stringify({ name }),
  }, token);
}

export function deleteProject(token: string, projectId: number) {
  return request<void>(`/projects/${projectId}`, {
    method: "DELETE",
  }, token);
}

export function listRuns(token: string, projectId: number) {
  return request<Run[]>(`/projects/${projectId}/runs`, {}, token);
}

export function createRun(token: string, projectId: number, target: string) {
  return request<Run>(`/projects/${projectId}/runs`, {
    method: "POST",
    body: JSON.stringify({ target }),
  }, token);
}

export function deleteRun(token: string, projectId: number, runId: number) {
  return request<void>(`/projects/${projectId}/runs/${runId}`, {
    method: "DELETE",
  }, token);
}

export function listEvents(token: string, projectId: number, runId: number) {
  return request<EventRecord[]>(`/projects/${projectId}/runs/${runId}/events`, {}, token);
}

export function getAssessmentSummary(token: string, projectId: number, runId: number) {
  return request<AssessmentSummary>(`/projects/${projectId}/runs/${runId}/assessment/summary`, {}, token);
}

export function listAssessmentSurfaces(token: string, projectId: number, runId: number) {
  return request<AssessmentSurface[]>(`/projects/${projectId}/runs/${runId}/assessment/surfaces`, {}, token);
}

export function listAssessmentFindings(token: string, projectId: number, runId: number) {
  return request<AssessmentFindingDetail[]>(`/projects/${projectId}/runs/${runId}/assessment/findings`, {}, token);
}

export function listAssessmentFindingLinks(token: string, projectId: number, runId: number) {
  return request<AssessmentFindingLink[]>(`/projects/${projectId}/runs/${runId}/assessment/finding-links`, {}, token);
}

export function listAssessmentProbes(token: string, projectId: number, runId: number) {
  return request<AssessmentProbeDetail[]>(`/projects/${projectId}/runs/${runId}/assessment/probe-runs`, {}, token);
}

export function listAssessmentAttackChains(token: string, projectId: number, runId: number) {
  return request<AssessmentAttackChainDetail[]>(`/projects/${projectId}/runs/${runId}/assessment/attack-chains`, {}, token);
}

export function listAssessmentAttackChainLinks(token: string, projectId: number, runId: number) {
  return request<AssessmentAttackChainLink[]>(`/projects/${projectId}/runs/${runId}/assessment/attack-chain-links`, {}, token);
}

export function listArtifacts(token: string, projectId: number, runId: number) {
  return request<Artifact[]>(`/projects/${projectId}/runs/${runId}/artifacts`, {}, token);
}

export function readArtifact(token: string, projectId: number, runId: number, artifactName: string) {
  return request<ArtifactContent>(`/projects/${projectId}/runs/${runId}/artifacts/${artifactName}`, {}, token);
}

export function createWebSocketTicket(token: string) {
  return request<WebSocketTicketResponse>("/auth/ws-ticket", { method: "POST" }, token);
}

export function runWebSocketUrl(projectId: number, runId: number, ticket: string) {
  const httpUrl = new URL(
    `ws/projects/${projectId}/runs/${runId}?ticket=${encodeURIComponent(ticket)}`,
    appBaseUrl(),
  );
  httpUrl.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return httpUrl.toString();
}
