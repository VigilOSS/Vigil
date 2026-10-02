import { engagementHref, positiveRouteId } from "./workspaceRoutes.ts";

export type RunAuditSection =
  | "sources"
  | "source-reads"
  | "dispatches"
  | "commands"
  | "observed-events"
  | "decision-history"
  | "proof-receipts"
  | "obligations"
  | "candidates"
  | "tool-signals"
  | "discovery-passes"
  | "code-receipts"
  | "comparisons";

export type AuditPage<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

export type AuditBlocker = {
  code: string;
  message: string;
  object_type: string;
  object_id: number | string | null;
  action: string;
  [key: string]: unknown;
};

export type RunComparison = {
  run_id: number;
  baseline_run_id: number | null;
  target_compatible: boolean | null;
  source_compatible: boolean | null;
  deterministic: boolean;
  classifications: {
    new: string[];
    persisting: string[];
    resolved: string[];
    unknown: string[];
  };
};

export type AuditLifecycleEvent = {
  id?: number;
  from_status?: string | null;
  to_status: string;
  created_at?: string;
  reason?: string;
  [key: string]: unknown;
};

export type RunDispatchFields = {
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
  seal?: unknown;
};

export type AuditUiState = {
  section: RunAuditSection;
};

export type AuditUiAction = { type: "select-section"; section: RunAuditSection };

export const initialAuditUiState: AuditUiState = {
  section: "sources",
};

export function parseRunAuditQuery(params: URLSearchParams): {
  runId?: number;
  section?: RunAuditSection;
  object?: string;
} {
  const parsedRunId = positiveRouteId(params, "run");
  if (parsedRunId === undefined) return {};
  const rawSection = params.get("section");
  const section = rawSection && ["sources", "source-reads", "dispatches", "commands", "observed-events", "decision-history", "proof-receipts", "obligations", "candidates", "tool-signals", "discovery-passes", "code-receipts", "comparisons"].includes(rawSection)
    ? rawSection as RunAuditSection
    : undefined;
  const object = section ? params.get("object")?.trim() || undefined : undefined;
  return { runId: parsedRunId, section, object };
}

export function auditUiReducer(state: AuditUiState, action: AuditUiAction): AuditUiState {
  return { ...state, section: action.section };
}

export function appendAuditPage<T extends { id?: number | string }>(
  current: T[],
  page: AuditPage<T>,
): { items: T[]; nextOffset: number; hasMore: boolean } {
  const seen = new Set(
    current
      .filter((item) => item.id !== undefined)
      .map((item) => `${typeof item.id}:${String(item.id)}`),
  );
  const additions = page.items.filter((item) => {
    if (item.id === undefined) return true;
    const key = `${typeof item.id}:${String(item.id)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return {
    items: [...current, ...additions],
    nextOffset: page.offset + page.items.length,
    hasMore: page.has_more && page.items.length > 0,
  };
}

export async function collectBarePages<T>(
  fetchPage: (offset: number, limit: number) => Promise<T[]>,
  pageSize: number,
  maxPages = 200,
): Promise<T[]> {
  if (!Number.isInteger(pageSize) || pageSize < 1) {
    throw new Error("page size must be a positive integer");
  }
  if (!Number.isInteger(maxPages) || maxPages < 1) {
    throw new Error("page limit must be a positive integer");
  }
  const items: T[] = [];
  let offset = 0;
  for (let pageNumber = 0; pageNumber < maxPages; pageNumber += 1) {
    const page = await fetchPage(offset, pageSize);
    items.push(...page);
    if (page.length < pageSize) return items;
    offset += page.length;
  }
  throw new Error(`run listing did not reach EOF after ${maxPages} pages`);
}

export function chooseRunSelection(
  runIds: number[],
  currentRunId: number | null,
  requestedRunId?: number,
): number | null {
  if (currentRunId !== null && runIds.includes(currentRunId)) return currentRunId;
  if (requestedRunId !== undefined && runIds.includes(requestedRunId)) return requestedRunId;
  return runIds[0] ?? null;
}

function sectionForObject(objectType: string): RunAuditSection | null {
  const normalized = objectType.toLowerCase().replace(/_/g, "-");
  if (normalized === "source" || normalized === "sources") return "sources";
  if (normalized === "source-read" || normalized === "source-reads") return "source-reads";
  if (normalized === "dispatch" || normalized === "dispatches") return "dispatches";
  if (normalized === "command" || normalized === "command-run" || normalized === "commands") return "commands";
  if (normalized === "observed-event" || normalized === "observed-events") return "observed-events";
  if (normalized === "decision-history") return "decision-history";
  if (normalized === "proof-receipt" || normalized === "proof-receipts") return "proof-receipts";
  if (normalized === "obligation" || normalized === "obligations") return "obligations";
  if (normalized === "candidate" || normalized === "candidates") return "candidates";
  if (normalized === "discovery-pass" || normalized === "discovery-passes") return "discovery-passes";
  if (normalized === "comparison" || normalized === "comparisons") return "comparisons";
  return null;
}

export function blockerDestination(
  engagementKey: string,
  runId: number,
  blocker: AuditBlocker,
): string {
  const objectType = String(blocker.object_type ?? "").toLowerCase();
  const objectId = blocker.object_id;
  if (objectType === "finding" && objectId !== null && String(objectId)) {
    return engagementHref(engagementKey, { tab: "findings", finding: String(objectId) });
  }
  if (objectType === "artifact") {
    return engagementHref(engagementKey, { tab: "artifacts" });
  }
  const params = new URLSearchParams({ tab: "runs", run: String(runId) });
  const section = sectionForObject(objectType);
  if (section) params.set("section", section);
  const identifiesChild = ["source", "source-read", "dispatch", "proof-receipt", "obligation", "candidate", "discovery-pass", "discovery-passes"].includes(
    objectType.replace(/_/g, "-"),
  );
  if (section && identifiesChild && objectId !== null && String(objectId)) {
    params.set("object", String(objectId));
  }
  return engagementHref(engagementKey, Object.fromEntries(params));
}

const COMPARISON_ORDER = ["new", "persisting", "resolved", "unknown"] as const;

export function normalizedComparison(comparison: RunComparison) {
  return COMPARISON_ORDER.map((key) => ({
    key,
    items: Array.isArray(comparison.classifications[key])
      ? comparison.classifications[key]
      : [],
  }));
}

export function lifecyclePresentation(events: AuditLifecycleEvent[]) {
  return events.map((event, index) => ({
    key: event.id === undefined ? `position-${index}` : `event-${event.id}`,
    transition: `${event.from_status || "created"} → ${event.to_status}`,
    event,
  }));
}

export function dispatchProvenance(run: RunDispatchFields) {
  const seal = run.seal;
  const frozen = seal !== null && typeof seal === "object"
    ? (seal as { dispatch_provenance?: unknown }).dispatch_provenance
    : null;
  const sealed = frozen !== null && typeof frozen === "object"
    ? frozen as Record<string, unknown>
    : null;
  if (sealed) {
    return {
      dispatch_id: sealed.dispatch_id,
      agent_id: sealed.agent_id,
      agent_role: sealed.agent_role,
      requested_model: sealed.requested_model,
      requested_reasoning: sealed.requested_reasoning,
      launcher_effective_model: sealed.launcher_effective_model ?? null,
      launcher_effective_reasoning: sealed.launcher_effective_reasoning ?? null,
      launcher_effective_source: sealed.launcher_effective_source ?? null,
      observed_model: sealed.actual_model,
      observed_reasoning: sealed.actual_reasoning,
      requested_client: sealed.requested_client ?? "unknown",
      launcher_effective_client:
        sealed.launcher_effective_client ?? sealed.client_name ?? "unknown",
      provider_observed_client: sealed.provider_observed_client ?? "unknown",
      client_name_compatibility_projection: sealed.client_name,
      source_revision: sealed.source_revision,
      operator_instruction: {
        path: sealed.operator_instruction_path,
        sha256: sealed.operator_instruction_sha256,
      },
      specialist_instruction: {
        path: sealed.specialist_instruction_path,
        sha256: sealed.specialist_instruction_sha256,
      },
      instruction_identity_status: sealed.instruction_identity_status,
      instructions_stale: sealed.instructions_stale,
    };
  }
  return {
    dispatch_id: run.producer_dispatch_id,
    agent_id: run.producer_dispatch_agent_id,
    agent_role: run.producer_dispatch_agent_role,
    requested_model: run.requested_model,
    requested_reasoning: run.requested_reasoning,
    launcher_effective_model: run.launcher_effective_model ?? null,
    launcher_effective_reasoning: run.launcher_effective_reasoning ?? null,
    launcher_effective_source: run.launcher_effective_source ?? null,
    observed_model: run.actual_model,
    observed_reasoning: run.actual_reasoning,
    requested_client: run.requested_client ?? "unknown",
    launcher_effective_client:
      run.launcher_effective_client ?? run.client_name ?? "unknown",
    provider_observed_client: run.provider_observed_client ?? "unknown",
    client_name_compatibility_projection: run.client_name,
    source_revision: run.source_revision,
    operator_instruction: {
      path: run.operator_instruction_path,
      sha256: run.operator_instruction_sha256,
    },
    specialist_instruction: {
      path: run.specialist_instruction_path,
      sha256: run.specialist_instruction_sha256,
    },
    instruction_identity_status: run.instruction_identity_status,
    instructions_stale: run.instructions_stale,
  };
}

export function elapsedLabel(startedAt?: string | null, finishedAt?: string | null): string {
  if (!startedAt) return "Not observed";
  const start = Date.parse(startedAt);
  const finish = finishedAt ? Date.parse(finishedAt) : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(finish) || finish < start) {
    return "Not observed";
  }
  const seconds = Math.floor((finish - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}
