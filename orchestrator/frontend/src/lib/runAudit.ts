import type { AssessmentRun } from "./api.ts";
import { formatDuration, serverTimeMs } from "./serverTime.ts";
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

// Evidence sections are filtered views of one receipt ledger and render in
// the drawer's evidence list; the rest are audit records under "Audit details".
export const EVIDENCE_SECTIONS: { key: RunAuditSection; label: string }[] = [
  { key: "proof-receipts", label: "All evidence" },
  { key: "commands", label: "Commands" },
  { key: "observed-events", label: "HTTP, browser & OOB" },
];

export const AUDIT_RECORD_SECTIONS: {
  key: RunAuditSection;
  label: string;
  // The run count that totals this section, when the run carries one.
  countKey?: string;
}[] = [
  { key: "sources", label: "Sources", countKey: "inventory_total" },
  { key: "source-reads", label: "Source reads", countKey: "source_reads" },
  { key: "dispatches", label: "Dispatches" },
  { key: "decision-history", label: "Decision history" },
  { key: "obligations", label: "Obligations", countKey: "obligations" },
  { key: "candidates", label: "Candidates", countKey: "candidates" },
  { key: "tool-signals", label: "Tool signals", countKey: "tool_signals" },
  { key: "discovery-passes", label: "Discovery passes", countKey: "discovery_passes" },
  { key: "code-receipts", label: "Code receipts", countKey: "code_receipt_links" },
  { key: "comparisons", label: "Comparison records" },
];

const ALL_SECTIONS = new Set<string>([
  ...EVIDENCE_SECTIONS.map((section) => section.key),
  ...AUDIT_RECORD_SECTIONS.map((section) => section.key),
]);

export function isRunAuditSection(value: string | null | undefined): value is RunAuditSection {
  return typeof value === "string" && ALL_SECTIONS.has(value);
}

export function isEvidenceSection(section: RunAuditSection): boolean {
  return EVIDENCE_SECTIONS.some((entry) => entry.key === section);
}

// A proof run opens on its evidence; a scan run opens on its source inventory.
export function defaultSectionForRun(runPurpose: string | null | undefined): RunAuditSection {
  return runPurpose === "scan" ? "sources" : "proof-receipts";
}

export function parseRunAuditQuery(params: URLSearchParams): {
  runId?: number;
  section?: RunAuditSection;
  object?: string;
} {
  const parsedRunId = positiveRouteId(params, "run");
  if (parsedRunId === undefined) return {};
  const rawSection = params.get("section");
  const section = isRunAuditSection(rawSection) ? rawSection : undefined;
  const object = section ? params.get("object")?.trim() || undefined : undefined;
  return { runId: parsedRunId, section, object };
}

/**
 * The raw `run=` value when the link names no run (anything but a positive
 * integer). The route parser drops such a value; the Runs view reports it
 * instead of silently showing the list.
 */
export function invalidRunLink(params: URLSearchParams): string | null {
  const raw = params.get("run");
  if (raw === null) return null;
  return positiveRouteId(params, "run") === undefined ? raw : null;
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
  const start = serverTimeMs(startedAt);
  const finish = finishedAt ? serverTimeMs(finishedAt) : Date.now();
  if (start == null || finish == null || finish < start) {
    return "Not observed";
  }
  return formatDuration(finish - start);
}

// ── Run list presentation ─────────────────────────────────────────────

export type RunHealthKey = "healthy" | "attention" | "failed" | "running";

export type RunHealth = {
  key: RunHealthKey;
  // Status as recorded, in words.
  status: string;
  // Why the run is not plainly healthy (empty when it is).
  reason: string;
};

// Labels, tones and meanings live in the shared "run-health" status domain
// (components/ui/statusTones.ts).
const RUN_HEALTH_KEYS: readonly RunHealthKey[] = ["running", "attention", "failed", "healthy"];

/**
 * The runs that need the operator: the one rule behind the Runs view's
 * "Needs attention" scope, its header count and the rail badge.
 */
export const RUN_ATTENTION_HEALTH: ReadonlySet<RunHealthKey> = new Set<RunHealthKey>(["attention", "failed"]);

export const RUN_ATTENTION_RULE =
  "Runs that failed or stopped, and finished runs with open work: blockers, unhealthy evidence receipts, or a partial end.";

export function runNeedsAttention(health: Pick<RunHealth, "key">): boolean {
  return RUN_ATTENTION_HEALTH.has(health.key);
}

const ACTIVE_RUN_STATUSES = new Set(["queued", "running"]);
const STOPPED_RUN_STATUSES = new Set(["failed", "interrupted", "canceled"]);
const UNHEALTHY_RECEIPT_STATES = ["stale", "missing", "tombstoned"] as const;

const BLOCKER_PHRASES: Record<string, [string, string]> = {
  unresolved_obligation: ["open obligation", "open obligations"],
  unresolved_candidate: ["open candidate", "open candidates"],
  promoted_finding_unverified: ["unverified finding", "unverified findings"],
  discovery_terminal_missing: ["discovery not finished", "discovery not finished"],
  discovery_unresolved: ["discovery not finished", "discovery not finished"],
  discovery_proof_unhealthy: ["discovery evidence unhealthy", "discovery evidence unhealthy"],
  target_identity_missing: ["target identity missing", "target identity missing"],
  inventory_missing: ["source inventory missing", "source inventory missing"],
};

export function statusText(value: string | null | undefined): string {
  return (value || "unknown").replace(/_/g, " ");
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** The run's live blockers; a sealed copy only when no live list was sent. */
export function currentBlockers(run: Pick<AssessmentRun, "blockers" | "seal">): AuditBlocker[] {
  if (Array.isArray(run.blockers)) return run.blockers;
  return run.seal?.blockers ?? [];
}

/**
 * Health is never "healthy" while anything still needs work: a completed run
 * with blockers or unhealthy receipts needs attention, whatever its status.
 */
export function runHealth(run: Pick<AssessmentRun, "status" | "blockers" | "seal" | "proof_health">): RunHealth {
  const blockers = currentBlockers(run);
  const proofHealth = run.proof_health ?? {};
  const receiptTotal = Object.values(proofHealth).reduce<number>(
    (sum, value) => sum + (typeof value === "number" ? value : 0),
    0,
  );
  const phrases: string[] = [];
  for (const state of UNHEALTHY_RECEIPT_STATES) {
    const count = proofHealth[state];
    if (typeof count === "number" && count > 0) {
      phrases.push(plural(count, `${state} receipt`, `${state} receipts`));
    }
  }
  if (receiptTotal === 0 && blockers.some((blocker) => blocker.code === "proof_missing")) {
    phrases.push("no evidence recorded");
  }
  const otherCodes = new Map<string, number>();
  for (const blocker of blockers) {
    const code = String(blocker.code ?? "");
    if (code.startsWith("proof_")) continue;
    otherCodes.set(code, (otherCodes.get(code) ?? 0) + 1);
  }
  for (const [code, count] of otherCodes) {
    const [one, many] = BLOCKER_PHRASES[code] ?? [statusText(code), statusText(code)];
    phrases.push(one === many ? one : plural(count, one, many));
  }
  const status = statusText(run.status);
  const reason = phrases.join(" · ");
  if (ACTIVE_RUN_STATUSES.has(run.status)) return { key: "running", status, reason: "" };
  if (STOPPED_RUN_STATUSES.has(run.status)) return { key: "failed", status, reason };
  if (run.status === "completed" && phrases.length === 0 && blockers.length === 0) {
    return { key: "healthy", status, reason: "" };
  }
  const fallback = blockers.length
    ? plural(blockers.length, "blocker", "blockers")
    : run.seal?.requested_status === "partial"
      ? "its agent ended it as partial"
      : "finished with open work";
  return { key: "attention", status, reason: reason || fallback };
}

export type RunFindingRelation = "cited" | "associated" | "dispatched";

export type RunFindingLink = { slug: string; relations: RunFindingRelation[] };

/**
 * Every finding a run relates to, with how: its receipts are cited by the
 * finding's verification, it was started to verify the finding, or its
 * dispatch was sent for the finding.
 */
export function runFindingLinks(
  run: Pick<AssessmentRun, "finding_slugs" | "associated_finding_slugs" | "dispatch_finding_slugs">,
): RunFindingLink[] {
  const links = new Map<string, RunFindingRelation[]>();
  const add = (slugs: string[] | undefined, relation: RunFindingRelation) => {
    for (const slug of slugs ?? []) {
      if (!slug) continue;
      const relations = links.get(slug) ?? [];
      if (!relations.includes(relation)) relations.push(relation);
      links.set(slug, relations);
    }
  };
  add(run.finding_slugs, "cited");
  add(run.associated_finding_slugs, "associated");
  add(run.dispatch_finding_slugs, "dispatched");
  return [...links].map(([slug, relations]) => ({ slug, relations }));
}

export const EVIDENCE_KIND_LABELS: Record<string, { short: string; long: string }> = {
  http_exchange: { short: "HTTP", long: "HTTP exchange" },
  browser_action: { short: "browser", long: "Browser action" },
  oob_event: { short: "OOB", long: "Out-of-band callback" },
  command: { short: "cmd", long: "Command" },
  artifact: { short: "artifact", long: "Artifact" },
  source_observation: { short: "source", long: "Source observation" },
};

const EVIDENCE_KIND_ORDER = Object.keys(EVIDENCE_KIND_LABELS);
export const LIVE_EVIDENCE_KINDS = new Set(["http_exchange", "browser_action", "oob_event"]);

export function evidenceMixLabel(counts: Record<string, number> | undefined): string {
  const entries = Object.entries(counts ?? {}).filter(([, count]) => count > 0);
  if (entries.length === 0) return "None";
  entries.sort(([a], [b]) => {
    const left = EVIDENCE_KIND_ORDER.indexOf(a);
    const right = EVIDENCE_KIND_ORDER.indexOf(b);
    return (left < 0 ? 99 : left) - (right < 0 ? 99 : right) || a.localeCompare(b);
  });
  return entries
    .map(([kind, count]) => `${count} ${EVIDENCE_KIND_LABELS[kind]?.short ?? statusText(kind)}`)
    .join(" · ");
}

function known(value: string | null | undefined): string | null {
  return value && value !== "unknown" ? value : null;
}

/** Client and model, preferring observed over launcher-effective over requested. */
export function runClientModel(run: Pick<
  AssessmentRun,
  | "provider_observed_client" | "launcher_effective_client" | "client_name" | "requested_client"
  | "actual_model" | "launcher_effective_model" | "requested_model"
>): { client: string; model: string } {
  const observedClient = known(run.provider_observed_client)
    ?? known(run.launcher_effective_client)
    ?? known(run.client_name);
  const requestedClient = known(run.requested_client);
  const client = observedClient ?? (requestedClient ? `${requestedClient} (requested)` : "");
  const observedModel = known(run.actual_model) ?? known(run.launcher_effective_model);
  const requestedModel = known(run.requested_model);
  const model = observedModel ?? (requestedModel ? `${requestedModel} (requested)` : "");
  return { client, model };
}

export type RunRow = {
  id: number;
  run: AssessmentRun;
  name: string;
  startedAt: string | null;
  startedMs: number | null;
  health: RunHealth;
  role: string;
  agent: string;
  findings: RunFindingLink[];
  task: string;
  evidenceMix: string;
  liveEvidence: boolean;
  receipts: number;
  durationSeconds: number | null;
  client: string;
  model: string;
  track: string;
  purpose: string;
  blockerCount: number;
  proofWorkIds: number[];
};

export function deriveRunRow(run: AssessmentRun, nowMs: number = Date.now()): RunRow {
  const startedAt = run.started_at ?? run.created_at ?? null;
  const startedMs = serverTimeMs(startedAt);
  const finishedMs = serverTimeMs(run.finished_at);
  const kinds = run.evidence_kind_counts ?? {};
  const { client, model } = runClientModel(run);
  return {
    id: run.id,
    run,
    name: run.run_uuid,
    startedAt,
    startedMs,
    health: runHealth(run),
    role: run.producer_dispatch_agent_role ?? "",
    agent: run.producer_dispatch_agent_id ?? "",
    findings: runFindingLinks(run),
    task: run.producer_dispatch_task ?? "",
    evidenceMix: evidenceMixLabel(kinds),
    liveEvidence: Object.entries(kinds).some(([kind, count]) => LIVE_EVIDENCE_KINDS.has(kind) && count > 0),
    receipts: run.counts?.proof_receipts ?? 0,
    durationSeconds: run.elapsed_seconds
      ?? (startedMs != null && ACTIVE_RUN_STATUSES.has(run.status) && finishedMs == null
        ? Math.max(0, Math.floor((nowMs - startedMs) / 1000))
        : null),
    client,
    model,
    track: run.run_kind,
    purpose: run.run_purpose ?? "proof",
    blockerCount: currentBlockers(run).length,
    proofWorkIds: run.proof_work_ids ?? [],
  };
}

/** The Runs grid's default order: Started, newest first, missing start times last. */
export function compareRunRowsNewestFirst(a: Pick<RunRow, "startedMs">, b: Pick<RunRow, "startedMs">): number {
  if (a.startedMs == null && b.startedMs == null) return 0;
  if (a.startedMs == null) return 1;
  if (b.startedMs == null) return -1;
  return b.startedMs - a.startedMs;
}

export type RunTimeRange = "all" | "24h" | "7d" | "30d";

export const RUN_TIME_RANGES: { key: RunTimeRange; label: string; ms: number | null }[] = [
  { key: "all", label: "All time", ms: null },
  { key: "24h", label: "Last 24 h", ms: 24 * 3600_000 },
  { key: "7d", label: "Last 7 days", ms: 7 * 24 * 3600_000 },
  { key: "30d", label: "Last 30 days", ms: 30 * 24 * 3600_000 },
];

export type RunFilters = {
  query: string;
  health: ReadonlySet<RunHealthKey>;
  roles: ReadonlySet<string>;
  tracks: ReadonlySet<string>;
  finding: string;
  client: string;
  liveOnly: boolean;
  blockersOnly: boolean;
  range: RunTimeRange;
};

/** "attention" narrows the list to RUN_ATTENTION_HEALTH; it is not a filter (Clear filters keeps it). */
export type RunScope = "attention" | "all";

export const EMPTY_RUN_FILTERS: RunFilters = {
  query: "",
  health: new Set(),
  roles: new Set(),
  tracks: new Set(),
  finding: "",
  client: "",
  liveOnly: false,
  blockersOnly: false,
  range: "all",
};

export function activeRunFilterCount(filters: RunFilters): number {
  return (filters.query.trim() ? 1 : 0)
    + filters.health.size
    + filters.roles.size
    + filters.tracks.size
    + (filters.finding ? 1 : 0)
    + (filters.client ? 1 : 0)
    + (filters.liveOnly ? 1 : 0)
    + (filters.blockersOnly ? 1 : 0)
    + (filters.range !== "all" ? 1 : 0);
}

function rowSearchText(row: RunRow): string {
  return [
    row.name, row.task, row.role, row.agent, row.client, row.model, row.track,
    row.health.status, row.health.reason,
    ...row.findings.map((finding) => finding.slug),
  ].join("\n").toLowerCase();
}

/** One dimension of the run filters; a facet's counts ignore its own dimension. */
export type RunFacet = "query" | "health" | "roles" | "tracks" | "finding" | "client" | "liveOnly" | "blockersOnly" | "range" | "scope";

function rowMatches(row: RunRow, filters: RunFilters, scope: RunScope, nowMs: number, ignore?: RunFacet): boolean {
  if (ignore !== "scope" && scope === "attention" && !runNeedsAttention(row.health)) return false;
  if (ignore !== "health" && filters.health.size && !filters.health.has(row.health.key)) return false;
  if (ignore !== "roles" && filters.roles.size && !filters.roles.has(row.role)) return false;
  if (ignore !== "tracks" && filters.tracks.size && !filters.tracks.has(row.track)) return false;
  if (ignore !== "finding" && filters.finding && !row.findings.some((finding) => finding.slug === filters.finding)) return false;
  if (ignore !== "client" && filters.client && row.client !== filters.client) return false;
  if (ignore !== "liveOnly" && filters.liveOnly && !row.liveEvidence) return false;
  if (ignore !== "blockersOnly" && filters.blockersOnly && row.blockerCount === 0) return false;
  if (ignore !== "range") {
    const range = RUN_TIME_RANGES.find((entry) => entry.key === filters.range)?.ms ?? null;
    if (range != null && (row.startedMs == null || nowMs - row.startedMs > range)) return false;
  }
  if (ignore !== "query") {
    const terms = filters.query.toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length) {
      const text = rowSearchText(row);
      if (!terms.every((term) => text.includes(term))) return false;
    }
  }
  return true;
}

export function filterRuns(rows: RunRow[], filters: RunFilters, nowMs: number = Date.now(), scope: RunScope = "all"): RunRow[] {
  return rows.filter((row) => rowMatches(row, filters, scope, nowMs));
}

/** Value → count, most frequent first, for a filter facet. */
export function facetCounts(values: Iterable<string>): [string, number][] {
  const counts = new Map<string, number>();
  for (const value of values) {
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts].sort(([a, left], [b, right]) => right - left || a.localeCompare(b));
}

export type RunFacetCounts = {
  /** Rows under every filter but the scope: what each scope option would show. */
  scope: Record<RunScope, number>;
  health: Record<RunHealthKey, number>;
  tracks: [string, number][];
  roles: [string, number][];
  findings: [string, number][];
  clients: [string, number][];
  live: number;
  blockers: number;
  ranges: Record<RunTimeRange, number>;
};

/**
 * Counts for every filter control. Each facet counts the rows that match
 * every other filter (scope and search included) but its own, so a count is
 * what choosing that value would show; selected values stay listed.
 */
export function runFacetCounts(rows: RunRow[], filters: RunFilters, scope: RunScope, nowMs: number = Date.now()): RunFacetCounts {
  const matching = (ignore: RunFacet) => rows.filter((row) => rowMatches(row, filters, scope, nowMs, ignore));
  const health: Record<RunHealthKey, number> = { healthy: 0, attention: 0, failed: 0, running: 0 };
  for (const row of matching("health")) health[row.health.key] += 1;
  const withSelected = (counts: [string, number][], selected: Iterable<string>) => {
    const known = new Set(counts.map(([value]) => value));
    return [...counts, ...[...selected].filter((value) => value && !known.has(value)).map((value): [string, number] => [value, 0])];
  };
  const scopeRows = matching("scope");
  const ranges = Object.fromEntries(RUN_TIME_RANGES.map((range) => [range.key, 0])) as Record<RunTimeRange, number>;
  for (const row of matching("range")) {
    for (const range of RUN_TIME_RANGES) {
      if (range.ms == null || (row.startedMs != null && nowMs - row.startedMs <= range.ms)) ranges[range.key] += 1;
    }
  }
  return {
    scope: { all: scopeRows.length, attention: scopeRows.filter((row) => runNeedsAttention(row.health)).length },
    health,
    tracks: withSelected(facetCounts(matching("tracks").map((row) => row.track)), filters.tracks),
    roles: withSelected(facetCounts(matching("roles").map((row) => row.role)), filters.roles),
    findings: withSelected(
      facetCounts(matching("finding").flatMap((row) => row.findings.map((finding) => finding.slug))),
      [filters.finding],
    ).sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true })),
    clients: withSelected(facetCounts(matching("client").map((row) => row.client)), [filters.client]),
    live: matching("liveOnly").filter((row) => row.liveEvidence).length,
    blockers: matching("blockersOnly").filter((row) => row.blockerCount > 0).length,
    ranges,
  };
}

// ── Sort and saved view ───────────────────────────────────────────────

export type RunSort = { colId: string; sort: "asc" | "desc" };

export const DEFAULT_RUN_SORT: RunSort = { colId: "started", sort: "desc" };

/** The Runs grid's columns as the results line names them. */
export const RUN_SORT_COLUMNS: Record<string, { label: string; kind: "time" | "number" | "text" | "status" }> = {
  started: { label: "Started", kind: "time" },
  status: { label: "Status", kind: "status" },
  run: { label: "Run", kind: "text" },
  findings: { label: "Findings", kind: "text" },
  task: { label: "Task", kind: "text" },
  evidence: { label: "Evidence receipts", kind: "number" },
  duration: { label: "Duration", kind: "number" },
  client: { label: "Client", kind: "text" },
};

/** The view the Runs tab restores when the operator comes back to it. */
export type RunsSavedView = { filters: RunFilters; scope: RunScope; sort: RunSort };

export function serializeRunsView(view: RunsSavedView): string {
  const { filters } = view;
  return JSON.stringify({
    ...filters,
    health: [...filters.health],
    roles: [...filters.roles],
    tracks: [...filters.tracks],
    scope: view.scope,
    sort: view.sort,
  });
}

/** Parses a saved view; anything unreadable falls back to the defaults. */
export function parseRunsView(text: string | null | undefined): RunsSavedView {
  const fallback: RunsSavedView = { filters: EMPTY_RUN_FILTERS, scope: "all", sort: DEFAULT_RUN_SORT };
  if (!text) return fallback;
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    const strings = (items: unknown) => new Set(Array.isArray(items) ? items.filter((item): item is string => typeof item === "string") : []);
    const sort = value.sort as Partial<RunSort> | undefined;
    return {
      filters: {
        query: typeof value.query === "string" ? value.query : "",
        health: new Set([...strings(value.health)].filter((key): key is RunHealthKey => (RUN_HEALTH_KEYS as readonly string[]).includes(key))),
        roles: strings(value.roles),
        tracks: strings(value.tracks),
        finding: typeof value.finding === "string" ? value.finding : "",
        client: typeof value.client === "string" ? value.client : "",
        liveOnly: value.liveOnly === true,
        blockersOnly: value.blockersOnly === true,
        range: RUN_TIME_RANGES.some((range) => range.key === value.range) ? value.range as RunTimeRange : "all",
      },
      scope: value.scope === "attention" ? "attention" : "all",
      sort: sort && typeof sort.colId === "string" && sort.colId in RUN_SORT_COLUMNS && (sort.sort === "asc" || sort.sort === "desc")
        ? { colId: sort.colId, sort: sort.sort }
        : DEFAULT_RUN_SORT,
    };
  } catch {
    return fallback;
  }
}
