// ── Coverage ledger API ───────────────────────────────────────────────
//
// Operator reads of the coverage ledger: a server-paged list with a visible
// total, server-side facet counts, a latest-reason rollup, one item's full
// explanation, and where one item sits in the paged order (record navigation). `GET /coverage-items` (the bare list `vigil assess fetch`
// pages) is NOT used here — it returns the full note log for every row.

import { request } from "./api";

export type CoverageSortKey =
  | "updated_at"
  | "created_at"
  | "status"
  | "attack_family"
  | "input_slot"
  | "auth_context"
  | "method"
  | "url"
  | "host"
  | "id";

export type CoverageSortDir = "asc" | "desc";

/** Ledger filters. Multi-valued fields match any of their values. */
export type CoverageFilters = {
  status: string[];
  attack_family: string[];
  auth_context: string[];
  input_slot: string[];
  method: string[];
  host: string[];
  q: string;
  /** Exact latest reason (one line). */
  reason?: string | null;
  /** Only items with no recorded reason yet. */
  reason_missing?: boolean;
  /** Exact creation note (line 1 of the note log). */
  created_from?: string | null;
};

export const EMPTY_COVERAGE_FILTERS: CoverageFilters = {
  status: [],
  attack_family: [],
  auth_context: [],
  input_slot: [],
  method: [],
  host: [],
  q: "",
  reason: null,
  reason_missing: false,
  created_from: null,
};

/** One ledger row: the item plus its derived host and latest reason (no note log). */
export type CoverageLedgerItem = {
  id: number;
  engagement_id: number;
  request_variant_id: number | null;
  service_id: number | null;
  application_unit_id: number | null;
  auth_context: string;
  input_slot: string;
  attack_family: string;
  status: string;
  created_at: string;
  updated_at: string;
  method: string | null;
  canonical_url: string | null;
  normalized_path: string | null;
  host: string | null;
  service_endpoint: string | null;
  service_name: string | null;
  /** Host the ledger groups the item under (request-variant or service target host). */
  item_host: string;
  /** Last recorded reason; null when only the creation note exists. */
  latest_reason: string | null;
  /** The note the item was created with. */
  created_from: string;
};

export type CoverageLedgerPage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CoverageLedgerItem[];
};

export type CoverageFacetGroup = {
  values: { value: string; count: number }[];
  distinct: number;
  omitted_count: number;
};

export type CoverageFacetName = "status" | "attack_family" | "auth_context" | "input_slot" | "method" | "host";

export type CoverageFacets = {
  /** Items matching every filter. */
  total: number;
  /** Engagement-wide counts per status, independent of filters. */
  status_totals: Record<string, number>;
  facets: Record<CoverageFacetName, CoverageFacetGroup>;
};

export type CoverageReasonEntry = {
  reason: string | null;
  created_from: string | null;
  count: number;
};

export type CoverageReasonGroup = {
  status: string;
  count: number;
  distinct: number;
  omitted_count: number;
  reasons: CoverageReasonEntry[];
};

export type CoverageReasonRollup = {
  total: number;
  statuses: CoverageReasonGroup[];
};

export type CoverageWorkItem = {
  id: number;
  status: string;
  retry_count: number;
  terminal_reason: string | null;
  triage_rationale: string | null;
  type: string;
  source: string;
  method: string;
  url: string;
  assigned_agent: string | null;
  priority_score: number;
  priority_reason: string | null;
  live_status: string | null;
  consumed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type CoverageProbeRun = {
  id: number;
  attack_family: string;
  input_slot: string;
  auth_context: string;
  payload_family: string;
  tool_name: string;
  agent_name: string;
  result_status: string;
  observed_http_status: number | null;
  signal_type: string;
  outcome_assertion: string;
  evidence_ref: string;
  notes: string;
  lens: string;
  target_host: string;
  target_path: string;
  finding_id: number | null;
  finding_slug: string | null;
  created_at: string;
};

export type CoverageBlockedTechnique = {
  id: number;
  technique_key: string;
  technique: string;
  target_kind: string;
  target_ref: string;
  reason: string;
  retry_state: string;
  evidence_ref: string;
  notes: string;
  created_at: string;
  updated_at: string;
  /** "endpoint": names this item's endpoint; "host": names its host. */
  relation: "endpoint" | "host";
};

export type CoverageItemDetail = {
  item: CoverageLedgerItem;
  note_lines: { text: string; provenance: boolean }[];
  work_items: { total: number; items: CoverageWorkItem[] };
  probe_runs: { total: number; items: CoverageProbeRun[] };
  request_variant: {
    id: number;
    method: string;
    scheme: string;
    host: string;
    port: number;
    normalized_path: string;
    path_template: string;
    canonical_url: string;
    auth_context: string;
    content_type_family: string;
    discovery_source: string;
    first_seen_at: string;
    last_seen_at: string;
  } | null;
  service: {
    id: number;
    target_id: number | null;
    endpoint: string;
    port: number | null;
    protocol: string;
    service: string;
    state: string;
    coverage_status: string;
    updated_at: string;
  } | null;
  blocked_techniques: CoverageBlockedTechnique[];
};

function base(engagementKey: string): string {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/coverage-items`;
}

/** Serialize filters as the routes expect (repeat a key per value). */
export function coverageFilterQuery(filters: CoverageFilters): URLSearchParams {
  const query = new URLSearchParams();
  for (const key of ["status", "attack_family", "auth_context", "input_slot", "method", "host"] as const) {
    for (const value of filters[key]) query.append(key, value);
  }
  if (filters.q.trim()) query.set("q", filters.q.trim());
  if (filters.reason != null) query.set("reason", filters.reason);
  if (filters.reason_missing) query.set("reason_missing", "true");
  if (filters.created_from != null) query.set("created_from", filters.created_from);
  return query;
}

export function fetchCoveragePage(
  engagementKey: string,
  filters: CoverageFilters,
  params: { sort: CoverageSortKey; dir: CoverageSortDir; limit: number; offset: number },
  init?: RequestInit,
) {
  const query = coverageFilterQuery(filters);
  query.set("sort", params.sort);
  query.set("dir", params.dir);
  query.set("limit", String(params.limit));
  query.set("offset", String(params.offset));
  return request<CoverageLedgerPage>(`${base(engagementKey)}/page?${query}`, init);
}

export function fetchCoverageFacets(engagementKey: string, filters: CoverageFilters, init?: RequestInit) {
  const qs = coverageFilterQuery(filters).toString();
  return request<CoverageFacets>(`${base(engagementKey)}/facets${qs ? `?${qs}` : ""}`, init);
}

export function fetchCoverageReasons(
  engagementKey: string,
  filters: CoverageFilters,
  reasonLimit?: number,
  init?: RequestInit,
) {
  const query = coverageFilterQuery(filters);
  if (reasonLimit != null) query.set("reason_limit", String(reasonLimit));
  const qs = query.toString();
  return request<CoverageReasonRollup>(`${base(engagementKey)}/reasons${qs ? `?${qs}` : ""}`, init);
}

export function fetchCoverageItem(engagementKey: string, coverageItemId: number, init?: RequestInit) {
  return request<CoverageItemDetail>(`${base(engagementKey)}/${coverageItemId}`, init);
}

/** Where an item sits in the page order for these filters and sort; `index` is null when it does not match. */
export type CoverageItemPosition = {
  index: number | null;
  total: number;
  previous: CoverageLedgerItem | null;
  next: CoverageLedgerItem | null;
};

export function fetchCoveragePosition(
  engagementKey: string,
  coverageItemId: number,
  filters: CoverageFilters,
  order: { sort: CoverageSortKey; dir: CoverageSortDir },
  init?: RequestInit,
) {
  const query = coverageFilterQuery(filters);
  query.set("sort", order.sort);
  query.set("dir", order.dir);
  return request<CoverageItemPosition>(`${base(engagementKey)}/${coverageItemId}/position?${query}`, init);
}
