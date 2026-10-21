// The operator command ledger (backend `services/state_manager/command_run_queries.py`
// owns the contract): server-paged rows with the matching total, facet counts
// for the filters, and a record's position for Previous / Next. Filtering,
// search, sort and the "needs attention" rule all run on the server, so every
// count covers the whole ledger. `GET /command-runs/{id}` (lib/api.ts) keeps
// the full record: command, argv and the output previews.

import { request, type AssessmentCommandRunDetail, type CommandRunStatus } from "./api.ts";
import type { SortKind } from "../components/ui/Sorting.tsx";

export type CommandScope = "attention" | "all";

/** Shared filters of the page, facets and position reads. */
export type CommandFilters = {
  /** Lifecycle statuses; any of them matches. */
  status: string[];
  /** Derived tool (tool_bin, falling back to tool_name); any of them matches. */
  tool: string[];
  agent: string[];
  /** Declared techniques, as stored (case-sensitive); "" selects runs that declared none. */
  technique: string[];
  /** Declared probe kinds, as stored; "" selects runs that declared none. */
  probe_kind: string[];
  scope: CommandScope;
  /**
   * The search-box grammar: `tool:` `agent:` `phase:` `rc:0|!0|timeout`
   * `status:` `target:` `hash:` `technique:` `probe:` `intent:`
   * `destructive:`/`write:` tokens, free terms, a run_uuid prefix, or `#id`.
   */
  q: string;
};

/** A history opens on every run; "Needs attention" is the narrower scope. */
export const DEFAULT_COMMAND_FILTERS: CommandFilters = { status: [], tool: [], agent: [], technique: [], probe_kind: [], scope: "all", q: "" };

export type CommandSortKey =
  | "created_at"
  | "started_at"
  | "completed_at"
  | "duration_ms"
  | "return_code"
  | "status"
  | "tool"
  | "agent"
  | "phase"
  | "id";

export type CommandSort = { sort: CommandSortKey; dir: "asc" | "desc" };

/** The ledger's own order: newest recorded first. */
export const DEFAULT_COMMAND_SORT: CommandSort = { sort: "created_at", dir: "desc" };

/**
 * One list row. The command text is cut to `command_preview` (its full length
 * is `command_chars`); argv, notes and the output previews come with the
 * record read. `status` is the effective lifecycle status; `needs_attention`
 * and `attention_reasons` are the server's rule; `target` is the stored
 * target host or, when none was stored, one inferred from the command.
 */
export type CommandLedgerRow = {
  id: number;
  engagement_id: number;
  run_uuid: string;
  command_preview: string;
  command_chars: number;
  tool_name: string;
  tool_bin: string;
  tool: string;
  route: string;
  agent_name: string;
  phase: string;
  audit_source: string;
  status: CommandRunStatus;
  return_code: number | null;
  timed_out: boolean;
  success: boolean;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number;
  command_hash: string;
  output_retention_status: string;
  output_cleanup_status: string;
  output_integrity_status: string;
  stdout_bytes: number;
  stderr_bytes: number;
  created_at: string;
  target_host: string;
  target: string;
  target_source: "stored" | "inferred" | "none";
  auth_context: string | null;
  superseded_by_id: number | null;
  timeout_seconds_requested: number | null;
  partial_results: boolean;
  finding_id: number | null;
  finding_slug: string | null;
  technique: string | null;
  intent: string | null;
  probe_kind: string | null;
  destructive: boolean | null;
  needs_attention: boolean;
  attention_reasons: string[];
};

export type CommandLedgerPage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CommandLedgerRow[];
};

export type CommandFacet = {
  values: Array<{ value: string; count: number }>;
  /** Distinct values, including those past the facet limit. */
  distinct: number;
  /** Runs carrying a value past the facet limit. */
  omitted_count: number;
};

export type CommandLedgerFacets = {
  /** Runs matching every filter (the page total). */
  total: number;
  /** "Needs attention N · All N" under every filter except the scope. */
  scope_totals: { attention: number; all: number };
  /** The whole ledger, ignoring every filter. */
  engagement_totals: { attention: number; all: number };
  /** Each facet ignores its own filter and honours the rest. */
  facets: { status: CommandFacet; tool: CommandFacet; agent: CommandFacet; technique: CommandFacet; probe_kind: CommandFacet };
};

export type CommandLedgerPosition = {
  /** 0-based; null when the run does not match the filters. */
  index: number | null;
  total: number;
  previous: CommandLedgerRow | null;
  next: CommandLedgerRow | null;
};

function ledgerPath(engagementKey: string, suffix: string) {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/command-runs${suffix}`;
}

function filterParams(filters: CommandFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const value of filters.status) params.append("status", value);
  for (const value of filters.tool) params.append("tool", value);
  for (const value of filters.agent) params.append("agent", value);
  for (const value of filters.technique) params.append("technique", value);
  for (const value of filters.probe_kind) params.append("probe_kind", value);
  params.set("scope", filters.scope);
  const q = filters.q.trim();
  if (q) params.set("q", q);
  return params;
}

export function fetchCommandPage(
  engagementKey: string,
  filters: CommandFilters,
  { sort, dir, limit, offset }: CommandSort & { limit: number; offset: number },
) {
  const params = filterParams(filters);
  params.set("sort", sort);
  params.set("dir", dir);
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  return request<CommandLedgerPage>(ledgerPath(engagementKey, `/page?${params}`));
}

export function fetchCommandFacets(engagementKey: string, filters: CommandFilters, facetLimit?: number) {
  const params = filterParams(filters);
  if (facetLimit != null) params.set("facet_limit", String(facetLimit));
  return request<CommandLedgerFacets>(ledgerPath(engagementKey, `/facets?${params}`));
}

export function fetchCommandPosition(engagementKey: string, id: number, filters: CommandFilters, { sort, dir }: CommandSort) {
  const params = filterParams(filters);
  params.set("sort", sort);
  params.set("dir", dir);
  return request<CommandLedgerPosition>(ledgerPath(engagementKey, `/${id}/position?${params}`));
}

export function getCommandRunRecord(engagementKey: string, id: number) {
  return request<AssessmentCommandRunDetail>(ledgerPath(engagementKey, `/${id}`));
}

/** Stable identity of a filter set (drives grid resets and stale-response checks). */
export function commandFiltersKey(filters: CommandFilters): string {
  return JSON.stringify([
    [...filters.status].sort(),
    [...filters.tool].sort(),
    [...filters.agent].sort(),
    [...filters.technique].sort(),
    [...filters.probe_kind].sort(),
    filters.scope,
    filters.q.trim(),
  ]);
}

/** Chips and search set by the operator (the scope is not counted: it has its own control). */
export function activeCommandFilterCount(filters: CommandFilters): number {
  return filters.status.length + filters.tool.length + filters.agent.length + filters.technique.length
    + filters.probe_kind.length + (filters.q.trim() ? 1 : 0);
}

// ── Grid ↔ server sort ────────────────────────────────────────────────

/** Grid column id → server sort key. Columns not listed are not sortable. */
export const COMMAND_COLUMN_SORT: Record<string, CommandSortKey> = {
  time: "created_at",
  status: "status",
  tool: "tool",
  agent: "agent",
  phase: "phase",
  duration: "duration_ms",
  rc: "return_code",
};

/** Column header, and the kind of values it sorts (for "Sorted by …"). */
export const COMMAND_SORT_LABELS: Record<CommandSortKey, { column: string; kind: SortKind }> = {
  created_at: { column: "Time", kind: "time" },
  started_at: { column: "Started", kind: "time" },
  completed_at: { column: "Finished", kind: "time" },
  duration_ms: { column: "Duration", kind: "number" },
  return_code: { column: "Exit code", kind: "number" },
  status: { column: "Status", kind: "status" },
  tool: { column: "Tool", kind: "text" },
  agent: { column: "Agent", kind: "text" },
  phase: { column: "Phase", kind: "text" },
  id: { column: "ID", kind: "number" },
};

/** The grid column that shows a server sort key (keys without a column fall back to Time). */
export function commandSortColumn(sort: CommandSort): { colId: string; dir: CommandSort["dir"] } {
  const colId = Object.keys(COMMAND_COLUMN_SORT).find((column) => COMMAND_COLUMN_SORT[column] === sort.sort);
  return colId ? { colId, dir: sort.dir } : { colId: "time", dir: DEFAULT_COMMAND_SORT.dir };
}

// ── Saved view ────────────────────────────────────────────────────────
// Scope, chips, search and sort survive leaving the tab (sessionStorage per
// engagement, written by CommandsTab). Anything unreadable falls back to the default.

export type CommandView = { filters: CommandFilters; sort: CommandSort };

export const commandViewKey = (engagementKey: string) => `commands.view.${engagementKey}`;

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function parseCommandView(raw: string | null): CommandView {
  let value: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(raw || "{}");
    if (parsed && typeof parsed === "object") value = parsed as Record<string, unknown>;
  } catch {
    // An unreadable entry is a fresh start.
  }
  const filters = (value.filters && typeof value.filters === "object" ? value.filters : {}) as Record<string, unknown>;
  const sort = (value.sort && typeof value.sort === "object" ? value.sort : {}) as Record<string, unknown>;
  const sortKey = typeof sort.sort === "string" && sort.sort in COMMAND_SORT_LABELS ? (sort.sort as CommandSortKey) : null;
  return {
    filters: {
      status: stringList(filters.status),
      tool: stringList(filters.tool),
      agent: stringList(filters.agent),
      technique: stringList(filters.technique),
      probe_kind: stringList(filters.probe_kind),
      scope: filters.scope === "attention" || filters.scope === "all" ? filters.scope : DEFAULT_COMMAND_FILTERS.scope,
      q: typeof filters.q === "string" ? filters.q : "",
    },
    sort: sortKey && (sort.dir === "asc" || sort.dir === "desc") ? { sort: sortKey, dir: sort.dir } : DEFAULT_COMMAND_SORT,
  };
}

export function commandSortFromModel(
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[],
): CommandSort {
  for (const entry of sortModel) {
    const key = COMMAND_COLUMN_SORT[entry.colId];
    if (key && (entry.sort === "asc" || entry.sort === "desc")) return { sort: key, dir: entry.sort };
  }
  return DEFAULT_COMMAND_SORT;
}

export type CommandRowsRequest = {
  startRow: number;
  endRow: number;
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[];
  successCallback: (rows: CommandLedgerRow[], lastRow?: number) => void;
  failCallback: () => void;
};

/**
 * An ag-grid infinite-row datasource over `/command-runs/page`. Each block
 * reports the server total as the last row, so the grid's scroll extent is
 * the whole matching ledger; `onPage` sees every answered block.
 */
export function createCommandDatasource(
  fetchPage: (params: CommandSort & { limit: number; offset: number }) => Promise<CommandLedgerPage>,
  handlers: { onPage?: (page: CommandLedgerPage) => void; onError?: (message: string) => void } = {},
) {
  return {
    rowCount: undefined,
    getRows(params: CommandRowsRequest) {
      const { sort, dir } = commandSortFromModel(params.sortModel);
      fetchPage({ sort, dir, limit: Math.max(1, params.endRow - params.startRow), offset: params.startRow })
        .then((page) => {
          handlers.onPage?.(page);
          params.successCallback(page.items, page.total);
        })
        .catch((error: unknown) => {
          handlers.onError?.(error instanceof Error ? error.message : String(error));
          params.failCallback();
        });
    },
  };
}

// ── Record text ───────────────────────────────────────────────────────

type ReasonFields = Pick<CommandLedgerRow, "status" | "return_code" | "timeout_seconds_requested"> & {
  attention_reasons?: string[] | null;
};

/**
 * The status pill's reason: the server's attention reasons with the exit
 * outcome after the status meaning ("finished unsuccessfully · exit code 7",
 * "exit code 0 · output cleanup deferred").
 */
export function commandStatusReason(row: ReasonFields): string {
  const reasons = row.attention_reasons ?? [];
  const exit = row.status === "timed_out" && row.timeout_seconds_requested
    ? `limit ${row.timeout_seconds_requested}s`
    : row.return_code != null
      ? `exit code ${row.return_code}`
      : row.status === "completed" || row.status === "failed"
        ? "no exit code recorded"
        : "";
  const parts = row.status !== "completed" && reasons.length
    ? [reasons[0], exit, ...reasons.slice(1)]
    : [exit, ...reasons];
  return parts.filter(Boolean).join(" · ");
}

/** A search-box token for one value, quoted when it holds spaces. */
export function searchToken(scope: string, value: string): string {
  return /\s/.test(value) ? `${scope}:"${value}"` : `${scope}:${value}`;
}
