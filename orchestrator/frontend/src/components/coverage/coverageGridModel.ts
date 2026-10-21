// Pure pieces of the coverage grid: column -> server sort mapping, the
// infinite-row datasource, and sort labels. Kept out of the lazy
// grid module so they are testable without rendering ag-grid.

import {
  EMPTY_COVERAGE_FILTERS,
  type CoverageFilters,
  type CoverageLedgerItem,
  type CoverageLedgerPage,
  type CoverageSortDir,
  type CoverageSortKey,
} from "../../lib/coverageApi";
import type { SortKind } from "../ui";

export const COVERAGE_GRID_BLOCK_SIZE = 100;

/** Grid column id -> server sort key. Columns not listed are not sortable. */
export const COVERAGE_COLUMN_SORT: Record<string, CoverageSortKey> = {
  status: "status",
  url: "url",
  family: "attack_family",
  slot: "input_slot",
  auth: "auth_context",
  host: "host",
  updated: "updated_at",
};

export const DEFAULT_COVERAGE_SORT: { sort: CoverageSortKey; dir: CoverageSortDir } = {
  sort: "updated_at",
  dir: "desc",
};

/** The grid column a server sort is shown on (null when no column shows it). */
export function columnForServerSort(sort: CoverageSortKey): string | null {
  return Object.keys(COVERAGE_COLUMN_SORT).find((colId) => COVERAGE_COLUMN_SORT[colId] === sort) ?? null;
}

/**
 * A column's starting sort for a grid that mounts on `order` (the tab keeps
 * the order across view switches, so a remounted grid shows the same order
 * the record's Previous / Next walk).
 */
export function columnInitialSort(
  colId: string,
  order: { sort: CoverageSortKey; dir: CoverageSortDir },
): CoverageSortDir | undefined {
  return columnForServerSort(order.sort) === colId ? order.dir : undefined;
}

/** How each server sort reads in "Sorted by …" (column name and value kind). */
export const COVERAGE_SORT_LABELS: Record<CoverageSortKey, { label: string; kind: SortKind }> = {
  updated_at: { label: "Updated", kind: "time" },
  created_at: { label: "Created", kind: "time" },
  status: { label: "Status", kind: "status" },
  attack_family: { label: "Family", kind: "text" },
  input_slot: { label: "Input slot", kind: "text" },
  auth_context: { label: "Auth", kind: "text" },
  method: { label: "Method", kind: "text" },
  url: { label: "Method + URL", kind: "text" },
  host: { label: "Host", kind: "text" },
  id: { label: "Item ID", kind: "number" },
};

export function serverSortFromModel(
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[],
): { sort: CoverageSortKey; dir: CoverageSortDir } {
  for (const entry of sortModel) {
    const key = COVERAGE_COLUMN_SORT[entry.colId];
    if (key && (entry.sort === "asc" || entry.sort === "desc")) return { sort: key, dir: entry.sort };
  }
  return DEFAULT_COVERAGE_SORT;
}

export type CoverageRowsRequest = {
  startRow: number;
  endRow: number;
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[];
  successCallback: (rows: CoverageLedgerItem[], lastRow?: number) => void;
  failCallback: () => void;
};

export type CoveragePageFetcher = (params: {
  sort: CoverageSortKey;
  dir: CoverageSortDir;
  limit: number;
  offset: number;
}) => Promise<CoverageLedgerPage>;

/**
 * An ag-grid infinite-row datasource over `/coverage-items/page`. Every block
 * reports the server total as the last row, so the grid's scroll extent is the
 * whole matching ledger. `onPage` sees each answered block (for the totals line).
 */
export function createCoverageDatasource(
  fetchPage: CoveragePageFetcher,
  handlers: { onPage?: (page: CoverageLedgerPage) => void; onError?: (message: string) => void } = {},
) {
  return {
    rowCount: undefined,
    getRows(params: CoverageRowsRequest) {
      const { sort, dir } = serverSortFromModel(params.sortModel);
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

/** Stable identity of a filter set (drives reloads and stale-response checks). */
export function coverageFiltersKey(filters: CoverageFilters): string {
  return JSON.stringify([
    [...filters.status].sort(),
    [...filters.attack_family].sort(),
    [...filters.auth_context].sort(),
    [...filters.input_slot].sort(),
    [...filters.method].sort(),
    [...filters.host].sort(),
    filters.q.trim(),
    filters.reason ?? null,
    Boolean(filters.reason_missing),
    filters.created_from ?? null,
  ]);
}

/** "GET /orders?id=1" style label for a row (service-bound rows show their endpoint). */
export function coverageTargetLabel(item: Pick<CoverageLedgerItem, "method" | "canonical_url" | "service_endpoint">): {
  method: string;
  target: string;
} {
  if (item.canonical_url) {
    try {
      const url = new URL(item.canonical_url);
      return { method: item.method ?? "", target: `${url.pathname}${url.search}` };
    } catch {
      return { method: item.method ?? "", target: item.canonical_url };
    }
  }
  return { method: item.method ?? "", target: item.service_endpoint || "Unbound item" };
}

/** What the tab keeps across visits (sessionStorage, per engagement). */
export type CoverageSavedView = {
  view: "reasons" | "items";
  filters: CoverageFilters;
  includeClosed: boolean;
  sort: { sort: CoverageSortKey; dir: CoverageSortDir };
};

const MULTI_FILTERS = ["status", "attack_family", "auth_context", "input_slot", "method", "host"] as const;

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
const optionalString = (value: unknown): string | null => (typeof value === "string" ? value : null);

/** A saved view, or the defaults for anything missing or malformed. */
export function parseCoverageView(raw: string | null): CoverageSavedView {
  let value: Record<string, unknown> = {};
  try {
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (parsed && typeof parsed === "object") value = parsed as Record<string, unknown>;
  } catch {
    // A malformed entry falls back to the defaults.
  }
  const saved = (value.filters && typeof value.filters === "object" ? value.filters : {}) as Record<string, unknown>;
  const filters: CoverageFilters = { ...EMPTY_COVERAGE_FILTERS, q: typeof saved.q === "string" ? saved.q : "" };
  for (const key of MULTI_FILTERS) filters[key] = strings(saved[key]);
  filters.reason = optionalString(saved.reason);
  filters.reason_missing = saved.reason_missing === true;
  filters.created_from = optionalString(saved.created_from);
  const order = (value.sort && typeof value.sort === "object" ? value.sort : {}) as Record<string, unknown>;
  const sortKey = typeof order.sort === "string" && order.sort in COVERAGE_SORT_LABELS ? (order.sort as CoverageSortKey) : null;
  const sortDir = order.dir === "asc" || order.dir === "desc" ? order.dir : null;
  return {
    view: value.view === "items" ? "items" : "reasons",
    filters,
    includeClosed: value.includeClosed === true,
    sort: sortKey && sortDir ? { sort: sortKey, dir: sortDir } : DEFAULT_COVERAGE_SORT,
  };
}
