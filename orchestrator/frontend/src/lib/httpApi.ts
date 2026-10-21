// ── HTTP inventory API ────────────────────────────────────────────────
//
// Operator reads of the endpoint inventory (request variants): a server-paged
// list with a visible total, server search and facet counts, one variant by id,
// where one variant sits in the paged order (record navigation), and one
// variant's observations. Every count comes from the server over the whole
// inventory, never from a loaded window. `GET /request-variants` (the bare list
// `vigil assess fetch` pages) is not used here.

import { request, type RequestObservation, type RequestVariant } from "./api.ts";

export type RequestVariantSortKey =
  | "last_seen_at"
  | "first_seen_at"
  | "method"
  | "path"
  | "host"
  | "port"
  | "content_type"
  | "auth_context"
  | "source"
  | "observations"
  | "id";

export type RequestVariantSortDir = "asc" | "desc";

export type RequestVariantOrder = { sort: RequestVariantSortKey; dir: RequestVariantSortDir };

export const DEFAULT_REQUEST_VARIANT_ORDER: RequestVariantOrder = { sort: "last_seen_at", dir: "desc" };

/** Facet dimensions; multi-valued filters match any of their values. */
export type RequestVariantFacetName = "method" | "auth_context" | "content_type" | "source" | "host";

export const REQUEST_VARIANT_FACETS: readonly RequestVariantFacetName[] = ["method", "auth_context", "content_type", "source", "host"];

export type RequestVariantFilters = Record<RequestVariantFacetName, string[]> & {
  /** Every whitespace-separated term must match the path, host, URL, template, a parameter name, content type, auth or source. */
  q: string;
};

export const EMPTY_REQUEST_VARIANT_FILTERS: RequestVariantFilters = {
  method: [],
  auth_context: [],
  content_type: [],
  source: [],
  host: [],
  q: "",
};

export type RequestVariantPage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: RequestVariant[];
};

export type FacetGroup = {
  values: { value: string; count: number }[];
  /** Distinct values, including any not listed. */
  distinct: number;
  /** Rows under the values not listed. */
  omitted_count: number;
};

export type RequestVariantFacets = {
  /** Variants matching every filter. */
  total: number;
  /** The whole inventory, ignoring filters. */
  engagement_total: number;
  /** Each dimension ignores its own filter. */
  facets: Record<RequestVariantFacetName, FacetGroup>;
};

/** Where a variant sits in the page order; `index` is null when it does not match the filters. */
export type RequestVariantPosition = {
  index: number | null;
  total: number;
  previous: RequestVariant | null;
  next: RequestVariant | null;
};

export type RequestObservationPage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: RequestObservation[];
};

/** Stable identity of a filter set (drives reloads and stale-response checks). */
export function requestVariantFiltersKey(filters: RequestVariantFilters): string {
  return JSON.stringify([...REQUEST_VARIANT_FACETS.map((name) => [...filters[name]].sort()), filters.q.trim()]);
}

/** Filters set by the operator (each selected value and a search count once). */
export function activeRequestVariantFilterCount(filters: RequestVariantFilters): number {
  return REQUEST_VARIANT_FACETS.reduce((sum, name) => sum + filters[name].length, 0) + (filters.q.trim() ? 1 : 0);
}

/** Serialize filters as the routes expect (repeat a key per value). */
export function requestVariantFilterQuery(filters: RequestVariantFilters): URLSearchParams {
  const query = new URLSearchParams();
  for (const name of REQUEST_VARIANT_FACETS) for (const value of filters[name]) query.append(name, value);
  if (filters.q.trim()) query.set("q", filters.q.trim());
  return query;
}

function base(engagementKey: string): string {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/request-variants`;
}

export function fetchRequestVariantPage(
  engagementKey: string,
  filters: RequestVariantFilters,
  params: RequestVariantOrder & { limit: number; offset: number },
  init?: RequestInit,
) {
  const query = requestVariantFilterQuery(filters);
  query.set("sort", params.sort);
  query.set("dir", params.dir);
  query.set("limit", String(params.limit));
  query.set("offset", String(params.offset));
  return request<RequestVariantPage>(`${base(engagementKey)}/page?${query}`, init);
}

export function fetchRequestVariantFacets(engagementKey: string, filters: RequestVariantFilters, init?: RequestInit) {
  const qs = requestVariantFilterQuery(filters).toString();
  return request<RequestVariantFacets>(`${base(engagementKey)}/facets${qs ? `?${qs}` : ""}`, init);
}

export function fetchRequestVariant(engagementKey: string, requestVariantId: number, init?: RequestInit) {
  return request<RequestVariant>(`${base(engagementKey)}/${requestVariantId}`, init);
}

export function fetchRequestVariantPosition(
  engagementKey: string,
  requestVariantId: number,
  filters: RequestVariantFilters,
  order: RequestVariantOrder,
  init?: RequestInit,
) {
  const query = requestVariantFilterQuery(filters);
  query.set("sort", order.sort);
  query.set("dir", order.dir);
  return request<RequestVariantPosition>(`${base(engagementKey)}/${requestVariantId}/position?${query}`, init);
}

/** One variant's observations, newest first. */
export function fetchRequestVariantObservations(
  engagementKey: string,
  requestVariantId: number,
  params: { limit: number; offset: number },
  init?: RequestInit,
) {
  const query = new URLSearchParams({ limit: String(params.limit), offset: String(params.offset) });
  return request<RequestObservationPage>(`${base(engagementKey)}/${requestVariantId}/observations?${query}`, init);
}

// ── Grid ↔ server sort ────────────────────────────────────────────────

/** Inventory grid column id → server sort key. Columns not listed do not sort. */
export const REQUEST_VARIANT_COLUMN_SORT: Record<string, RequestVariantSortKey> = {
  method: "method",
  path: "path",
  host: "host",
  port: "port",
  ctype: "content_type",
  auth: "auth_context",
  source: "source",
  obs: "observations",
  lastseen: "last_seen_at",
};

export function requestVariantOrderFromModel(
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[],
): RequestVariantOrder {
  for (const entry of sortModel) {
    const key = REQUEST_VARIANT_COLUMN_SORT[entry.colId];
    if (key && (entry.sort === "asc" || entry.sort === "desc")) return { sort: key, dir: entry.sort };
  }
  return DEFAULT_REQUEST_VARIANT_ORDER;
}

/** Column header names, for "Sorted by …". */
export const REQUEST_VARIANT_SORT_LABELS: Record<RequestVariantSortKey, { label: string; kind: "time" | "number" | "text" }> = {
  last_seen_at: { label: "Last seen", kind: "time" },
  first_seen_at: { label: "First seen", kind: "time" },
  method: { label: "Method", kind: "text" },
  path: { label: "Path", kind: "text" },
  host: { label: "Host", kind: "text" },
  port: { label: "Port", kind: "number" },
  content_type: { label: "Content type", kind: "text" },
  auth_context: { label: "Auth", kind: "text" },
  source: { label: "Source", kind: "text" },
  observations: { label: "Observations", kind: "number" },
  id: { label: "ID", kind: "number" },
};

export type RowsRequest<T> = {
  startRow: number;
  endRow: number;
  sortModel: readonly { colId: string; sort: "asc" | "desc" | null | undefined }[];
  successCallback: (rows: T[], lastRow?: number) => void;
  failCallback: () => void;
};

/**
 * An ag-grid infinite-row datasource over `/request-variants/page`. Every block
 * reports the server total as the last row, so the grid's scroll extent is the
 * whole matching inventory. `onPage` sees each answered block.
 */
export function createRequestVariantDatasource(
  fetchPage: (params: RequestVariantOrder & { limit: number; offset: number }) => Promise<RequestVariantPage>,
  handlers: { onPage?: (page: RequestVariantPage) => void; onError?: (message: string) => void } = {},
) {
  return {
    rowCount: undefined,
    getRows(params: RowsRequest<RequestVariant>) {
      const order = requestVariantOrderFromModel(params.sortModel);
      fetchPage({ ...order, limit: Math.max(1, params.endRow - params.startRow), offset: params.startRow })
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

// ── Captured exchanges ────────────────────────────────────────────────

/** Captured exchanges load a page this size at a time (the server's list cap). */
export const FLOW_PAGE_SIZE = 5000;
/** A live refresh first reads this many of the newest exchanges (then four times more, as needed). */
export const FLOW_REFRESH_PROBE = 25;

/**
 * The newest page of an append-only, newest-first ledger (captured exchanges
 * are never edited, and the server lists them newest first), read without
 * downloading what is already held: a short read of the newest rows finds
 * where the held rows begin, and the page is the new rows ahead of them plus
 * the held rows. While no held row shows up, each read takes four times more
 * rows, up to the whole page; a read that does not line up with what is held
 * falls back to the whole page.
 */
export async function readLedgerHead<T>(
  fetchPage: (offset: number, limit: number) => Promise<T[]>,
  held: readonly T[] | null,
  limit: number,
  keyOf: (row: T) => string | number,
  probe = FLOW_REFRESH_PROBE,
): Promise<T[]> {
  if (!held || held.length === 0) return fetchPage(0, limit);
  const newest = keyOf(held[0]);
  for (let size = Math.max(1, probe); size < limit; size *= 4) {
    const head = await fetchPage(0, size);
    const at = head.findIndex((row) => keyOf(row) === newest);
    if (at < 0) {
      // Fewer rows than asked and none held: that is the whole ledger now.
      if (head.length < size) return head;
      continue;
    }
    const linedUp = head.slice(at).every((row, index) => index < held.length && keyOf(held[index]) === keyOf(row));
    return linedUp ? [...head.slice(0, at), ...held].slice(0, limit) : fetchPage(0, limit);
  }
  return fetchPage(0, limit);
}
