// ── HttpTab ───────────────────────────────────────────────────────────
// Read-only view over the engagement's HTTP traffic, in two views named in the
// URL (`view=`): the endpoint inventory (one row per REQUEST VARIANT, with
// every observation recorded against it) and the captured exchanges (the
// full-flow store, `view=exchanges`). Opening a request or an exchange
// replaces the list with the shared record view; Back, Escape and browser
// Back return to the list.
//
// The inventory is server-backed end to end: paged rows with a visible total
// (`/request-variants/page`, read by the infinite grid), server search and
// facet counts (`/facets`), a deep-linked request read by id, its place in
// the paged order for Previous / Next (`/{id}/position`), and its own
// observation history (`/{id}/observations`). Nothing is counted over a
// loaded window. Exchanges filter server-side and load newest first, a page
// at a time. The grids are lazy-loaded so ag-grid lands in the shared
// code-split chunk and never bloats the main entry bundle.

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { GridApi } from "ag-grid-community";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import type {
  CapturePolicy,
  CapturePolicyUpdate,
  HttpFlow,
  HttpFlowFilters,
  RequestObservation,
  RequestVariant,
} from "../lib/api";
import {
  ApiError,
  exportHarUrl,
  getCapturePolicy,
  getHttpFlow,
  listHttpFlows,
  setCapturePolicy,
} from "../lib/api";
import {
  DEFAULT_REQUEST_VARIANT_ORDER,
  EMPTY_REQUEST_VARIANT_FILTERS,
  FLOW_PAGE_SIZE,
  FLOW_REFRESH_PROBE,
  REQUEST_VARIANT_FACETS,
  REQUEST_VARIANT_SORT_LABELS,
  activeRequestVariantFilterCount,
  fetchRequestVariant,
  fetchRequestVariantFacets,
  fetchRequestVariantObservations,
  fetchRequestVariantPosition,
  readLedgerHead,
  requestVariantFiltersKey,
  type RequestVariantFacetName,
  type RequestVariantFilters,
  type RequestVariantOrder,
} from "../lib/httpApi";
import { useToast } from "../contexts/ToastContext";
import { CodeBlock, TimeStamp, formatBytes } from "./formatting";
import { KV, KVTime, ProseSection } from "./drawer/DrawerKit";
import { CardSkeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FacetChipGroup,
  PageHeader,
  ResultsSummary,
  SegmentedControl,
  StatusPill,
  describeSort,
  statusEntry,
  statusTone,
  type FacetChipValue,
  type PageStat,
} from "./ui";
import { useCoalescedRequest } from "../lib/useCoalescedRequest";
import { useLiveRefreshToken } from "../lib/useLiveRefreshToken";
import {
  RecordBody,
  RecordCopyButton,
  RecordCopyLinkButton,
  RecordHeader,
  RecordTabs,
  RecordView,
  useResultsScrollMemory,
} from "./record/RecordView";
import { useLedgerWindow } from "./record/ledgerWindow";
import { useGridView, useRecordPosition, useWindowedNavigation, windowedReviewOrder } from "./record/recordNavigation";
import type { HttpGridWindow } from "./HttpGrid";
import "../styles/http.css";

const HttpGrid = lazy(() => import("./HttpGrid"));
const HttpFlowsGrid = lazy(() => import("./HttpFlowsGrid"));

// Which view of the HTTP tab is active: the request-variant inventory or the
// canonical full-flow store (`view=exchanges` in the URL).
type HttpView = "variants" | "flows";

// ── HTTP method colors ────────────────────────────────────────────────
// Mapped onto the Vigil palette. The class drives the colored .method-badge in
// both the grids and the record title — see app.css "HTTP method colors".
const METHOD_CLASSES: Record<string, string> = {
  GET: "m-get",
  POST: "m-post",
  PUT: "m-put",
  PATCH: "m-patch",
  DELETE: "m-delete",
  HEAD: "m-head",
  OPTIONS: "m-options",
};

export function methodClass(method: string): string {
  return METHOD_CLASSES[(method || "").toUpperCase()] || "m-other";
}

const methodColor = (method: string) => `var(--${methodClass(method)})`;

// An HTTP status code's class in the shared `http-response` vocabulary
// (2xx, 3xx, 4xx, 5xx; anything below 200 reads as 1xx).
function responseClass(status: number): string {
  const bucket = Math.floor(status / 100);
  return bucket >= 5 ? "5xx" : bucket >= 2 ? `${bucket}xx` : "1xx";
}

/** One response status code as a status pill (tone by class, the code as text). */
export function HttpStatusPill({ status, size = "sm" }: { status: number; size?: "sm" | "md" }) {
  const entry = statusEntry("http-response", responseClass(status));
  return <StatusPill value={String(status)} label={String(status)} tone={entry.tone} title={`${status}: ${entry.meaning}`} size={size} />;
}

// ── Schema pretty-print ───────────────────────────────────────────────
// The *_schema_json columns are JSON-encoded strings. Parse + re-stringify
// with 2-space indent for the record; fall back to the raw string when it
// isn't valid JSON. An empty / "{}" schema renders nothing.
function prettyJson(raw: string | null | undefined): string | null {
  const text = (raw || "").trim();
  if (!text || text === "{}" || text === "[]" || text === "null") return null;
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

// ── Icons (match CommandsTab / SurfacesTab) ───────────────────────────
const IconSearch = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    className="search-icon"
  >
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
const IconClose = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);

type ToastFn = (message: string, type?: "success" | "error" | "info") => void;

type HttpTabProps = {
  engagementKey: string;
  /** `request=` in the URL: the request variant whose record is open. */
  initialRequestVariantId?: number;
  // Bumped by EngagementPage after every successful page refresh (including
  // WebSocket-driven ones). A change triggers a silent background reload so
  // this tab stays live alongside the others without flickering to a spinner.
  refreshVersion?: number;
  /** `flow=` in the URL: the captured exchange whose record is open. */
  initialFlowId?: number;
  /** `dtab=` in the URL: the open record's section. */
  initialDrawerTab?: string;
  /** `view=` in the URL: endpoint inventory or captured exchanges. */
  initialView?: "inventory" | "exchanges";
};

// A request record reads its observation history this many at a time.
const OBSERVATION_PAGE_SIZE = 100;
const SEARCH_DEBOUNCE_MS = 300;
// A burst of live updates refreshes the inventory at most this often (with a trailing refresh).
const LIVE_REFRESH_MIN_MS = 5000;

const PURPOSE = "Every request Vigil has seen against the target. The endpoint inventory groups them into distinct request shapes; captured exchanges keep full requests and responses while full-flow capture is on.";

// ── Record sections (`dtab` in the URL) ───────────────────────────────
type VariantSection = "request" | "observations" | "schema";
const VARIANT_SECTIONS: readonly VariantSection[] = ["request", "observations", "schema"];
type FlowSection = "exchange" | "headers" | "bodies" | "routing";
const FLOW_SECTIONS: readonly FlowSection[] = ["exchange", "headers", "bodies", "routing"];

function isVariantSection(value: string | null | undefined): value is VariantSection {
  return typeof value === "string" && (VARIANT_SECTIONS as readonly string[]).includes(value);
}
function isFlowSection(value: string | null | undefined): value is FlowSection {
  return typeof value === "string" && (FLOW_SECTIONS as readonly string[]).includes(value);
}

const EMPTY_FLOWS: HttpFlow[] = [];
/** The rows a ledger window holds (null before its first page). */
type HeldFlows = HttpFlow[] | null;
const rowId = (row: { id: number }) => row.id;

function schemaBlocksOf(variant: RequestVariant): { label: string; text: string }[] {
  const fields: [string, string | undefined][] = [
    ["Query schema", variant.query_schema_json],
    ["Body schema", variant.body_schema_json],
    ["Path schema", variant.path_schema_json],
    ["Cookie schema", variant.cookie_schema_json],
    ["Header schema", variant.header_schema_json],
  ];
  return fields.flatMap(([label, raw]) => {
    const text = prettyJson(raw);
    return text ? [{ label, text }] : [];
  });
}

function viewFromRoute(initialView: HttpTabProps["initialView"], flowId?: number, requestId?: number): HttpView {
  // A record link names its view: an exchange opens the exchanges, a request the inventory.
  if (flowId !== undefined) return "flows";
  if (requestId !== undefined) return "variants";
  return initialView === "exchanges" ? "flows" : "variants";
}

/** The list URL of a view (`view=exchanges` for the exchanges; the inventory is the default). */
function listHref(engagementKey: string, view: HttpView): string {
  return engagementHref(engagementKey, { tab: "http", view: view === "flows" ? "exchanges" : undefined });
}

type ViewCounts = { variants: number | null; exchanges: { count: number; partial: boolean } | null };

export function HttpTab({ engagementKey, refreshVersion, initialRequestVariantId, initialFlowId, initialDrawerTab, initialView }: HttpTabProps) {
  const { toast } = useToast();
  const [view, setView] = useState<HttpView>(() => viewFromRoute(initialView, initialFlowId, initialRequestVariantId));
  // The URL owns the view; history and links move it.
  useEffect(() => {
    setView(viewFromRoute(initialView, initialFlowId, initialRequestVariantId));
  }, [initialView, initialFlowId, initialRequestVariantId]);
  const chooseView = useCallback((next: HttpView) => {
    setView(next);
    writeWorkspaceHash(listHref(engagementKey, next));
  }, [engagementKey]);

  // Counts each view last reported, so the switch shows both.
  const [counts, setCounts] = useState<ViewCounts>({ variants: null, exchanges: null });
  useEffect(() => setCounts({ variants: null, exchanges: null }), [engagementKey]);
  const reportVariants = useCallback((variants: number) => {
    setCounts((current) => (current.variants === variants ? current : { ...current, variants }));
  }, []);
  const reportExchanges = useCallback((count: number, partial: boolean) => {
    setCounts((current) => (current.exchanges?.count === count && current.exchanges.partial === partial
      ? current
      : { ...current, exchanges: { count, partial } }));
  }, []);

  const viewSwitch = (
    <SegmentedControl<HttpView>
      label="HTTP view"
      value={view}
      onChange={chooseView}
      options={[
        {
          value: "variants",
          label: "Endpoint inventory",
          count: counts.variants,
          description: "One row per distinct request shape (method, host, path, parameters), with every time it was seen.",
        },
        {
          value: "flows",
          label: "Captured exchanges",
          count: counts.exchanges?.count,
          countPartial: counts.exchanges?.partial,
          description: "Full request and response records the Vigil proxy captured while full-flow capture was on.",
        },
      ]}
    />
  );

  return (
    <div className="findings-redesign http-page">
      {view === "flows" ? (
        <HttpFlowsView
          key={engagementKey}
          engagementKey={engagementKey}
          refreshVersion={refreshVersion}
          toast={toast}
          initialFlowId={initialFlowId}
          initialDrawerTab={initialDrawerTab}
          viewSwitch={viewSwitch}
          onCount={reportExchanges}
        />
      ) : (
        <HttpInventoryView
          key={engagementKey}
          engagementKey={engagementKey}
          refreshVersion={refreshVersion}
          toast={toast}
          initialRequestVariantId={initialRequestVariantId}
          initialDrawerTab={initialDrawerTab}
          viewSwitch={viewSwitch}
          onTotal={reportVariants}
        />
      )}
    </div>
  );
}

/** The HTTP page header: one title and purpose for both views, hidden under an open record. */
function HttpPageHeader({ hidden, stats, status, actions, children }: {
  hidden: boolean;
  stats?: PageStat[];
  status?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <PageHeader title="HTTP" purpose={PURPOSE} stats={stats} status={status} actions={actions} hidden={hidden} className="http-head">
      {children}
    </PageHeader>
  );
}

/** A view's saved search and filters (sessionStorage, per engagement), or an empty object. */
function readSavedView(key: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(window.sessionStorage.getItem(key) || "{}");
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function writeSavedView(key: string, view: object): void {
  try {
    window.sessionStorage.setItem(key, JSON.stringify(view));
  } catch {
    // Browser storage may be unavailable; the view just resets next visit.
  }
}

const savedString = (value: unknown) => (typeof value === "string" ? value : "");
const savedStrings = (value: unknown) => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);

// ── Endpoint inventory ────────────────────────────────────────────────

const FACET_GROUPS: { name: RequestVariantFacetName; label: string; collapsedLimit?: number }[] = [
  { name: "method", label: "Method" },
  { name: "auth_context", label: "Auth" },
  { name: "source", label: "Source" },
  { name: "host", label: "Host", collapsedLimit: 6 },
  { name: "content_type", label: "Content type" },
];

/** The open request: its id, and its row once known (a deep link starts without one). */
type OpenRequest = { id: number; row: RequestVariant | null };

function HttpInventoryView({
  engagementKey,
  refreshVersion,
  toast,
  initialRequestVariantId,
  initialDrawerTab,
  viewSwitch,
  onTotal,
}: {
  engagementKey: string;
  refreshVersion?: number;
  toast: ToastFn;
  initialRequestVariantId?: number;
  initialDrawerTab?: string;
  viewSwitch: ReactNode;
  onTotal: (total: number) => void;
}) {
  // Search and filters survive leaving the tab.
  const viewKey = `http.inventory.${engagementKey}`;
  const [filters, setFilters] = useState<RequestVariantFilters>(() => {
    const saved = readSavedView(viewKey);
    const restored = { ...EMPTY_REQUEST_VARIANT_FILTERS, q: savedString(saved.q) };
    for (const name of REQUEST_VARIANT_FACETS) restored[name] = savedStrings(saved[name]);
    return restored;
  });
  const [searchText, setSearchText] = useState(filters.q);
  useEffect(() => writeSavedView(viewKey, { ...filters, q: searchText }), [viewKey, filters, searchText]);
  const [order, setOrder] = useState<RequestVariantOrder>(DEFAULT_REQUEST_VARIANT_ORDER);
  const refreshToken = useLiveRefreshToken(refreshVersion, LIVE_REFRESH_MIN_MS);
  const [gridWindow, setGridWindow] = useState<HttpGridWindow>({ total: null, first: 0, last: 0 });
  const [gridError, setGridError] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const invokerRef = useRef<HTMLElement | null>(null);
  const gridApiRef = useRef<GridApi<RequestVariant> | null>(null);

  // Typing updates the box immediately; the server sees it after a pause.
  useEffect(() => {
    if (searchText === filters.q) return undefined;
    const timer = window.setTimeout(() => setFilters((current) => ({ ...current, q: searchText })), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [searchText, filters.q]);

  const filtersKey = useMemo(() => requestVariantFiltersKey(filters), [filters]);
  const facets = useCoalescedRequest(
    `${engagementKey}\u0000${filtersKey}`,
    useCallback(() => fetchRequestVariantFacets(engagementKey, filters), [engagementKey, filters]),
    refreshToken,
  );
  const engagementTotal = facets.data?.engagement_total ?? null;
  useEffect(() => {
    if (engagementTotal != null) onTotal(engagementTotal);
  }, [engagementTotal, onTotal]);

  const activeFilterCount = activeRequestVariantFilterCount(filters);
  const toggleFacet = (name: RequestVariantFacetName, value: string) => {
    setFilters((current) => {
      const values = current[name].includes(value) ? current[name].filter((entry) => entry !== value) : [...current[name], value];
      return { ...current, [name]: values };
    });
  };
  const clearAll = () => {
    setSearchText("");
    setFilters(EMPTY_REQUEST_VARIANT_FILTERS);
  };

  // ── The open request (`request=` in the URL) ────
  const [selected, setSelected] = useState<OpenRequest | null>(initialRequestVariantId !== undefined ? { id: initialRequestVariantId, row: null } : null);
  const [lastOpenedId, setLastOpenedId] = useState<number | null>(initialRequestVariantId ?? null);
  const [section, setSection] = useState<VariantSection>(isVariantSection(initialDrawerTab) ? initialDrawerTab : "request");
  const [linkError, setLinkError] = useState<{ id: number; message: string; missing: boolean } | null>(null);
  useEffect(() => {
    if (initialRequestVariantId === undefined) {
      setSelected(null);
      return;
    }
    setLastOpenedId(initialRequestVariantId);
    setSelected((current) => (current?.id === initialRequestVariantId ? current : { id: initialRequestVariantId, row: null }));
  }, [initialRequestVariantId]);
  useEffect(() => {
    setSection(isVariantSection(initialDrawerTab) ? initialDrawerTab : "request");
  }, [initialDrawerTab]);

  // A linked request is read by id, and the open one re-read on live
  // refresh: its counts and dates move as traffic arrives.
  const selectedId = selected?.id ?? null;
  const needsRow = selected !== null && selected.row === null;
  useEffect(() => {
    if (selectedId === null) return undefined;
    if (!needsRow && refreshToken === 0) return undefined;
    let active = true;
    fetchRequestVariant(engagementKey, selectedId)
      .then((row) => {
        if (!active) return;
        setLinkError(null);
        setSelected((current) => (current?.id === row.id ? { id: row.id, row } : current));
      })
      .catch((error: unknown) => {
        if (!active) return;
        const missing = error instanceof ApiError && error.status === 404;
        setLinkError({ id: selectedId, message: error instanceof Error ? error.message : "request failed", missing });
      });
    return () => {
      active = false;
    };
    // Re-read on a live refresh even when the row is already known.
  }, [engagementKey, selectedId, needsRow, refreshToken]);

  const openRecord = useCallback((row: RequestVariant, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setSelected({ id: row.id, row });
    setLastOpenedId(row.id);
    setSection("request");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", request: row.id }));
  }, [engagementKey]);
  // Stepping keeps the open section.
  const stepTo = useCallback((row: RequestVariant) => {
    setSelected({ id: row.id, row });
    setLastOpenedId(row.id);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", request: row.id, dtab: section === "request" ? undefined : section }));
  }, [engagementKey, section]);
  const closeRecord = useCallback(() => {
    setSelected(null);
    setLinkError(null);
    writeWorkspaceHash(listHref(engagementKey, "variants"));
  }, [engagementKey]);
  const chooseSection = useCallback((next: VariantSection) => {
    setSection(next);
    if (selectedId !== null) writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", request: selectedId, dtab: next === "request" ? undefined : next }));
  }, [engagementKey, selectedId]);

  const unresolved = selected !== null && selected.row === null && linkError?.id === selected.id ? linkError : null;
  const investigating = selected !== null && unresolved === null;

  // Previous / Next walk the paged inventory in the grid's order: the server
  // locates the open request under the current filters and sort.
  const navigation = useRecordPosition<RequestVariant>({
    key: investigating && selectedId !== null ? String(selectedId) : null,
    identity: JSON.stringify([engagementKey, filtersKey, order.sort, order.dir, refreshToken]),
    load: () => fetchRequestVariantPosition(engagementKey, selectedId as number, filters, order),
    keyOf: (row) => String(row.id),
    open: stepTo,
  });
  // Back to results lands on the record last shown: scroll the grid to it
  // (by row when its block is loaded, else by its server position).
  const lastIndexRef = useRef<number | null>(null);
  if (investigating && typeof navigation.index === "number") lastIndexRef.current = navigation.index;
  const reveal = useCallback((key: string) => {
    const api = gridApiRef.current;
    if (!api) return;
    const node = api.getRowNode(key);
    if (node) api.ensureNodeVisible(node, "middle");
    else if (lastIndexRef.current !== null) api.ensureIndexVisible(lastIndexRef.current, "middle");
  }, []);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: investigating ? selectedId : null, reveal });

  // `/` focuses search (from a record too), Esc leaves the search box.
  const investigatingRef = useRef(investigating);
  investigatingRef.current = investigating;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea" || tag === "select";
      if (!isTyping && e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        if (investigatingRef.current) closeRecord();
        queueMicrotask(() => searchRef.current?.focus());
        return;
      }
      if (e.key === "Escape" && isTyping && target === searchRef.current) searchRef.current?.blur();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeRecord]);

  const empty = engagementTotal === 0;
  const noMatches = !empty && gridWindow.total === 0;
  const sortLabel = REQUEST_VARIANT_SORT_LABELS[order.sort];
  const facetGroups = facets.data?.facets;

  return (
    <>
      <HttpPageHeader
        hidden={investigating}
        stats={[{ value: engagementTotal, label: "request variants", title: "Distinct request shapes in the endpoint inventory" }]}
        status={facets.loading && facets.data ? "Updating…" : null}
      >
        {viewSwitch}
      </HttpPageHeader>

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel" hidden={investigating}>
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              type="search"
              className="search-input"
              placeholder="Search the inventory — path, host, URL, parameter, source…"
              aria-label="Search endpoint inventory"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
            {searchText && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setSearchText("")}
                title="Clear"
                aria-label="Clear endpoint search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
        </div>
        <div className="filter-row http-filter-row" hidden={empty}>
          {FACET_GROUPS.map(({ name, label, collapsedLimit }) => {
            const group = facetGroups?.[name];
            if (!group) return null;
            const selectedValues = new Set(filters[name]);
            // A dimension every variant shares filters nothing.
            if (group.distinct <= 1 && selectedValues.size === 0) return null;
            const values: FacetChipValue[] = group.values.map((entry) => ({ value: entry.value ?? "", count: entry.count }));
            return (
              <FacetChipGroup
                key={name}
                label={label}
                values={values}
                selected={selectedValues}
                onToggle={(value) => toggleFacet(name, value)}
                colorFor={name === "method" ? methodColor : undefined}
                collapsedLimit={collapsedLimit}
                unlistedCount={Math.max(0, group.distinct - group.values.length)}
              />
            );
          })}
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
        </div>
      </div>

      {facets.error && !facets.data && (
        <div className="panel findings-toolbar-panel http-banner" hidden={investigating}>
          <p className="error-text" role="alert">Endpoint inventory counts unavailable: {facets.error}</p>
        </div>
      )}
      {gridError && (
        <div className="panel findings-toolbar-panel http-banner" hidden={investigating}>
          <p className="error-text" role="alert">
            Endpoint inventory unavailable: {gridError}
            {gridWindow.total != null ? " · Showing the last loaded rows." : ""}
          </p>
        </div>
      )}
      {unresolved && (
        <p className="meta-text http-banner-text" role="status">
          {unresolved.missing
            ? `Request #${unresolved.id} is not in the endpoint inventory.`
            : `Request #${unresolved.id} could not be opened: ${unresolved.message}`}
        </p>
      )}

      {/* Inventory grid (the open record replaces it below) */}
      <div ref={resultsRef} className="http-results" hidden={investigating}>
        <section className="panel http-list-panel">
          <div className="http-list-head">
            {gridWindow.total != null ? (
              <ResultsSummary
                shown={gridWindow.total}
                total={engagementTotal}
                noun="request variants"
                sort={describeSort(sortLabel.label, order.dir, sortLabel.kind)}
              />
            ) : (
              <span className="meta-text" role="status">{facets.error || gridError ? "" : "Counting request variants…"}</span>
            )}
            {gridWindow.total != null && gridWindow.total > 0 && gridWindow.last > 0 && (
              <span className="meta-text http-window">
                Showing {gridWindow.first.toLocaleString()}–{gridWindow.last.toLocaleString()}
              </span>
            )}
          </div>
          <SlowLoadHint active={gridWindow.total == null && !gridError && !facets.error} what="the endpoint inventory" />
          {empty ? (
            <EmptyState variant="empty" title="No endpoint inventory recorded yet.">
              Agents and the Vigil proxy add a request variant for each distinct request shape they see.
            </EmptyState>
          ) : (
            <>
              {noMatches && (
                activeFilterCount > 0 ? (
                  <EmptyState variant="filtered" title="No request variants match these filters." onClearFilters={clearAll}>
                    The search and filters apply to the whole inventory of {(engagementTotal ?? 0).toLocaleString()} request variants.
                  </EmptyState>
                ) : (
                  <EmptyState variant="empty" title="No request variants to show yet." />
                )
              )}
              <div className="http-grid-wrap" hidden={noMatches}>
                <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
                  <HttpGrid
                    engagementKey={engagementKey}
                    filters={filters}
                    filtersKey={filtersKey}
                    refreshToken={refreshToken}
                    selectedId={lastOpenedId}
                    onRowOpen={openRecord}
                    onWindow={setGridWindow}
                    onError={setGridError}
                    onSortChange={setOrder}
                    onApi={(api) => { gridApiRef.current = api; }}
                  />
                </Suspense>
              </div>
            </>
          )}
        </section>
      </div>

      {investigating && selected !== null && (
        <RecordView
          label="Request record"
          noun="request"
          navigation={navigation}
          onBack={closeRecord}
          titleId="http-request-record-title"
          returnFocusRef={invokerRef}
          className="http-record"
        >
          <VariantRecord
            key={selected.id}
            engagementKey={engagementKey}
            variantId={selected.id}
            variant={selected.row}
            section={section}
            onSectionChange={chooseSection}
            refreshToken={refreshToken}
            toast={toast}
            titleId="http-request-record-title"
          />
        </RecordView>
      )}

      <div className="findings-shortcuts" hidden={investigating}>
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>[ / ]</code> previous / next in a record
        </span>
        <span>
          <code>Esc</code> back to results
        </span>
      </div>
    </>
  );
}

// ── VariantRecord ─────────────────────────────────────────────────────
// One request variant inside the shared record view: what the request is
// (method, URL, auth, discovery, hashes), every observation recorded against
// it (read from the server, newest first, a page at a time), and the
// parameter schemas Vigil inferred.

type ObservationHistory = {
  items: RequestObservation[];
  total: number;
  hasMore: boolean;
  loading: boolean;
  error: string | null;
};

function useObservationHistory(engagementKey: string, variantId: number, enabled: boolean, refreshToken: number) {
  const [history, setHistory] = useState<ObservationHistory>({ items: [], total: 0, hasMore: false, loading: true, error: null });
  const loadedRef = useRef(0);
  loadedRef.current = history.items.length;
  const requestRef = useRef(0);

  // First page, and on live refresh the pages already shown (newest first).
  useEffect(() => {
    if (!enabled) return;
    const request = ++requestRef.current;
    const limit = Math.min(500, Math.max(OBSERVATION_PAGE_SIZE, loadedRef.current));
    setHistory((current) => ({ ...current, loading: true }));
    fetchRequestVariantObservations(engagementKey, variantId, { limit, offset: 0 })
      .then((page) => {
        if (request !== requestRef.current) return;
        setHistory({ items: page.items, total: page.total, hasMore: page.has_more, loading: false, error: null });
      })
      .catch((error: unknown) => {
        if (request !== requestRef.current) return;
        setHistory((current) => ({ ...current, loading: false, error: error instanceof Error ? error.message : "request failed" }));
      });
  }, [engagementKey, variantId, enabled, refreshToken]);

  const loadMore = useCallback(() => {
    const request = ++requestRef.current;
    const offset = loadedRef.current;
    setHistory((current) => ({ ...current, loading: true }));
    fetchRequestVariantObservations(engagementKey, variantId, { limit: OBSERVATION_PAGE_SIZE, offset })
      .then((page) => {
        if (request !== requestRef.current) return;
        setHistory((current) => ({
          items: [...current.items, ...page.items.filter((item) => !current.items.some((known) => known.id === item.id))],
          total: page.total,
          hasMore: page.has_more,
          loading: false,
          error: null,
        }));
      })
      .catch((error: unknown) => {
        if (request !== requestRef.current) return;
        setHistory((current) => ({ ...current, loading: false, error: error instanceof Error ? error.message : "request failed" }));
      });
  }, [engagementKey, variantId]);

  return { history, loadMore };
}

function VariantRecord({
  engagementKey,
  variantId,
  variant,
  section,
  onSectionChange,
  refreshToken,
  toast,
  titleId,
}: {
  engagementKey: string;
  variantId: number;
  /** Null while a linked request is read by id. */
  variant: RequestVariant | null;
  section: VariantSection;
  onSectionChange: (section: VariantSection) => void;
  refreshToken: number;
  toast: ToastFn;
  titleId: string;
}) {
  const { history, loadMore } = useObservationHistory(engagementKey, variantId, variant !== null && section === "observations", refreshToken);

  if (!variant) {
    return (
      <>
        <RecordHeader id={`Request #${variantId}`} title={`Request #${variantId}`} titleId={titleId} />
        <RecordBody busy>
          <p className="meta-text" role="status">Loading request #{variantId}…</p>
          <CardSkeleton lines={4} />
        </RecordBody>
      </>
    );
  }

  const method = (variant.method || "GET").toUpperCase();
  const schemaBlocks = schemaBlocksOf(variant);
  const shownSection: VariantSection = section === "schema" && schemaBlocks.length === 0 ? "request" : section;
  const observationCount = history.items.length > 0 || !history.loading ? Math.max(history.total, variant.observation_count) : variant.observation_count;
  const remaining = Math.max(0, history.total - history.items.length);
  return (
    <>
      <RecordHeader
        id={`Request #${variant.id}`}
        copyId={String(variant.id)}
        copyIdLabel="Copy request ID"
        title={
          <>
            <span className={`method-badge ${methodClass(method)}`}>{method}</span>{" "}
            <span className="mono" title={variant.normalized_path || "/"}>{variant.normalized_path || "/"}</span>
          </>
        }
        titleId={titleId}
        accent={methodColor(method)}
        actions={
          <>
            <RecordCopyButton
              label="Copy canonical URL"
              text={() => variant.canonical_url}
              successMessage="URL copied"
              failureMessage="Could not copy the URL. Select it in the Request section instead."
              disabled={!variant.canonical_url}
            />
            <RecordCopyLinkButton noun="request" />
          </>
        }
        pills={
          <>
            <span className="tag mono" title="Host">{variant.host}</span>
            {variant.content_type_family && variant.content_type_family !== "unknown" && (
              <span className="tag" title="Content type">{variant.content_type_family}</span>
            )}
            {variant.auth_context && <span className="tag" title="Auth context">{variant.auth_context}</span>}
            {variant.discovery_source && <span className="tag" title="Discovered by">{variant.discovery_source}</span>}
            <span className="record-pill-reason">
              Seen {variant.observation_count.toLocaleString()} {variant.observation_count === 1 ? "time" : "times"}
            </span>
          </>
        }
        datesLabel="Request dates"
        dates={[
          { label: "First seen", value: variant.first_seen_at },
          { label: "Last seen", value: variant.last_seen_at },
        ]}
      />
      <RecordTabs
        label="Request sections"
        active={shownSection}
        onChange={onSectionChange}
        tabs={[
          { id: "request", label: "Request" },
          { id: "observations", label: "Observations", count: observationCount },
          { id: "schema", label: "Parameters & schema", count: schemaBlocks.length, hidden: schemaBlocks.length === 0 },
        ]}
      />
      <RecordBody>
        {shownSection === "request" && (
          <>
            <section className="section">
              <h3 className="section-title">Request</h3>
              <div className="kv-grid">
                <KV k="Method" v={method} />
                <KV k="Scheme" v={variant.scheme} />
                <KV k="Host" v={variant.host} mono toast={variant.host ? toast : undefined} />
                <KV k="Port" v={variant.port} mono />
                <KV
                  k="Canonical URL"
                  v={variant.canonical_url}
                  mono
                  toast={variant.canonical_url ? toast : undefined}
                />
                <KV k="Path template" v={variant.path_template} mono />
                <KV k="Content-Type" v={variant.content_type_family} />
                <KV k="Auth context" v={variant.auth_context} />
                <KV k="Discovery source" v={variant.discovery_source} />
                <KV
                  k="Params hash"
                  v={variant.params_schema_hash}
                  mono
                  toast={variant.params_schema_hash ? toast : undefined}
                />
                <KV
                  k="Body hash"
                  v={variant.body_schema_hash}
                  mono
                  toast={variant.body_schema_hash ? toast : undefined}
                />
                <KVTime k="First seen" v={variant.first_seen_at} />
                <KVTime k="Last seen" v={variant.last_seen_at} />
                <KVTime k="Last observed" v={variant.last_observed_at} />
              </div>
            </section>
            {variant.notes && variant.notes.trim() && (
              <ProseSection title="Notes" text={variant.notes} mode="rendered" toast={toast} kind="callout" />
            )}
          </>
        )}

        {shownSection === "observations" && (
          <section className="section">
            <h3 className="section-title">
              Observations <span className="count">{observationCount.toLocaleString()}</span>
            </h3>
            {history.error && history.items.length === 0 ? (
              <p className="error-text" role="alert">
                Observation history unavailable: {history.error}
              </p>
            ) : history.loading && history.items.length === 0 ? (
              <CardSkeleton lines={3} />
            ) : history.items.length === 0 ? (
              <EmptyState variant="empty" compact title="No observations recorded for this request yet." />
            ) : (
              <div className="http-obs-list">
                {history.items.map((o) => {
                  const payload = prettyJson(o.raw_payload);
                  return (
                    <div key={o.id} className="http-obs-card">
                      <div className="http-obs-head">
                        <span className="http-obs-url mono">{o.observed_url}</span>
                        {o.response_status != null && <HttpStatusPill status={o.response_status} />}
                      </div>
                      <div className="http-obs-meta">
                        {o.source_name && <span className="tag">{o.source_name}</span>}
                        {o.evidence_ref && <span className="tag">{o.evidence_ref}</span>}
                        <TimeStamp value={o.created_at} mode="both" fallback={null} />
                      </div>
                      {payload && (
                        <CodeBlock
                          label="Payload"
                          text={payload}
                          onCopied={() => toast("Copied", "success")}
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            {history.items.length > 0 && (
              <div className="http-older">
                <p className="meta-text">
                  {history.items.length.toLocaleString()} of {history.total.toLocaleString()} observations shown, newest first.
                </p>
                {history.hasMore && (
                  <button type="button" className="ghost-button" onClick={loadMore} disabled={history.loading}>
                    {history.loading
                      ? "Loading observations…"
                      : `Show ${Math.min(OBSERVATION_PAGE_SIZE, remaining).toLocaleString()} more ${Math.min(OBSERVATION_PAGE_SIZE, remaining) === 1 ? "observation" : "observations"}`}
                  </button>
                )}
                {history.error && (
                  <p className="error-text" role="alert">Could not load observations: {history.error}</p>
                )}
              </div>
            )}
          </section>
        )}

        {shownSection === "schema" && (
          <section className="section">
            <h3 className="section-title">Parameters & schema</h3>
            <div className="http-schema-grid">
              {schemaBlocks.map((b) => (
                <CodeBlock
                  key={b.label}
                  label={b.label}
                  text={b.text}
                  onCopied={() => toast("Copied", "success")}
                />
              ))}
            </div>
          </section>
        )}
      </RecordBody>
    </>
  );
}

// ── Flows view (canonical full-flow store) ────────────────────────────
// The second view of the HTTP tab, rendering assessment_http_flows. The
// filter set is pushed to the backend as query params so large corpora filter
// server-side. The unfiltered ledger drives the filter chips and their counts
// and is the list when no filter is active; a filter reads its own
// server-filtered ledger. Both load newest first, a page at a time.

type CapturePolicyPartialSuccess = {
  policy: CapturePolicy;
  error: string;
};

function capturePolicyPartialSuccess(error: unknown): CapturePolicyPartialSuccess | null {
  if (!(error instanceof ApiError) || !error.body || typeof error.body !== "object") return null;
  const detail = (error.body as { detail?: unknown }).detail;
  if (!detail || typeof detail !== "object") return null;
  const record = detail as Record<string, unknown>;
  if (record.database_updated !== true || record.filesystem_mirror_updated !== false) return null;
  const policy = record.policy;
  if (!policy || typeof policy !== "object") return null;
  return {
    policy: policy as CapturePolicy,
    error: typeof record.error === "string" ? record.error : "unknown mirror error",
  };
}

// Typing in the filters waits for a pause before the server sees it.
const FLOW_FILTER_DEBOUNCE_MS = 250;

/** Value → count over the loaded exchanges, most common first. */
function countBy(flows: HttpFlow[], valueOf: (flow: HttpFlow) => string | null | undefined): FacetChipValue[] {
  const counts = new Map<string, number>();
  for (const flow of flows) {
    const value = valueOf(flow);
    if (value == null || value === "") continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
}

const FLOW_SORT_LABELS: Record<string, { label: string; kind: "time" | "number" | "text" }> = {
  seen: { label: "Seen", kind: "time" },
  method: { label: "Method", kind: "text" },
  host: { label: "Host", kind: "text" },
  path: { label: "Path", kind: "text" },
  status: { label: "Status", kind: "number" },
  ctype: { label: "Content type", kind: "text" },
  auth: { label: "Auth", kind: "text" },
  reqbytes: { label: "Request size", kind: "number" },
  respbytes: { label: "Response size", kind: "number" },
};

function HttpFlowsView({
  engagementKey,
  refreshVersion,
  toast,
  initialFlowId,
  initialDrawerTab,
  viewSwitch,
  onCount,
}: {
  engagementKey: string;
  refreshVersion?: number;
  toast: ToastFn;
  initialFlowId?: number;
  initialDrawerTab?: string;
  /** The inventory / exchanges switch; hidden with the list while a record is open. */
  viewSwitch: ReactNode;
  onCount: (count: number, partial: boolean) => void;
}) {
  // Server-side filter axes (names align 1:1 with the backend query params);
  // they and the search survive leaving the tab.
  const viewKey = `http.exchanges.${engagementKey}`;
  const [saved] = useState(() => readSavedView(viewKey));
  const [host, setHost] = useState(savedString(saved.host));
  const [method, setMethod] = useState(savedString(saved.method));
  const [status, setStatus] = useState(/^\d+$/.test(savedString(saved.status)) ? savedString(saved.status) : ""); // exact response_status; "" = any
  const [ctype, setCtype] = useState(savedString(saved.ctype));
  const [auth, setAuth] = useState(savedString(saved.auth));
  const [truncated, setTruncated] = useState<"" | "true" | "false">(saved.truncated === "true" || saved.truncated === "false" ? saved.truncated : "");
  const [query, setQuery] = useState(savedString(saved.query));
  useEffect(
    () => writeSavedView(viewKey, { host, method, status, ctype, auth, truncated, query }),
    [viewKey, host, method, status, ctype, auth, truncated, query],
  );
  const searchRef = useRef<HTMLInputElement | null>(null);

  // ── Active server filters ────
  const serverFilters = useMemo<HttpFlowFilters>(() => {
    const f: HttpFlowFilters = {};
    if (host) f.host = host;
    if (method) f.method = method;
    if (status) f.response_status = Number(status);
    if (ctype) f.content_type_family = ctype;
    if (auth) f.auth_context = auth;
    if (truncated) f.truncated = truncated === "true";
    if (query.trim()) f.q = query.trim();
    return f;
  }, [host, method, status, ctype, auth, truncated, query]);
  const serverKey = JSON.stringify(serverFilters);
  const [appliedKey, setAppliedKey] = useState(serverKey);
  useEffect(() => {
    // Clearing every filter shows the unfiltered ledger at once.
    if (serverKey === "{}") {
      setAppliedKey(serverKey);
      return undefined;
    }
    const handle = window.setTimeout(() => setAppliedKey(serverKey), FLOW_FILTER_DEBOUNCE_MS);
    return () => window.clearTimeout(handle);
  }, [serverKey]);
  const filtersActive = appliedKey !== "{}";

  // A refresh of the newest page reads only the exchanges newer than those
  // held (exchanges are append-only, newest first); older pages read as asked.
  const allRowsRef = useRef<HeldFlows>(null);
  const filteredRowsRef = useRef<HeldFlows>(null);
  const fetchAll = useCallback((offset: number, limit: number) => {
    const read = (from: number, size: number) => listHttpFlows(engagementKey, { limit: size, offset: from });
    return offset === 0 ? readLedgerHead(read, allRowsRef.current, limit, rowId, FLOW_REFRESH_PROBE) : read(offset, limit);
  }, [engagementKey]);
  const fetchFiltered = useCallback((offset: number, limit: number) => {
    const filters = JSON.parse(appliedKey) as HttpFlowFilters;
    const read = (from: number, size: number) => listHttpFlows(engagementKey, { ...filters, limit: size, offset: from });
    return offset === 0 ? readLedgerHead(read, filteredRowsRef.current, limit, rowId, FLOW_REFRESH_PROBE) : read(offset, limit);
  }, [engagementKey, appliedKey]);
  const allLedger = useLedgerWindow<HttpFlow>({
    identity: engagementKey,
    pageSize: FLOW_PAGE_SIZE,
    fetchPage: fetchAll,
    keyOf: rowId,
    failureMessage: "Failed to load HTTP flows",
  });
  const filteredLedger = useLedgerWindow<HttpFlow>({
    identity: `${engagementKey}\u0000${appliedKey}`,
    pageSize: FLOW_PAGE_SIZE,
    fetchPage: fetchFiltered,
    keyOf: rowId,
    failureMessage: "Failed to filter HTTP flows",
    enabled: filtersActive,
  });
  allRowsRef.current = allLedger.rows;
  filteredRowsRef.current = filteredLedger.rows;
  const resultsLedger = filtersActive ? filteredLedger : allLedger;
  const allFlows = allLedger.rows ?? EMPTY_FLOWS;
  const results = resultsLedger.rows ?? EMPTY_FLOWS;
  const loading = allLedger.rows === null && !allLedger.error;
  const resultsLoading = serverKey !== appliedKey || resultsLedger.loading;
  const loadError = resultsLedger.error ?? (filtersActive ? null : allLedger.error);
  const allPartial = allLedger.rows !== null && !allLedger.complete;

  useEffect(() => {
    if (allLedger.rows !== null) onCount(allLedger.rows.length, allPartial);
  }, [allLedger.rows, allPartial, onCount]);

  // Live refresh, throttled like the inventory's. The unfiltered ledger feeds
  // the chips, so both re-read while a filter is on (each only its new rows).
  const refreshToken = useLiveRefreshToken(refreshVersion, LIVE_REFRESH_MIN_MS);
  const { refresh: refreshAll } = allLedger;
  const { refresh: refreshFiltered } = filteredLedger;
  useEffect(() => {
    if (refreshToken === 0) return;
    void refreshAll();
    void refreshFiltered();
  }, [refreshToken, refreshAll, refreshFiltered]);

  // ── Filter chips from the unfiltered ledger ────
  const methodValues = useMemo(() => countBy(allFlows, (f) => (f.method || "GET").toUpperCase()), [allFlows]);
  const hostValues = useMemo(() => countBy(allFlows, (f) => f.host), [allFlows]);
  const statusValues = useMemo(
    () => countBy(allFlows, (f) => (f.response_status == null ? null : String(f.response_status)))
      .sort((a, b) => Number(a.value) - Number(b.value)),
    [allFlows],
  );
  const ctypeValues = useMemo(() => countBy(allFlows, (f) => f.content_type_family), [allFlows]);
  const authValues = useMemo(() => countBy(allFlows, (f) => f.auth_context), [allFlows]);
  const truncatedCount = useMemo(
    () => allFlows.filter((f) => f.request_body_truncated || f.response_body_truncated).length,
    [allFlows],
  );

  const activeFilterCount =
    (host ? 1 : 0) +
    (method ? 1 : 0) +
    (status ? 1 : 0) +
    (ctype ? 1 : 0) +
    (auth ? 1 : 0) +
    (truncated ? 1 : 0) +
    (query ? 1 : 0);

  const clearAll = () => {
    setHost("");
    setMethod("");
    setStatus("");
    setCtype("");
    setAuth("");
    setTruncated("");
    setQuery("");
  };

  // The server filters on one value per dimension: a chip selects it, the same chip clears it.
  const pick = (setter: (value: string) => void, current: string) => (value: string) => setter(current === value ? "" : value);
  const one = (value: string) => new Set(value ? [value] : []);

  // ── The open exchange (`flow=` in the URL) ────
  const [openId, setOpenId] = useState<number | null>(initialFlowId ?? null);
  const [lastOpenedUid, setLastOpenedUid] = useState<string | null>(null);
  const [section, setSection] = useState<FlowSection>(isFlowSection(initialDrawerTab) ? initialDrawerTab : "exchange");
  const invokerRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    setOpenId(initialFlowId ?? null);
  }, [initialFlowId]);
  useEffect(() => {
    setSection(isFlowSection(initialDrawerTab) ? initialDrawerTab : "exchange");
  }, [initialDrawerTab]);

  const resultById = useMemo(() => new Map(results.map((flow) => [flow.id, flow])), [results]);
  const listedFlow = openId === null ? undefined : resultById.get(openId);
  // An exchange outside the loaded results (a link, or one a filter hides)
  // is read by id so its record shows; older pages load back to it.
  const [linked, setLinked] = useState<{ id: number; flow: HttpFlow | null; error: string | null } | null>(null);
  const linkedRef = useRef(linked);
  linkedRef.current = linked;
  const needsRead = openId !== null && resultsLedger.rows !== null && listedFlow === undefined;
  useEffect(() => {
    if (!needsRead || openId === null) return undefined;
    const known = linkedRef.current;
    if (known?.id === openId && (known.flow || known.error)) return undefined;
    let active = true;
    setLinked({ id: openId, flow: null, error: null });
    getHttpFlow(engagementKey, String(openId))
      .then((flow) => { if (active) setLinked({ id: openId, flow, error: null }); })
      .catch((error: unknown) => {
        if (active) setLinked({ id: openId, flow: null, error: error instanceof Error ? error.message : "request failed" });
      });
    return () => {
      active = false;
    };
  }, [needsRead, openId, engagementKey]);
  const openFlow = listedFlow ?? (linked?.id === openId ? linked.flow ?? undefined : undefined);
  const investigating = openId !== null && openFlow !== undefined;
  const linkError = openId !== null && listedFlow === undefined && linked?.id === openId ? linked.error : null;

  const openRecord = useCallback((flow: HttpFlow, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setOpenId(flow.id);
    setLastOpenedUid(flow.flow_uid);
    setSection("exchange");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", flow: flow.id }));
  }, [engagementKey]);
  const stepTo = useCallback((id: number) => {
    setOpenId(id);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", flow: id, dtab: section === "exchange" ? undefined : section }));
  }, [engagementKey, section]);
  const closeRecord = useCallback(() => {
    setOpenId(null);
    writeWorkspaceHash(listHref(engagementKey, "flows"));
  }, [engagementKey]);
  const chooseSection = useCallback((next: FlowSection) => {
    setSection(next);
    if (openId !== null) writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", flow: openId, dtab: next === "exchange" ? undefined : next }));
  }, [engagementKey, openId]);
  useEffect(() => {
    if (openFlow) setLastOpenedUid(openFlow.flow_uid);
  }, [openFlow]);

  const [gridView, reportGridView] = useGridView<number>();
  const review = useMemo(() => windowedReviewOrder(results.map(rowId), gridView, "seen"), [results, gridView]);
  const navigation = useWindowedNavigation({
    order: review.order,
    current: investigating ? openId : null,
    loaded: listedFlow !== undefined,
    window: resultsLedger,
    growsAt: review.growsAt,
    open: stepTo,
  });
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const flowGridApiRef = useRef<GridApi<HttpFlow> | null>(null);
  const revealFlow = useCallback((key: string) => {
    const node = flowGridApiRef.current?.getRowNode(key);
    if (node) flowGridApiRef.current?.ensureNodeVisible(node, "middle");
  }, []);
  useResultsScrollMemory(resultsRef, investigating, {
    recordKey: investigating && openFlow ? openFlow.flow_uid || String(openFlow.id) : null,
    reveal: revealFlow,
  });

  // `/` focuses search (from a record too), Esc leaves a filter field.
  const investigatingRef = useRef(investigating);
  investigatingRef.current = investigating;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea" || tag === "select";
      if (!isTyping && e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        if (investigatingRef.current) closeRecord();
        queueMicrotask(() => searchRef.current?.focus());
        return;
      }
      if (e.key === "Escape" && isTyping && !investigatingRef.current) target?.blur();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeRecord]);

  // ── HAR export honouring the active filters ────
  const onExportHar = () => {
    if (allFlows.length === 0) {
      toast("No flows to export", "info");
      return;
    }
    const url = exportHarUrl(engagementKey, serverFilters);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${engagementKey}-http-flows.har`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast("Exporting HAR…", "info");
  };

  const olderUnloaded = resultsLedger.rows !== null && !resultsLedger.complete;
  const sortEntry = gridView?.sort[0];
  const sortLabel = FLOW_SORT_LABELS[sortEntry?.colId ?? "seen"] ?? FLOW_SORT_LABELS.seen;
  const noMatches = filtersActive && !resultsLoading && resultsLedger.rows !== null && results.length === 0;

  return (
    <>
      <HttpPageHeader
        hidden={investigating}
        stats={[{
          value: allLedger.rows === null ? null : `${allFlows.length.toLocaleString()}${allPartial ? "+" : ""}`,
          label: "captured exchanges",
          title: allPartial ? "Counted among the loaded exchanges; older ones are not loaded yet" : undefined,
        }]}
        actions={(
          <button type="button" className="ui-button" onClick={onExportHar}>
            Export HAR
          </button>
        )}
      >
        {viewSwitch}
      </HttpPageHeader>
      <div className="http-flows-head" hidden={investigating}>
        <CapturePolicyControl engagementKey={engagementKey} toast={toast} />
      </div>

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel" hidden={investigating}>
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              type="search"
              className="search-input"
              placeholder="Search captured exchanges — URL, path, host…"
              aria-label="Search captured exchanges"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                aria-label="Clear exchange search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
        </div>

        <div className="filter-row http-filter-row">
          {methodValues.length > 1 || method ? (
            <FacetChipGroup label="Method" values={methodValues} selected={one(method)} onToggle={pick(setMethod, method)} colorFor={methodColor} partial={allPartial} />
          ) : null}
          {statusValues.length > 1 || status ? (
            <FacetChipGroup label="Status" values={statusValues} selected={one(status)} onToggle={pick(setStatus, status)} partial={allPartial} />
          ) : null}
          {hostValues.length > 1 || host ? (
            <FacetChipGroup label="Host" values={hostValues} selected={one(host)} onToggle={pick(setHost, host)} collapsedLimit={6} partial={allPartial} />
          ) : null}
          {ctypeValues.length > 1 || ctype ? (
            <FacetChipGroup label="Content type" values={ctypeValues} selected={one(ctype)} onToggle={pick(setCtype, ctype)} partial={allPartial} />
          ) : null}
          {authValues.length > 1 || auth ? (
            <FacetChipGroup label="Auth" values={authValues} selected={one(auth)} onToggle={pick(setAuth, auth)} partial={allPartial} />
          ) : null}
          {(truncatedCount > 0 || truncated) && (
            <FacetChipGroup
              label="Body"
              values={[{ value: "true", count: truncatedCount }, { value: "false", count: allFlows.length - truncatedCount }]
                .filter((entry) => entry.count > 0 || truncated === entry.value)}
              selected={one(truncated)}
              partial={allPartial}
              onToggle={(value) => setTruncated((current) => (current === value ? "" : value as "true" | "false"))}
              labelFor={(value) => (value === "true" ? "Truncated" : "Complete")}
              descriptionFor={(value) => (value === "true"
                ? "The request or response body was cut at the capture size cap."
                : "Both bodies were captured in full.")}
            />
          )}
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel http-banner" hidden={investigating}>
          <p className="error-text" role="alert">
            {loadError}
            {resultsLedger.rows !== null ? " · Showing the last loaded exchanges." : ""}
          </p>
        </div>
      )}
      {openId !== null && !openFlow && !linkError && resultsLedger.rows !== null && (
        <p className="meta-text http-banner-text" role="status">Loading exchange #{openId}…</p>
      )}
      {linkError && (
        <div className="panel findings-toolbar-panel http-banner">
          <p className="error-text" role="alert">Exchange #{openId} could not be opened: {linkError}</p>
        </div>
      )}

      {/* Flows table (the open record replaces it below) */}
      <div ref={resultsRef} className="http-results" hidden={investigating}>
        <section className="panel http-list-panel">
          <div className="http-list-head">
            {resultsLedger.rows !== null && !noMatches && results.length > 0 ? (
              <ResultsSummary
                shown={results.length}
                total={allFlows.length}
                partial={allPartial}
                noun="captured exchanges"
                sort={describeSort(sortLabel.label, sortEntry?.sort ?? "desc", sortLabel.kind)}
              />
            ) : (
              <span className="meta-text" role="status">{!loading && resultsLoading ? "Filtering…" : ""}</span>
            )}
            {truncatedCount > 0 && <span className="meta-text">{truncatedCount.toLocaleString()} truncated</span>}
          </div>
          <SlowLoadHint active={loading} what="the captured exchanges" />

          {loading ? (
            <TableSkeleton rows={8} showHeader={false} />
          ) : allLedger.rows === null ? null : allFlows.length === 0 ? (
            <EmptyState variant="empty" title="No full HTTP exchanges captured yet.">
              Enable full-flow capture above and route future traffic through the Vigil proxy to populate this view.
            </EmptyState>
          ) : noMatches ? (
            <EmptyState variant="filtered" title="No captured exchanges match these filters." onClearFilters={clearAll} />
          ) : resultsLedger.rows === null && resultsLedger.error ? null : (
            <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
              <HttpFlowsGrid
                rows={results}
                selectedUid={lastOpenedUid}
                onRowOpen={openRecord}
                onViewChange={reportGridView}
                onApi={(api) => { flowGridApiRef.current = api; }}
              />
            </Suspense>
          )}
          {resultsLedger.rows !== null && results.length > 0 && (olderUnloaded || resultsLedger.extendError) && (
            <div className="list-footer">
              <span>Older exchanges not loaded yet.</span>
              {olderUnloaded && (
                <button type="button" className="ui-button" onClick={() => void resultsLedger.loadOlder()} disabled={resultsLedger.extending}>
                  {resultsLedger.extending ? "Loading older exchanges…" : `Load ${FLOW_PAGE_SIZE.toLocaleString()} older exchanges`}
                </button>
              )}
              {resultsLedger.extendError && !investigating && (
                <span className="error-text" role="alert">Could not load older exchanges: {resultsLedger.extendError}</span>
              )}
            </div>
          )}
        </section>
      </div>

      {investigating && openFlow && (
        <RecordView
          label="Exchange record"
          noun="exchange"
          navigation={navigation}
          onBack={closeRecord}
          titleId="http-exchange-record-title"
          returnFocusRef={invokerRef}
          className="http-record"
        >
          <FlowRecord
            key={openFlow.id}
            engagementKey={engagementKey}
            flow={openFlow}
            section={section}
            onSectionChange={chooseSection}
            toast={toast}
            titleId="http-exchange-record-title"
          />
        </RecordView>
      )}

      <div className="findings-shortcuts" hidden={investigating}>
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>[ / ]</code> previous / next in a record
        </span>
        <span>
          <code>Esc</code> back to results
        </span>
      </div>
    </>
  );
}

// ── Capture policy control ────────────────────────────────────────────
// View + edit the per-engagement raw-body capture policy. Capture is OFF by
// default; the operator flips it on here (backend also mirrors the policy to
// capture-policy.json for the offline addon). Compact summary row with an
// expander for the body-capture toggles + max-body-bytes cap.
function CapturePolicyControl({
  engagementKey,
  toast,
}: {
  engagementKey: string;
  toast: ToastFn;
}) {
  const [policy, setPolicy] = useState<CapturePolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [maxDraft, setMaxDraft] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getCapturePolicy(engagementKey)
      .then((p) => {
        if (!cancelled) {
          setPolicy(p);
          setMaxDraft(String(p.max_body_bytes));
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load capture policy");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  const save = useCallback(
    (patch: CapturePolicyUpdate) => {
      setSaving(true);
      setCapturePolicy(engagementKey, patch)
        .then((p) => {
          setPolicy(p);
          setMaxDraft(String(p.max_body_bytes));
          setError(null);
          toast("Capture policy updated", "success");
        })
        .catch((err) => {
          const detail = capturePolicyPartialSuccess(err);
          if (detail) {
            setPolicy(detail.policy);
            setMaxDraft(String(detail.policy.max_body_bytes));
            const msg = `Policy saved to the database, but the filesystem mirror was not updated: ${detail.error}`;
            setError(msg);
            toast(msg, "error");
            return;
          }
          const msg = err instanceof Error ? err.message : "Failed to update capture policy";
          setError(msg);
          toast(msg, "error");
        })
        .finally(() => setSaving(false));
    },
    [engagementKey, toast],
  );

  if (loading) {
    return (
      <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
        <CardSkeleton lines={1} />
      </div>
    );
  }
  if (!policy) {
    return (
      <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
        <p className="error-text" role="alert" style={{ textAlign: "left" }}>
          Capture policy unavailable{error ? `: ${error}` : "."}
        </p>
      </div>
    );
  }

  const enabled = policy.enabled;
  const maxChanged = maxDraft.trim() !== "" && Number(maxDraft) !== policy.max_body_bytes;

  return (
    <div className="panel findings-toolbar-panel">
      <div className="toolbar" style={{ alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="filter-label">Capture policy</span>
          <StatusPill
            value={enabled ? "on" : "off"}
            label={`Full-flow capture ${enabled ? "on" : "off"}`}
            tone={enabled ? "success" : "neutral"}
            title={enabled ? "The Vigil proxy records full requests and responses." : "The Vigil proxy records request shapes only."}
          />
          <span className="meta-text">
            Request bodies {policy.capture_request_bodies ? "on" : "off"} · Response bodies {policy.capture_response_bodies ? "on" : "off"} · {formatBytes(policy.max_body_bytes)} cap
          </span>
          {saving && <span className="meta-text">saving…</span>}
        </div>
        <div className="toolbar-right">
          <button
            type="button"
            className={`qa-btn ${enabled ? "" : "primary"}`}
            disabled={saving}
            onClick={() => save({ enabled: !enabled })}
            aria-pressed={enabled}
          >
            {enabled ? "Disable full-flow capture" : "Enable full-flow capture"}
          </button>
          <button
            type="button"
            className="qa-btn"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-controls="http-capture-options"
          >
            {open ? "Hide options" : "Options"}
          </button>
        </div>
      </div>

      {open && (
        <div
          id="http-capture-options"
          className="filter-row"
          style={{ gap: 16, alignItems: "center", paddingTop: 10 }}
        >
          <label
            className="meta-text"
            style={{ display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer" }}
          >
            <input
              type="checkbox"
              checked={policy.capture_request_bodies}
              disabled={saving}
              onChange={(e) => save({ capture_request_bodies: e.target.checked })}
            />
            Capture request bodies
          </label>
          <label
            className="meta-text"
            style={{ display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer" }}
          >
            <input
              type="checkbox"
              checked={policy.capture_response_bodies}
              disabled={saving}
              onChange={(e) => save({ capture_response_bodies: e.target.checked })}
            />
            Capture response bodies
          </label>
          <div className="filter-select-group">
            <label className="filter-label" htmlFor="http-max-body-bytes">Max body bytes</label>
            <input
              id="http-max-body-bytes"
              className="filter-select"
              type="number"
              min={0}
              step={1024}
              value={maxDraft}
              disabled={saving}
              style={{ width: 120 }}
              onChange={(e) => setMaxDraft(e.target.value)}
            />
            <button
              type="button"
              className="qa-btn"
              disabled={saving || !maxChanged || Number.isNaN(Number(maxDraft))}
              onClick={() => save({ max_body_bytes: Math.max(0, Math.floor(Number(maxDraft))) })}
            >
              Save
            </button>
          </div>
          <span className="meta-text">
            Retention: until engagement deletion
          </span>
          <span className="meta-text">
            Content types: allow {policy.content_type_allow.join(", ") || "all"}; deny {policy.content_type_deny.join(", ") || "none"}
          </span>
        </div>
      )}
      <p className="meta-text http-capture-fidelity-note">
        Policy changes apply to future proxy traffic only; existing endpoint inventory and earlier traffic are not backfilled.
      </p>
      {error && (
        <p className="error-text" role="alert" style={{ textAlign: "left", paddingTop: 8 }}>
          {error}
        </p>
      )}
    </div>
  );
}

// ── FlowRecord ────────────────────────────────────────────────────────
// One captured exchange inside the shared record view: request/response
// metadata and the evidence export, the captured header maps, body metadata +
// truncation flags, and routing-integrity indicators (host_mismatch). Raw body
// bytes are engagement-local artifacts, not inlined here — the operator
// materialises them via Export HAR. On open the record re-reads
// GET /http-flows/{flow_uid} for the canonical row.
function FlowRecord({
  engagementKey,
  flow,
  section,
  onSectionChange,
  toast,
  titleId,
}: {
  engagementKey: string;
  flow: HttpFlow;
  section: FlowSection;
  onSectionChange: (section: FlowSection) => void;
  toast: ToastFn;
  titleId: string;
}) {
  const [canonical, setCanonical] = useState<HttpFlow | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (!flow.flow_uid) return undefined;
    getHttpFlow(engagementKey, flow.flow_uid)
      .then((full) => {
        if (!cancelled) setCanonical(full);
      })
      .catch(() => {
        // Keep the list row on failure — it already carries the full shape.
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, flow.flow_uid]);
  const row = canonical ?? flow;

  const method = (row.method || "GET").toUpperCase();
  const requestHeaders = row.request_headers ?? {};
  const responseHeaders = row.response_headers ?? {};
  const headerCount = Object.keys(requestHeaders).length + Object.keys(responseHeaders).length;
  const reqHeaders = Object.keys(requestHeaders).length > 0 ? JSON.stringify(requestHeaders, null, 2) : null;
  const respHeaders = Object.keys(responseHeaders).length > 0 ? JSON.stringify(responseHeaders, null, 2) : null;
  const notes = [
    row.response_status == null ? "no response recorded" : "",
    row.host_mismatch ? "host mismatch: URL authority, Host header and SNI disagree" : "",
    row.request_body_truncated ? "request body truncated" : "",
    row.response_body_truncated ? "response body truncated" : "",
  ].filter(Boolean);
  return (
    <>
      <RecordHeader
        id={`Exchange #${row.id}`}
        copyId={String(row.id)}
        copyIdLabel="Copy exchange ID"
        title={
          <>
            <span className={`method-badge ${methodClass(method)}`}>{method}</span>{" "}
            <span className="mono" title={row.path || row.url || "/"}>{row.path || row.url || "/"}</span>
          </>
        }
        titleId={titleId}
        tone={row.response_status == null ? "neutral" : statusTone("http-response", responseClass(row.response_status))}
        actions={
          <>
            <RecordCopyButton
              label="Copy URL"
              text={() => row.url}
              successMessage="URL copied"
              failureMessage="Could not copy the URL. Select it in the Exchange section instead."
              disabled={!row.url}
            />
            <RecordCopyLinkButton noun="exchange" />
          </>
        }
        pills={
          <>
            {row.response_status != null && <HttpStatusPill status={row.response_status} size="md" />}
            {notes.length > 0 && <span className="record-pill-reason">{notes.join(" · ")}</span>}
            {row.host && <span className="tag mono" title="Host">{row.host}</span>}
            {row.content_type_family && row.content_type_family !== "unknown" && (
              <span className="tag" title="Content type">{row.content_type_family}</span>
            )}
            {row.auth_context && <span className="tag" title="Auth context">{row.auth_context}</span>}
            {row.request_variant_id != null && (
              <a className="tag" href={engagementHref(engagementKey, { tab: "http", request: row.request_variant_id })}>Request variant #{row.request_variant_id}</a>
            )}
          </>
        }
        datesLabel="Exchange dates"
        dates={[
          { label: "Started", value: row.started_at, detail: row.timing_ms != null ? <> · took {row.timing_ms} ms</> : undefined },
          { label: "Captured", value: row.created_at },
        ]}
      />
      <RecordTabs
        label="Exchange sections"
        active={section}
        onChange={onSectionChange}
        tabs={[
          { id: "exchange", label: "Exchange" },
          { id: "headers", label: "Headers", count: headerCount },
          { id: "bodies", label: "Bodies" },
          { id: "routing", label: "Routing integrity" },
        ]}
      />
      <RecordBody>
        {section === "exchange" && (
          <>
            <section className="section">
              <h3 className="section-title">Evidence</h3>
              <p className="meta-text">
                The flow UID and body artifact paths identify the captured evidence without altering it.
              </p>
              <div className="quick-actions">
                <a
                  className="qa-btn"
                  href={exportHarUrl(engagementKey, { flow_uid: row.flow_uid })}
                  download={`${row.flow_uid}.har`}
                >
                  Export this exchange as HAR
                </a>
              </div>
            </section>
            <section className="section">
              <h3 className="section-title">Metadata</h3>
              <div className="kv-grid">
                <KV k="Method" v={method} />
                <KV k="Scheme" v={row.scheme} />
                <KV k="Host" v={row.host} mono toast={row.host ? toast : undefined} />
                <KV k="Port" v={row.port} mono />
                <KV k="URL" v={row.url} mono toast={row.url ? toast : undefined} />
                <KV k="Path" v={row.path} mono />
                <KV k="Status" v={row.response_status} />
                <KV k="Request content-type" v={row.request_content_type} />
                <KV k="Response content-type" v={row.response_content_type} />
                <KV k="Content-Type family" v={row.content_type_family} />
                <KV k="Auth context" v={row.auth_context} />
                <KV k="Timing" v={row.timing_ms != null ? `${row.timing_ms} ms` : undefined} />
                <KV k="Flow UID" v={row.flow_uid} mono toast={row.flow_uid ? toast : undefined} />
                <KVTime k="Started" v={row.started_at} />
                <KVTime k="Captured" v={row.created_at} />
              </div>
            </section>
          </>
        )}

        {section === "headers" && (
          <section className="section">
            <h3 className="section-title">Headers</h3>
            {reqHeaders || respHeaders ? (
              <div className="http-schema-grid">
                {reqHeaders && (
                  <CodeBlock
                    label="Request headers"
                    text={reqHeaders}
                    onCopied={() => toast("Copied", "success")}
                  />
                )}
                {respHeaders && (
                  <CodeBlock
                    label="Response headers"
                    text={respHeaders}
                    onCopied={() => toast("Copied", "success")}
                  />
                )}
              </div>
            ) : (
              <p className="meta-text">No headers were captured for this exchange.</p>
            )}
          </section>
        )}

        {section === "bodies" && (
          <section className="section">
            <h3 className="section-title">Bodies</h3>
            <p className="meta-text">
              Raw body bytes stay engagement-local as artifacts. Use Export HAR to materialise
              the content.
            </p>
            <div className="http-schema-grid">
              <FlowBodyMeta
                label="Request"
                contentType={row.request_content_type}
                bytes={row.request_body_bytes}
                sha={row.request_body_sha256}
                truncated={row.request_body_truncated}
                captureStatus={row.request_body_capture_status}
                captureError={row.request_body_capture_error}
                artifactPath={row.request_body_artifact_path}
                toast={toast}
              />
              <FlowBodyMeta
                label="Response"
                contentType={row.response_content_type}
                bytes={row.response_body_bytes}
                sha={row.response_body_sha256}
                truncated={row.response_body_truncated}
                captureStatus={row.response_body_capture_status}
                captureError={row.response_body_capture_error}
                artifactPath={row.response_body_artifact_path}
                toast={toast}
              />
            </div>
          </section>
        )}

        {section === "routing" && (
          <section className="section">
            <h3 className="section-title">Routing integrity</h3>
            <div className="kv-grid">
              <KV k="URL authority" v={row.url_authority} mono />
              <KV k="Host header" v={row.host_header} mono />
              <KV k="SNI" v={row.sni} mono />
              <div className="kv">
                <p className="k">Host mismatch</p>
                <p className={`v${row.host_mismatch ? " http-warn" : ""}`}>
                  {row.host_mismatch ? "yes" : "no"}
                </p>
              </div>
            </div>
          </section>
        )}
      </RecordBody>
    </>
  );
}

// Body-side metadata block (request or response). Renders a compact KV grid
// covering content-type, size, truncation flag, sha256, and the artifact path.
function FlowBodyMeta({
  label,
  contentType,
  bytes,
  sha,
  truncated,
  captureStatus,
  captureError,
  artifactPath,
  toast,
}: {
  label: string;
  contentType: string;
  bytes: number;
  sha: string;
  truncated: boolean;
  captureStatus: string;
  captureError: string;
  artifactPath: string | null;
  toast: ToastFn;
}) {
  return (
    <div>
      <div className="code-block-header">
        <span className="code-block-label">
          {label} body
          {truncated && (
            <span className="tag warning" style={{ marginLeft: 8 }}>
              truncated
            </span>
          )}
        </span>
      </div>
      <div className="kv-grid" style={{ marginTop: 6 }}>
        <KV k="Content-Type" v={contentType || "—"} />
        <KV k="Capture status" v={captureStatus || "unknown"} />
        <KV k="Capture error" v={captureError || "—"} />
        <KV k="Size" v={formatBytes(bytes)} />
        <div className="kv">
          <p className="k">Truncated</p>
          <p className="v" style={{ color: truncated ? "var(--warn)" : undefined }}>
            {truncated ? "yes" : "no"}
          </p>
        </div>
        <KV k="SHA-256" v={sha} mono toast={sha ? toast : undefined} />
        <KV k="Artifact" v={artifactPath ?? undefined} mono toast={artifactPath ? toast : undefined} />
      </div>
    </div>
  );
}
