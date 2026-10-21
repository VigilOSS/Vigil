// ── CoverageTab ───────────────────────────────────────────────────────
// Every test Vigil planned for the target and where it stands. The tab loads
// its own data from the coverage-ledger routes: engagement-wide status totals
// and facet counts (`/coverage-items/facets`), the latest-reason rollup
// (`/reasons`), server-paged rows (`/page`, via the grid), one item's
// explanation (`/coverage-items/{id}`) and its place in the paged order
// (`/coverage-items/{id}/position`) for the record's Previous / Next. Nothing
// is capped to a loaded slice. Opening an item replaces the list with the
// shared record view; Back, Escape and browser Back return to the list.
// The view, filters, search, closed-items choice and grid sort survive leaving
// the tab (sessionStorage, per engagement).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AssessmentSummary } from "../lib/api";
import {
  EMPTY_COVERAGE_FILTERS,
  fetchCoverageFacets,
  fetchCoveragePosition,
  fetchCoverageReasons,
  type CoverageFilters,
  type CoverageLedgerItem,
  type CoverageReasonEntry,
  type CoverageSortDir,
  type CoverageSortKey,
} from "../lib/coverageApi";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { TimeStamp } from "./formatting";
import { PageHeader, SegmentedControl } from "./ui";
import { CoverageItemRecord, isCoverageRecordTab, type CoverageRecordTab } from "./coverage/CoverageItemRecord";
import { CoverageItemsView } from "./coverage/CoverageItemsView";
import { CoverageReasonRollup } from "./coverage/CoverageReasonRollup";
import { CoverageStatusBar } from "./coverage/CoverageStatusBar";
import { OPEN_COVERAGE_STATUSES } from "./coverage/coverageStatus";
import { coverageFiltersKey, parseCoverageView, type CoverageSavedView } from "./coverage/coverageGridModel";
import { useCoalescedRequest } from "../lib/useCoalescedRequest";
import { useLiveRefreshToken } from "../lib/useLiveRefreshToken";
import { RecordView, useResultsScrollMemory } from "./record/RecordView";
import { SlowLoadHint } from "./Skeletons";
import { useRecordPosition } from "./record/recordNavigation";
import "../styles/coverage.css";

type CoverageTabProps = {
  engagementKey: string;
  /** Engagement summary; only its service-level rollup is shown here. */
  summary: AssessmentSummary | null;
  /** Bumped by the page on live updates; reloads counts and visible rows. */
  refreshVersion?: number;
  /** Coverage item whose record is open (`item` in the URL). */
  initialItemId?: number;
  /** Open record section (`dtab` in the URL). */
  initialDrawerTab?: string;
};

/** The open record: its id, and its row once known (a deep link starts without one). */
type OpenItem = { id: number; row: CoverageLedgerItem | null };

type View = "reasons" | "items";

const SEARCH_DEBOUNCE_MS = 300;
// A burst of live updates refreshes counts at most this often (with a trailing refresh).
const LIVE_REFRESH_MIN_MS = 5000;
const SHOW_ALL_REASONS_LIMIT = 5000;

const viewKey = (engagementKey: string) => `coverage.view.${engagementKey}`;

function readSavedView(engagementKey: string): CoverageSavedView {
  try {
    return parseCoverageView(window.sessionStorage.getItem(viewKey(engagementKey)));
  } catch {
    return parseCoverageView(null);
  }
}

export function CoverageTab(props: CoverageTabProps) {
  // A different engagement mounts afresh, starting from the view kept for it.
  return <CoverageWorkspace key={props.engagementKey} {...props} />;
}

function CoverageWorkspace({ engagementKey, summary, refreshVersion = 0, initialItemId, initialDrawerTab }: CoverageTabProps) {
  const [saved] = useState(() => readSavedView(engagementKey));
  const [view, setView] = useState<View>(initialItemId !== undefined ? "items" : saved.view);
  const [filters, setFilters] = useState<CoverageFilters>(saved.filters);
  const [searchText, setSearchText] = useState(saved.filters.q);
  const [includeClosed, setIncludeClosed] = useState(saved.includeClosed);
  const [showAllReasons, setShowAllReasons] = useState(false);
  // Live updates, throttled into one refresh per window plus a trailing one;
  // "Try again" after a failed read re-reads every source the same way.
  const liveToken = useLiveRefreshToken(refreshVersion, LIVE_REFRESH_MIN_MS);
  const [retryToken, setRetryToken] = useState(0);
  const refreshToken = liveToken + retryToken;
  const [selected, setSelected] = useState<OpenItem | null>(initialItemId !== undefined ? { id: initialItemId, row: null } : null);
  const [recordTab, setRecordTab] = useState<CoverageRecordTab>(isCoverageRecordTab(initialDrawerTab) ? initialDrawerTab : "why");
  const [gridSort, setGridSort] = useState<{ sort: CoverageSortKey; dir: CoverageSortDir }>(saved.sort);
  const invokerRef = useRef<HTMLElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);

  // Typing updates the box immediately; the server sees it after a pause.
  useEffect(() => {
    if (searchText === filters.q) return;
    const timer = window.setTimeout(() => setFilters((current) => ({ ...current, q: searchText })), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [searchText, filters.q]);

  // The committed view (not the half-typed search) is kept for the next visit.
  useEffect(() => {
    try {
      const kept: CoverageSavedView = { view, filters, includeClosed, sort: gridSort };
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(kept));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, view, filters, includeClosed, gridSort]);

  // The URL owns which item's record is open and which section it shows.
  useEffect(() => {
    if (initialItemId === undefined) {
      setSelected(null);
      return;
    }
    setView("items");
    setSelected((current) => (current?.id === initialItemId ? current : { id: initialItemId, row: null }));
  }, [initialItemId]);
  useEffect(() => {
    setRecordTab(isCoverageRecordTab(initialDrawerTab) ? initialDrawerTab : "why");
  }, [initialDrawerTab]);

  const openItem = useCallback((item: CoverageLedgerItem, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setSelected({ id: item.id, row: item });
    setRecordTab("why");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "coverage", item: item.id }));
  }, [engagementKey]);
  // Stepping keeps the open section, like the Findings record.
  const stepToItem = useCallback((item: CoverageLedgerItem) => {
    setSelected({ id: item.id, row: item });
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "coverage", item: item.id, dtab: recordTab === "why" ? undefined : recordTab }));
  }, [engagementKey, recordTab]);
  const closeItem = useCallback(() => {
    setSelected(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "coverage" }));
  }, [engagementKey]);
  const chooseRecordTab = useCallback((next: CoverageRecordTab) => {
    setRecordTab(next);
    if (selected) writeWorkspaceHash(engagementHref(engagementKey, { tab: "coverage", item: selected.id, dtab: next === "why" ? undefined : next }));
  }, [engagementKey, selected]);
  const acceptRow = useCallback((row: CoverageLedgerItem) => {
    setSelected((current) => (current?.id === row.id ? { id: row.id, row } : current));
  }, []);

  const retry = useCallback(() => setRetryToken((token) => token + 1), []);

  const filtersKey = useMemo(() => coverageFiltersKey(filters), [filters]);

  // Previous / Next walk the paged list in the grid's order: the server
  // locates the open item under the current filters and sort, so stepping
  // crosses block boundaries the grid has not loaded.
  const selectedId = selected?.id ?? null;
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const recordNavigation = useRecordPosition<CoverageLedgerItem>({
    key: selectedId === null ? null : String(selectedId),
    identity: JSON.stringify([engagementKey, filtersKey, gridSort.sort, gridSort.dir, refreshToken]),
    load: () => fetchCoveragePosition(engagementKey, selectedId as number, filters, gridSort),
    keyOf: (item) => String(item.id),
    open: stepToItem,
  });
  // Back to results lands on the item last shown (after stepping, or from a
  // deep link), scrolling the grid to its row.
  const revealRef = useRef<((index: number) => void) | null>(null);
  const lastIndexRef = useRef<number | null>(null);
  if (selectedId !== null && typeof recordNavigation.index === "number" && !recordNavigation.pending) {
    lastIndexRef.current = recordNavigation.index;
  }
  useResultsScrollMemory(resultsRef, selected !== null, {
    recordKey: selectedId,
    reveal: () => {
      if (lastIndexRef.current !== null) revealRef.current?.(lastIndexRef.current);
    },
  });
  const facets = useCoalescedRequest(
    `${engagementKey}\u0000${filtersKey}`,
    useCallback(() => fetchCoverageFacets(engagementKey, filters), [engagementKey, filters]),
    refreshToken,
  );

  const reasonFilters = useMemo<CoverageFilters>(
    () => ({ ...EMPTY_COVERAGE_FILTERS, status: includeClosed ? [] : [...OPEN_COVERAGE_STATUSES] }),
    [includeClosed],
  );
  const reasonLimit = showAllReasons ? SHOW_ALL_REASONS_LIMIT : undefined;
  const rollup = useCoalescedRequest(
    `${engagementKey}\u0000${includeClosed}\u0000${reasonLimit ?? ""}`,
    useCallback(
      () => fetchCoverageReasons(engagementKey, reasonFilters, reasonLimit),
      [engagementKey, reasonFilters, reasonLimit],
    ),
    refreshToken,
    view === "reasons",
  );

  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);
  useEffect(() => {
    if (facets.data) setRefreshedAt(new Date().toISOString());
  }, [facets.data]);

  const statusTotals = facets.data?.status_totals ?? null;
  const ledgerTotal = statusTotals ? Object.values(statusTotals).reduce((sum, count) => sum + count, 0) : null;
  const openTotal = statusTotals
    ? OPEN_COVERAGE_STATUSES.reduce((sum, status) => sum + (statusTotals[status] ?? 0), 0)
    : null;

  const showItems = useCallback((next: CoverageFilters) => {
    setSearchText(next.q);
    setFilters(next);
    setView("items");
  }, []);

  const pickReason = useCallback(
    (status: string, entry: CoverageReasonEntry) => {
      showItems({
        ...EMPTY_COVERAGE_FILTERS,
        status: [status],
        ...(entry.reason != null
          ? { reason: entry.reason }
          : { reason_missing: true, created_from: entry.created_from ?? "" }),
      });
    },
    [showItems],
  );

  // `/` jumps to the item search from anywhere on the tab (not over a record).
  const drawerOpenRef = useRef(false);
  drawerOpenRef.current = selected !== null;
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      if (event.key !== "/" || tag === "input" || tag === "textarea" || target?.isContentEditable) return;
      if (event.metaKey || event.ctrlKey || event.altKey || drawerOpenRef.current) return;
      event.preventDefault();
      setView("items");
      window.setTimeout(() => searchRef.current?.focus(), 0);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="cov-page">
      <PageHeader
        className="cov-head"
        title="Coverage"
        titleId="coverage-title"
        purpose="Every test Vigil planned for this target and where it stands. Blocked and deferred items always show why."
        hidden={selected !== null}
        stats={[
          { value: openTotal, label: "open", tone: openTotal ? "warning" : undefined, title: "Blocked, deferred, pending or queued items that still owe a test" },
          { value: ledgerTotal, label: ledgerTotal === 1 ? "item" : "items", title: "Every coverage item in the ledger" },
        ]}
        status={facets.loading && facets.data ? "Updating…" : refreshedAt ? <>Updated <TimeStamp value={refreshedAt} /></> : null}
      >
        <div className="cov-head-body">
          <SegmentedControl<View>
            label="Coverage view"
            value={view}
            onChange={setView}
            options={[
              {
                value: "reasons",
                label: "Open work by reason",
                description: "Blocked, deferred, pending and queued items grouped by the latest reason recorded for each.",
              },
              { value: "items", label: "All items", description: "Every item in the ledger, with search and filters." },
            ]}
          />
          {facets.error && !facets.data ? (
            <p className="error-text" role="alert">
              Coverage totals unavailable: {facets.error}{" "}
              <button type="button" className="ui-clear-filters" onClick={retry} disabled={facets.loading}>
                Try again
              </button>
            </p>
          ) : (
            <CoverageStatusBar
              totals={statusTotals}
              compact={view === "items"}
              onPickStatus={(status) => showItems({ ...EMPTY_COVERAGE_FILTERS, status: [status] })}
            />
          )}
          {!facets.data ? <SlowLoadHint active={facets.loading} what="coverage totals" detail="Large ledgers take a few seconds." /> : null}
        </div>
      </PageHeader>

      <div ref={resultsRef} className="cov-results" hidden={selected !== null}>
      {view === "reasons" ? (
        <CoverageReasonRollup
          rollup={rollup.data}
          loading={rollup.loading}
          error={rollup.error}
          onRetry={retry}
          includeClosed={includeClosed}
          onIncludeClosedChange={setIncludeClosed}
          showingAllReasons={showAllReasons}
          onShowAllReasons={() => setShowAllReasons(true)}
          onPickReason={pickReason}
          serviceGaps={summary?.service_coverage_gaps ?? []}
          ledgerTotal={ledgerTotal}
        />
      ) : (
        <CoverageItemsView
          engagementKey={engagementKey}
          filters={filters}
          filtersKey={filtersKey}
          onFiltersChange={(next) => {
            if (next.q !== filters.q) setSearchText(next.q);
            setFilters(next);
          }}
          searchText={searchText}
          onSearchTextChange={setSearchText}
          searchRef={searchRef}
          facets={facets.data}
          facetsLoading={facets.loading}
          facetsError={facets.error}
          ledgerTotal={ledgerTotal}
          refreshToken={refreshToken}
          onRetry={retry}
          selectedId={selectedId}
          onRowOpen={openItem}
          sort={gridSort}
          onSortChange={setGridSort}
          revealRef={revealRef}
        />
      )}
      </div>

      {selected ? (
        <RecordView
          label="Coverage item record"
          noun="coverage item"
          navigation={recordNavigation}
          onBack={closeItem}
          titleId="coverage-record-title"
          returnFocusRef={invokerRef}
          className={`cov-record${selected.row ? ` cov-status-${selected.row.status}` : ""}`}
        >
          <CoverageItemRecord
            key={selected.id}
            engagementKey={engagementKey}
            itemId={selected.id}
            row={selected.row}
            tab={recordTab}
            onTabChange={chooseRecordTab}
            titleId="coverage-record-title"
            refreshToken={refreshToken}
            onRow={acceptRow}
          />
        </RecordView>
      ) : null}
    </div>
  );
}
