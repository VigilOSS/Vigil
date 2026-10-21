// "All items": the whole ledger behind server-counted facets and search,
// rendered by the infinite-scrolling grid. The total is always visible.

import { lazy, Suspense, useState, type MutableRefObject, type RefObject } from "react";
import { Search, X } from "lucide-react";
import {
  EMPTY_COVERAGE_FILTERS,
  type CoverageFacetName,
  type CoverageFacets,
  type CoverageFilters,
  type CoverageLedgerItem,
  type CoverageSortDir,
  type CoverageSortKey,
} from "../../lib/coverageApi";
import { TableSkeleton } from "../Skeletons";
import { ClearFiltersButton, EmptyState, FilterChip, FilterGroup, ResultsSummary, describeSort } from "../ui";
import { CoverageFacetMenu } from "./CoverageFacetMenu";
import { COVERAGE_STATUS_ORDER, compareCoverageStatus, facetValueLabel } from "./coverageStatus";
import { COVERAGE_SORT_LABELS } from "./coverageGridModel";

const CoverageGrid = lazy(() => import("./CoverageGrid"));

type MultiKey = "status" | "attack_family" | "auth_context" | "input_slot" | "method" | "host";

// Dimensions offered as menus (status is always visible as chips).
const MENU_FACETS: { key: Exclude<MultiKey, "status">; facet: CoverageFacetName; label: string }[] = [
  { key: "host", facet: "host", label: "Host" },
  { key: "attack_family", facet: "attack_family", label: "Attack family" },
  { key: "auth_context", facet: "auth_context", label: "Auth" },
  { key: "input_slot", facet: "input_slot", label: "Input slot" },
  { key: "method", facet: "method", label: "Method" },
];

type Order = { sort: CoverageSortKey; dir: CoverageSortDir };

type Props = {
  engagementKey: string;
  filters: CoverageFilters;
  filtersKey: string;
  onFiltersChange: (next: CoverageFilters) => void;
  searchText: string;
  onSearchTextChange: (value: string) => void;
  searchRef: RefObject<HTMLInputElement | null>;
  facets: CoverageFacets | null;
  facetsLoading: boolean;
  facetsError: string | null;
  ledgerTotal: number | null;
  refreshToken: number;
  /** Re-reads after a failed load. */
  onRetry: () => void;
  selectedId: number | null;
  onRowOpen: (item: CoverageLedgerItem, invoker: HTMLElement | null) => void;
  /** The order the grid shows; the tab keeps it across view switches. */
  sort: Order;
  onSortChange: (order: Order) => void;
  revealRef?: MutableRefObject<((index: number) => void) | null>;
};

type GridWindow = { total: number | null; first: number; last: number };

export function CoverageItemsView({
  engagementKey,
  filters,
  filtersKey,
  onFiltersChange,
  searchText,
  onSearchTextChange,
  searchRef,
  facets,
  facetsLoading,
  facetsError,
  ledgerTotal,
  refreshToken,
  onRetry,
  selectedId,
  onRowOpen,
  sort,
  onSortChange,
  revealRef,
}: Props) {
  const [gridWindow, setGridWindow] = useState<GridWindow>({ total: null, first: 0, last: 0 });
  const [gridError, setGridError] = useState<string | null>(null);

  const toggle = (key: MultiKey, value: string) => {
    const current = filters[key];
    const next = current.includes(value) ? current.filter((entry) => entry !== value) : [...current, value];
    onFiltersChange({ ...filters, [key]: next });
  };

  const reasonActive = filters.reason != null || filters.reason_missing || filters.created_from != null;
  const activeCount =
    filters.status.length
    + MENU_FACETS.reduce((sum, menu) => sum + filters[menu.key].length, 0)
    + (filters.q.trim() ? 1 : 0)
    + (reasonActive ? 1 : 0);
  const clearAll = () => {
    onSearchTextChange("");
    onFiltersChange(EMPTY_COVERAGE_FILTERS);
  };

  const statusValues = [...(facets?.facets.status.values ?? [])];
  // Selected statuses, and statuses the ledger has but the other filters
  // exclude, stay on the row at zero so it never reshuffles.
  for (const status of [...filters.status, ...COVERAGE_STATUS_ORDER]) {
    const known = filters.status.includes(status) || (facets?.status_totals[status] ?? 0) > 0;
    if (known && !statusValues.some((entry) => entry.value === status)) statusValues.push({ value: status, count: 0 });
  }
  statusValues.sort((a, b) => compareCoverageStatus(a.value, b.value));

  const total = gridWindow.total ?? facets?.total ?? null;
  const sortLabel = COVERAGE_SORT_LABELS[sort.sort];
  const sortText = describeSort(sortLabel.label, sort.dir, sortLabel.kind);
  const empty = gridWindow.total === 0;
  // An empty ledger and an empty filter result read differently.
  const nothingRecorded = empty && activeCount === 0 && (ledgerTotal ?? 0) === 0;

  return (
    <section className="panel cov-items" aria-label="All coverage items">
      <div className="cov-toolbar">
        <label className="cov-search">
          <Search size={14} aria-hidden="true" />
          <input
            ref={searchRef}
            type="search"
            aria-label="Search coverage items"
            placeholder="Search URL, family, slot, auth or notes…"
            value={searchText}
            onChange={(event) => onSearchTextChange(event.target.value)}
          />
          {searchText ? (
            <button type="button" className="cov-icon-button" aria-label="Clear search" onClick={() => onSearchTextChange("")}>
              <X size={13} aria-hidden="true" />
            </button>
          ) : (
            <kbd className="cov-kbd" aria-hidden="true">/</kbd>
          )}
        </label>
        <div className={`cov-menus ${facetsLoading && facets ? "cov-stale" : ""}`}>
          {MENU_FACETS.map((menu) => (
            <CoverageFacetMenu
              key={menu.key}
              label={menu.label}
              group={facets?.facets[menu.facet]}
              active={filters[menu.key]}
              formatValue={(value) => facetValueLabel(menu.key, value)}
              onToggle={(value) => toggle(menu.key, value)}
              allowCustom={menu.key === "host" ? (typed) => typed.trim().toLowerCase() || null : undefined}
            />
          ))}
        </div>
      </div>

      <div className={`cov-status-chips ${facetsLoading && facets ? "cov-stale" : ""}`}>
        <FilterGroup label="Status">
          {statusValues.map((entry) => (
            <FilterChip
              key={entry.value}
              label={facetValueLabel("status", entry.value)}
              status={{ domain: "coverage", value: entry.value }}
              count={entry.count}
              selected={filters.status.includes(entry.value)}
              onToggle={() => toggle("status", entry.value)}
            />
          ))}
        </FilterGroup>
        {facetsError ? <span className="error-text" role="alert">Filter counts unavailable: {facetsError}</span> : null}
      </div>

      {activeCount > 0 ? (
        <div className="cov-active" aria-label="Active filters">
          {reasonActive ? (
            <span className="cov-active-chip cov-active-reason">
              <span className="cov-active-key">Reason</span>
              <span className="cov-active-value" title={filters.reason ?? filters.created_from ?? undefined}>
                {filters.reason != null
                  ? filters.reason
                  : `No reason recorded${filters.created_from != null ? ` · created from: ${filters.created_from || "—"}` : ""}`}
              </span>
              <button
                type="button"
                className="cov-icon-button"
                aria-label="Remove reason filter"
                onClick={() => onFiltersChange({ ...filters, reason: null, reason_missing: false, created_from: null })}
              >
                <X size={12} aria-hidden="true" />
              </button>
            </span>
          ) : null}
          {MENU_FACETS.flatMap((menu) =>
            filters[menu.key].map((value) => (
              <span key={`${menu.key}:${value}`} className="cov-active-chip">
                <span className="cov-active-key">{menu.label}</span>
                <span className="cov-active-value">{facetValueLabel(menu.key, value)}</span>
                <button
                  type="button"
                  className="cov-icon-button"
                  aria-label={`Remove ${menu.label.toLowerCase()} ${facetValueLabel(menu.key, value)}`}
                  onClick={() => toggle(menu.key, value)}
                >
                  <X size={12} aria-hidden="true" />
                </button>
              </span>
            )),
          )}
          <ClearFiltersButton count={activeCount} onClear={clearAll} />
        </div>
      ) : null}

      <div className="cov-count-row">
        {total == null ? (
          <p className="ui-results-summary" role="status">Counting matching items…</p>
        ) : (
          <ResultsSummary
            shown={total}
            total={ledgerTotal != null && ledgerTotal !== total ? ledgerTotal : null}
            noun={(ledgerTotal ?? total) === 1 ? "coverage item" : "coverage items"}
            sort={sortText}
          />
        )}
        <p className="meta-text">
          {gridWindow.total != null && gridWindow.last > 0
            ? `Rows ${gridWindow.first.toLocaleString()}–${gridWindow.last.toLocaleString()} in view · `
            : ""}
          Select a row for its full history and related work.
        </p>
      </div>
      {gridError ? (
        <p className="error-text" role="alert">
          Coverage items unavailable: {gridError}{" "}
          <button type="button" className="ui-clear-filters" onClick={onRetry}>
            Try again
          </button>
        </p>
      ) : null}

      {empty ? (
        nothingRecorded ? (
          <EmptyState variant="empty" title="No coverage items recorded yet.">
            Items appear as Vigil observes the target's requests and services.
          </EmptyState>
        ) : (
          <EmptyState variant="filtered" title="No coverage items match these filters." onClearFilters={clearAll} />
        )
      ) : null}
      <div className={empty ? "cov-grid-hidden" : undefined}>
        <Suspense fallback={<TableSkeleton rows={10} showHeader />}>
          <CoverageGrid
            engagementKey={engagementKey}
            filters={filters}
            filtersKey={filtersKey}
            refreshToken={refreshToken}
            selectedId={selectedId}
            sort={sort}
            onRowOpen={onRowOpen}
            onWindow={setGridWindow}
            onError={setGridError}
            onSortChange={onSortChange}
            revealRef={revealRef}
          />
        </Suspense>
      </div>
    </section>
  );
}
