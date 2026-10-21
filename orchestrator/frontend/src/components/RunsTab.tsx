// ── RunsTab ───────────────────────────────────────────────────────────
// The Runs workspace: every evidence-gathering session, newest first, with
// the shared "Needs attention" scope and filters for what an operator triages
// by (health, track, live evidence, blockers, time, role, finding, client).
// Opening a run replaces the list with the shared record view; Back, Escape
// and browser Back return to the list, on the run last shown.
//
// Loading: one list read per refresh signal. Refreshes coalesce — one read
// in flight, one trailing re-read if more signals arrived — and the last
// loaded list stays on screen while a refresh runs or fails. Search, chips,
// scope and grid sort survive leaving the tab (sessionStorage, per engagement).

import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GridApi } from "ag-grid-community";
import { Search, X } from "lucide-react";

import "../styles/runs.css";
import { createCoalescedRunner } from "../lib/coalesce";
import {
  EMPTY_RUN_FILTERS,
  RUN_ATTENTION_HEALTH,
  RUN_ATTENTION_RULE,
  RUN_SORT_COLUMNS,
  RUN_TIME_RANGES,
  activeRunFilterCount,
  collectBarePages,
  compareRunRowsNewestFirst,
  currentBlockers,
  defaultSectionForRun,
  deriveRunRow,
  filterRuns,
  invalidRunLink,
  isRunAuditSection,
  parseRunsView,
  runFacetCounts,
  serializeRunsView,
  statusText,
  type RunAuditSection,
  type RunFilters,
  type RunHealthKey,
  type RunRow,
  type RunScope,
  type RunSort,
} from "../lib/runAudit";
import { getAssessmentRun, listAssessmentRuns, type AssessmentRun } from "../lib/api";
import { engagementHref, parseWorkspaceRoute, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { useViewportPane } from "../lib/viewportPane";
import { CardSkeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";
import { isRunRecordTab, RunDetail, runRecordTabForSection, type RunRecordTab } from "./RunDetail";
import { RecordView, useResultsScrollMemory } from "./record/RecordView";
import { listNavigation, useGridView } from "./record/recordNavigation";
import {
  ClearFiltersButton,
  EmptyState,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  describeSort,
  statusLabel,
  statusOrder,
} from "./ui";

const RunsGrid = lazy(() => import("./RunsGrid"));

const RUN_PAGE_SIZE = 200;
const HEALTH_ORDER = statusOrder("run-health") as RunHealthKey[];
// The grid never shrinks below this; shorter windows scroll the page.
const MIN_GRID_HEIGHT = 260;

type RunsTabProps = {
  engagementKey: string;
  refreshVersion?: number;
  initialRunId?: number;
  initialSection?: string;
  initialObject?: string;
  /** Open record section (`dtab`). */
  initialDrawerTab?: string;
  /** Reports run health after each successful list load (feeds the rail badge). */
  onHealthCounts?: (counts: Record<RunHealthKey, number>) => void;
};

function validSection(value: string | undefined): RunAuditSection | null {
  return isRunAuditSection(value) ? value : null;
}

function toggled<T>(values: ReadonlySet<T>, value: T): Set<T> {
  const next = new Set(values);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

const viewKey = (engagementKey: string) => `runs.queue.${engagementKey}`;

function readSavedView(engagementKey: string) {
  try {
    return parseRunsView(window.sessionStorage.getItem(viewKey(engagementKey)));
  } catch {
    return parseRunsView(null);
  }
}

/** A `run=` value in the address that names no run (the route parser drops it). */
function readInvalidRunLink(): string | null {
  if (typeof window === "undefined") return null;
  const route = parseWorkspaceRoute(window.location.hash);
  return route.kind === "engagement" ? invalidRunLink(route.params) : null;
}

export function RunsTab(props: RunsTabProps) {
  return <RunsWorkspace key={props.engagementKey} {...props} />;
}

function RunsWorkspace({
  engagementKey,
  refreshVersion = 0,
  initialRunId,
  initialSection,
  initialObject,
  initialDrawerTab,
  onHealthCounts,
}: RunsTabProps) {
  const [saved] = useState(() => readSavedView(engagementKey));
  const [runs, setRuns] = useState<AssessmentRun[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(initialRunId ?? null);
  const [chosenSection, setChosenSection] = useState<RunAuditSection | null>(validSection(initialSection));
  const [chosenTab, setChosenTab] = useState<RunRecordTab | null>(isRunRecordTab(initialDrawerTab) ? initialDrawerTab : null);
  const [gridView, reportGridView] = useGridView<number>();
  const gridApiRef = useRef<GridApi<RunRow> | null>(null);
  const setGridApi = useCallback((api: GridApi<RunRow> | null) => { gridApiRef.current = api; }, []);
  const [linkedRun, setLinkedRun] = useState<{ id: number; run: AssessmentRun | null; error: string | null } | null>(null);
  const [filters, setFilters] = useState<RunFilters>(saved.filters);
  const [scope, setScope] = useState<RunScope>(saved.scope);
  const [badRunLink, setBadRunLink] = useState<string | null>(readInvalidRunLink);
  const invokerRef = useRef<HTMLElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const aliveRef = useRef(true);

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  useEffect(() => {
    const onHash = () => setBadRunLink(readInvalidRunLink());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const loadRuns = useMemo(() => createCoalescedRunner(async () => {
    setLoading(true);
    try {
      const all = await collectBarePages(
        (offset, limit) => listAssessmentRuns(engagementKey, { limit, offset }),
        RUN_PAGE_SIZE,
      );
      if (!aliveRef.current) return;
      setRuns(all);
      setError(null);
    } catch (failure) {
      if (aliveRef.current) setError(failure instanceof Error ? failure.message : "Failed to load assessment runs");
    } finally {
      if (aliveRef.current) setLoading(false);
    }
  }), [engagementKey]);

  useEffect(() => {
    void loadRuns("join");
  }, [loadRuns]);

  const seenVersion = useRef(refreshVersion);
  useEffect(() => {
    if (seenVersion.current === refreshVersion) return;
    seenVersion.current = refreshVersion;
    void loadRuns("refresh");
  }, [loadRuns, refreshVersion]);

  // The URL owns which run is open and which record section it shows.
  useEffect(() => {
    setSelectedRunId(initialRunId ?? null);
  }, [initialRunId]);
  useEffect(() => {
    setChosenSection(validSection(initialSection));
  }, [initialSection]);
  useEffect(() => {
    setChosenTab(isRunRecordTab(initialDrawerTab) ? initialDrawerTab : null);
  }, [initialDrawerTab]);

  const listedRun = selectedRunId === null ? undefined : runs?.find((run) => run.id === selectedRunId);
  // A deep link can name a run the list does not hold (another page of a
  // concurrent write, or a mistyped id): read it once so the record opens or
  // explains why it cannot. The read depends only on which run is wanted, so
  // recording its progress never cancels it.
  const linkedReadId = selectedRunId !== null && runs !== null && !listedRun ? selectedRunId : null;
  useEffect(() => {
    if (linkedReadId === null) return undefined;
    let active = true;
    setLinkedRun((current) => (current?.id === linkedReadId ? current : { id: linkedReadId, run: null, error: null }));
    getAssessmentRun(engagementKey, linkedReadId)
      .then((run) => { if (active) setLinkedRun({ id: linkedReadId, run, error: null }); })
      .catch((failure: unknown) => {
        if (active) setLinkedRun({ id: linkedReadId, run: null, error: failure instanceof Error ? failure.message : "Run not found" });
      });
    return () => {
      active = false;
    };
  }, [engagementKey, linkedReadId]);

  const selectedRun = listedRun ?? (linkedRun?.id === selectedRunId ? linkedRun?.run ?? undefined : undefined);
  const section = chosenSection ?? defaultSectionForRun(selectedRun?.run_purpose);
  // An explicit section wins; a ledger link (`section=`) opens the section it
  // belongs to; otherwise the record opens on its overview. Blockers exist only
  // while the run has some.
  const requestedTab: RunRecordTab = chosenTab ?? (chosenSection ? runRecordTabForSection(chosenSection) : "overview");
  const recordTab: RunRecordTab = requestedTab === "blockers" && selectedRun && currentBlockers(selectedRun).length === 0 ? "overview" : requestedTab;
  const focusedObject = initialObject
    && selectedRunId === initialRunId
    && chosenSection !== null
    && chosenSection === validSection(initialSection)
    ? initialObject
    : undefined;

  // From the list: remember the row for the return trip. Stepping between
  // records keeps the open section, like the Findings record.
  const openRun = useCallback((id: number, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setSelectedRunId(id);
    setChosenSection(null);
    setChosenTab(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "runs", run: id }));
  }, [engagementKey]);

  const stepToRun = useCallback((id: number) => {
    setSelectedRunId(id);
    setChosenSection(null);
    setChosenTab(recordTab);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "runs", run: id, dtab: recordTab === "overview" ? undefined : recordTab }));
  }, [engagementKey, recordTab]);

  const closeRun = useCallback(() => {
    setSelectedRunId(null);
    setChosenSection(null);
    setChosenTab(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "runs" }));
  }, [engagementKey]);

  const chooseTab = useCallback((next: RunRecordTab) => {
    setChosenTab(next);
    if (selectedRunId === null) return;
    // Keep a chosen ledger only on the section it belongs to.
    const keep = chosenSection !== null && runRecordTabForSection(chosenSection) === next ? chosenSection : undefined;
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "runs", run: selectedRunId, dtab: next === "overview" ? undefined : next, section: keep }));
  }, [chosenSection, engagementKey, selectedRunId]);

  const chooseSection = useCallback((next: RunAuditSection) => {
    setChosenSection(next);
    if (selectedRunId !== null) {
      writeWorkspaceHash(engagementHref(engagementKey, { tab: "runs", run: selectedRunId, dtab: recordTab === "overview" ? undefined : recordTab, section: next }), "replace");
    }
  }, [engagementKey, recordTab, selectedRunId]);

  const rows = useMemo(() => (runs ?? []).map((run) => deriveRunRow(run)), [runs]);
  const filtered = useMemo(() => filterRuns(rows, filters, Date.now(), scope), [rows, filters, scope]);
  const facets = useMemo(() => runFacetCounts(rows, filters, scope), [rows, filters, scope]);
  const healthCounts = useMemo(() => {
    const counts: Record<RunHealthKey, number> = { healthy: 0, attention: 0, failed: 0, running: 0 };
    for (const row of rows) counts[row.health.key] += 1;
    return counts;
  }, [rows]);
  useEffect(() => {
    if (runs !== null) onHealthCounts?.(healthCounts);
  }, [runs, healthCounts, onHealthCounts]);
  const attentionTotal = [...RUN_ATTENTION_HEALTH].reduce((total, key) => total + healthCounts[key], 0);
  const activeFilters = activeRunFilterCount(filters);
  const setFilter = <K extends keyof RunFilters>(key: K, value: RunFilters[K]) =>
    setFilters((current) => ({ ...current, [key]: value }));
  const clearFilters = () => setFilters(EMPTY_RUN_FILTERS);

  // A status chip outside the scope widens it; narrowing the scope drops
  // status chips it excludes. The list never silently shows nothing.
  const toggleHealth = (key: RunHealthKey) => {
    const next = toggled(filters.health, key);
    if (scope === "attention" && next.has(key) && !RUN_ATTENTION_HEALTH.has(key)) setScope("all");
    setFilter("health", next);
  };
  const chooseScope = (next: RunScope) => {
    setScope(next);
    if (next === "attention") {
      setFilters((current) => ({ ...current, health: new Set([...current.health].filter((key) => RUN_ATTENTION_HEALTH.has(key))) }));
    }
  };

  const sort: RunSort = gridView?.sort[0] ?? saved.sort;
  const sortColumn = RUN_SORT_COLUMNS[sort.colId];
  useEffect(() => {
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), serializeRunsView({ filters, scope, sort }));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, filters, scope, sort]);

  const firstLoad = runs === null && !error;
  const investigating = selectedRunId !== null && selectedRun !== undefined;
  // Previous / Next walk the list as shown: current filters, grid sort. Until
  // the grid reports its order (a deep link opens the record before the hidden
  // grid has laid out its rows), walk the grid's default sort.
  const reviewOrder = useMemo(() => {
    const visible = new Set(filtered.map((row) => row.id));
    const shown = gridView?.ids.filter((id) => visible.has(id));
    if (shown && shown.length === visible.size) return shown;
    return [...filtered].sort(compareRunRowsNewestFirst).map((row) => row.id);
  }, [filtered, gridView]);
  const reviewNavigation = listNavigation(reviewOrder, selectedRunId, stepToRun);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const revealRow = useCallback((key: string) => {
    const api = gridApiRef.current;
    const node = api?.getRowNode(key);
    if (api && node) api.ensureNodeVisible(node, "middle");
  }, []);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: investigating ? selectedRunId : null, reveal: revealRow });
  const gridHostRef = useRef<HTMLDivElement | null>(null);
  const { height: gridHeight } = useViewportPane(gridHostRef, MIN_GRID_HEIGHT, [runs !== null, filtered.length === 0, error, badRunLink]);

  const linkedRunMissing = selectedRunId !== null && !selectedRun && linkedRun?.id === selectedRunId && linkedRun.error;
  const filteredEmpty = runs !== null && runs.length > 0 && filtered.length === 0;

  return (
    <div className="findings-redesign runs-page">
      <PageHeader
        title="Runs"
        purpose="Each run is one evidence-gathering session by an agent; open one to see what it tested and what it proved."
        stats={runs === null ? [] : [
          { value: runs.length, label: "runs" },
          { value: attentionTotal, label: "need attention", tone: attentionTotal > 0 ? "warning" : undefined, title: RUN_ATTENTION_RULE },
          { value: healthCounts.running, label: "running" },
        ]}
        status={loading && runs !== null ? "Updating…" : null}
        hidden={investigating}
      >
        {runs !== null && runs.length > 0 && (
          <ScopeToggle
            scope={scope}
            onChange={chooseScope}
            attentionCount={facets.scope.attention}
            allCount={facets.scope.all}
            attentionRule={RUN_ATTENTION_RULE}
          />
        )}
      </PageHeader>

      {(runs === null || runs.length > 0) && <div className="panel findings-toolbar-panel runs-toolbar" hidden={investigating}>
        <div className="toolbar">
          <div className="search-wrap">
            <Search className="search-icon" aria-hidden="true" />
            <input
              ref={searchRef}
              className="search-input"
              type="search"
              aria-label="Search runs"
              placeholder="Search run, task, agent, finding, model…"
              value={filters.query}
              onChange={(event) => setFilter("query", event.target.value)}
            />
            {filters.query && (
              <button type="button" className="icon-btn" onClick={() => setFilter("query", "")} aria-label="Clear run search">
                <X size={14} />
              </button>
            )}
          </div>
          <div className="toolbar-right">
            <label className="runs-select">
              <span>Finding</span>
              <select value={filters.finding} onChange={(event) => setFilter("finding", event.target.value)} aria-label="Filter by finding">
                <option value="">Any finding</option>
                {facets.findings.map(([slug, count]) => <option key={slug} value={slug}>{slug} ({count})</option>)}
              </select>
            </label>
            <label className="runs-select">
              <span>Client</span>
              <select value={filters.client} onChange={(event) => setFilter("client", event.target.value)} aria-label="Filter by client">
                <option value="">Any client</option>
                {facets.clients.map(([client, count]) => <option key={client} value={client}>{client} ({count})</option>)}
              </select>
            </label>
          </div>
        </div>
        <div className="filter-row runs-filter-row">
          <FilterGroup label="Status">
            {HEALTH_ORDER.map((key) => (
              <FilterChip
                key={key}
                label={statusLabel("run-health", key)}
                status={{ domain: "run-health", value: key }}
                count={facets.health[key]}
                selected={filters.health.has(key)}
                onToggle={() => toggleHealth(key)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Track">
            {facets.tracks.map(([track, count]) => (
              <FilterChip
                key={track}
                label={statusText(track)}
                count={count}
                selected={filters.tracks.has(track)}
                onToggle={() => setFilter("tracks", toggled(filters.tracks, track))}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Evidence">
            <FilterChip
              label="Live target evidence"
              description="Runs that recorded an HTTP exchange, browser action, or out-of-band callback against the target."
              count={facets.live}
              selected={filters.liveOnly}
              onToggle={() => setFilter("liveOnly", !filters.liveOnly)}
            />
            <FilterChip
              label="Has blockers"
              count={facets.blockers}
              selected={filters.blockersOnly}
              onToggle={() => setFilter("blockersOnly", !filters.blockersOnly)}
            />
          </FilterGroup>
          <FilterGroup label="Started">
            {RUN_TIME_RANGES.map((range) => (
              <FilterChip
                key={range.key}
                label={range.label}
                count={facets.ranges[range.key]}
                selected={filters.range === range.key}
                onToggle={() => setFilter("range", range.key)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Role">
            {facets.roles.map(([role, count]) => (
              <FilterChip
                key={role}
                label={statusText(role)}
                count={count}
                selected={filters.roles.has(role)}
                onToggle={() => setFilter("roles", toggled(filters.roles, role))}
              />
            ))}
          </FilterGroup>
          <ClearFiltersButton count={activeFilters} onClear={clearFilters} />
        </div>
      </div>}

      {badRunLink !== null && !investigating && (
        <p className="runs-banner error-text" role="alert">
          Run link “{badRunLink}” does not name a run; run links use the run number, such as run=42.{" "}
          <button type="button" className="runs-link-button" onClick={closeRun}>Dismiss</button>
        </p>
      )}

      {error && runs !== null && (
        <p className="runs-banner error-text" role="alert">
          Could not refresh runs: {error} · Showing the last loaded list.
        </p>
      )}

      {selectedRunId !== null && !selectedRun && !linkedRunMissing && runs !== null && (
        <div className="runs-banner" role="status" aria-busy="true" aria-label={`Loading run #${selectedRunId}`}>
          <CardSkeleton lines={3} />
          <SlowLoadHint active what={`run #${selectedRunId}`} />
        </div>
      )}

      {linkedRunMissing && (
        <p className="runs-banner error-text" role="alert">
          Run #{selectedRunId} could not be opened: {linkedRun?.error}{" "}
          <button type="button" className="runs-link-button" onClick={closeRun}>Show all runs</button>
        </p>
      )}

      <div ref={resultsRef} className="findings-shell runs-shell" hidden={investigating}>
        <section className="list-panel panel" aria-label="Assessment runs" aria-busy={loading}>
          {runs !== null && runs.length > 0 && (
            <div className="runs-results-head">
              <ResultsSummary
                shown={filtered.length}
                total={runs.length}
                noun="runs"
                sort={sortColumn ? describeSort(sortColumn.label, sort.sort, sortColumn.kind) : undefined}
              />
            </div>
          )}
          {firstLoad && (
            <div className="runs-loading">
              <TableSkeleton rows={8} columns={["9%", "14%", "20%", "10%", "25%", "10%", "6%"]} />
              <SlowLoadHint active={firstLoad} what="runs" detail="Large engagements can take a few seconds." />
            </div>
          )}
          {runs === null && error && (
            <div className="runs-empty-state" role="alert">
              <p className="error-text">{error}</p>
              <button type="button" className="qa-btn" onClick={() => void loadRuns("refresh")}>Try again</button>
            </div>
          )}
          {runs !== null && runs.length === 0 && (
            <EmptyState variant="empty" title="No assessment runs have been recorded.">
              Agents record a run whenever they gather evidence for a finding or scan a target.
            </EmptyState>
          )}
          {filteredEmpty && (
            <EmptyState
              variant="filtered"
              title={activeFilters > 0 ? "No runs match these filters." : "No run needs attention."}
              onClearFilters={activeFilters > 0 ? clearFilters : () => chooseScope("all")}
              clearLabel={activeFilters > 0 ? "Clear filters" : "Show all runs"}
              action={activeFilters > 0 && scope === "attention" ? (
                <button type="button" className="ui-button" onClick={() => chooseScope("all")}>Show all runs</button>
              ) : undefined}
            >
              {scope === "attention" && facets.scope.all > 0
                ? `${facets.scope.all} ${facets.scope.all === 1 ? "run matches" : "runs match"} outside the Needs attention scope.`
                : undefined}
            </EmptyState>
          )}
          {runs !== null && runs.length > 0 && !filteredEmpty && (
            <div ref={gridHostRef} className="runs-grid-frame" style={gridHeight ? { height: gridHeight } : undefined}>
              <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
                <RunsGrid
                  engagementKey={engagementKey}
                  rows={filtered}
                  selectedId={selectedRunId}
                  onRowOpen={openRun}
                  onViewChange={reportGridView}
                  initialSort={sort}
                  onApi={setGridApi}
                />
              </Suspense>
            </div>
          )}
        </section>
      </div>

      {investigating && (
        <RecordView
          label="Run record"
          noun="run"
          navigation={reviewNavigation}
          onBack={closeRun}
          titleId="run-record-title"
          returnFocusRef={invokerRef}
        >
          <RunDetail
            key={selectedRun.id}
            engagementKey={engagementKey}
            run={selectedRun}
            runs={runs ?? []}
            tab={recordTab}
            section={section}
            focusedObject={focusedObject}
            refreshVersion={refreshVersion}
            titleId="run-record-title"
            onTabChange={chooseTab}
            onSectionChange={chooseSection}
          />
        </RecordView>
      )}
    </div>
  );
}
