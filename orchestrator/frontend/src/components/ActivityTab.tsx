// Activity: the engagement's audit log and structured events as one
// newest-first record (backend /activity). Filters run on the server and live
// in the URL (`q`, `cats`, `actor`, `range`); loaded pages survive live
// refreshes, which only fetch what is newer. Refreshes coalesce (one catch-up
// in flight, one more after it); a refresh that arrives while a first page
// loads runs once that page lands. Leaving the tab (following an entity chip)
// and coming back restores the loaded depth, the open entries and the scroll
// position for the same filters.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  listActivityFeed,
  type ActivityActorKind,
  type ActivityCategory,
  type ActivityFeedPage,
  type ActivityItem,
} from "../lib/activityApi";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { Skeleton, SlowLoadHint } from "./Skeletons";
import { ClearFiltersButton, EmptyState, FilterChip, FilterGroup, PageHeader, ResultsSummary, describeSort } from "./ui";
import { EntryView, type EntryUi } from "./activity/ActivityEntries";
import { appendOlder, buildFeed, mergeNewer } from "./activity/activityModel";
import "../styles/activity.css";

type ActivityTabProps = {
  engagementKey: string;
  /** Bumped by the workspace on each live refresh. */
  refreshVersion?: number;
  /** `q=` in the URL: the search text. */
  initialQuery?: string;
  /** `cats=` in the URL (comma-separated): the selected categories; absent means the defaults. */
  initialCategories?: string[];
  /** `actor=` in the URL: operator, agent or system. */
  initialActor?: string;
  /** `range=` in the URL: the time-range key. */
  initialRange?: string;
};

const PAGE_SIZE = 100;
/** The feed's page limit (backend `/activity`), used to restore a deep scroll in few reads. */
const MAX_PAGE_SIZE = 500;
/** A restore stops after this many rows; older ones stay one "Load older" away. */
const MAX_RESTORE_ROWS = 2_000;
/** Pages of newer rows a refresh walks before it reloads from the top instead. */
const MAX_CATCH_UP_PAGES = 5;
/** Scrolled further than this, new rows wait behind the "new" pill. */
const AT_TOP_PX = 24;
const FRESH_HIGHLIGHT_MS = 6_000;
const SEARCH_DEBOUNCE_MS = 300;

const ACTORS: Array<[ActivityActorKind | "", string]> = [
  ["", "Everyone"], ["operator", "Operator"], ["agent", "Agents"], ["system", "System"],
];
const RANGES: Array<[string, string, number]> = [
  ["", "All time", 0], ["1h", "Last hour", 3_600_000], ["24h", "Last 24 hours", 86_400_000],
  ["7d", "Last 7 days", 7 * 86_400_000], ["30d", "Last 30 days", 30 * 86_400_000],
];
const LAST_CATEGORY_NOTICE = "At least one category stays selected. Choose another category first, or use Default categories.";

type Filters = {
  /** null: the server's default selection (everything except tool calls). */
  categories: string[] | null;
  actor: ActivityActorKind | "";
  q: string;
  range: string;
  /** Absolute lower bound fixed when the range was chosen. */
  since?: string;
};

const DEFAULT_FILTERS: Filters = { categories: null, actor: "", q: "", range: "" };

function sinceFor(range: string): string | undefined {
  const span = RANGES.find(([value]) => value === range)?.[2] ?? 0;
  return span ? new Date(Date.now() - span).toISOString() : undefined;
}

/** The filters a URL names; unknown actor or range values fall back to everything. */
function filtersFromRoute(query?: string, categories?: string[], actor?: string, range?: string): Filters {
  const knownActor = ACTORS.some(([value]) => value && value === actor) ? (actor as ActivityActorKind) : "";
  const knownRange = RANGES.some(([value]) => value && value === range) ? (range as string) : "";
  return {
    categories: categories?.length ? categories : null,
    actor: knownActor,
    q: (query ?? "").trim(),
    range: knownRange,
    since: sinceFor(knownRange),
  };
}

/** Identity of what the URL holds (the range's absolute bound is not part of it). */
function filtersKey(filters: Filters): string {
  return JSON.stringify([filters.categories, filters.actor, filters.q, filters.range]);
}

// ── Return-trip memory ──────────────────────────────────────────────────

type SavedView = { filters: string; rows: number; expanded: string[]; scrollTop: number };

const viewStorageKey = (engagementKey: string) => `activity.view.${engagementKey}`;

function readSavedView(engagementKey: string): SavedView | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(viewStorageKey(engagementKey)) || "null");
    if (!value || typeof value.filters !== "string") return null;
    return {
      filters: value.filters,
      rows: Number.isSafeInteger(value.rows) ? value.rows : 0,
      expanded: Array.isArray(value.expanded) ? value.expanded.filter((id: unknown): id is string => typeof id === "string") : [],
      scrollTop: typeof value.scrollTop === "number" ? value.scrollTop : 0,
    };
  } catch {
    return null;
  }
}

function writeSavedView(engagementKey: string, view: SavedView) {
  try {
    window.sessionStorage.setItem(viewStorageKey(engagementKey), JSON.stringify(view));
  } catch {
    // Storage full or blocked: the return trip starts from the newest page.
  }
}

function errorText(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback;
}

export function ActivityTab({
  engagementKey,
  refreshVersion = 0,
  initialQuery,
  initialCategories,
  initialActor,
  initialRange,
}: ActivityTabProps) {
  const [filters, setFilters] = useState<Filters>(() => filtersFromRoute(initialQuery, initialCategories, initialActor, initialRange));
  const [queryInput, setQueryInput] = useState(() => (initialQuery ?? "").trim());
  const [rows, setRows] = useState<ActivityItem[]>([]);
  const [pendingNew, setPendingNew] = useState<ActivityItem[]>([]);
  const [hasOlder, setHasOlder] = useState(false);
  const [total, setTotal] = useState<number | null>(null);
  const [categories, setCategories] = useState<ActivityCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [fresh, setFresh] = useState<ReadonlySet<string>>(new Set());
  const [now, setNow] = useState(() => Date.now());
  const [categoryNotice, setCategoryNotice] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const atTopRef = useRef(true);
  // Every filter or engagement change starts a new generation; responses from
  // an older generation are dropped.
  const generationRef = useRef(0);
  const rowsRef = useRef<ActivityItem[]>([]);
  const pendingRef = useRef<ActivityItem[]>([]);
  // A first-page load replaces the rows; a refresh that arrives meanwhile
  // waits for it and catches up from the page it lands.
  const pageLoadingRef = useRef(false);
  const refreshAfterPageRef = useRef(false);
  const refreshRef = useRef<() => void>(() => {});
  const lastRefreshVersionRef = useRef(refreshVersion);
  // The saved view for these filters is restored once, by the first load after mount.
  const restoreRef = useRef<SavedView | null>(readSavedView(engagementKey));
  const scrollTopRef = useRef(0);

  // Refresh passes read the latest rows synchronously, before React renders.
  const commitRows = useCallback((next: ActivityItem[]) => {
    rowsRef.current = next;
    setRows(next);
  }, []);
  const commitPending = useCallback((next: ActivityItem[]) => {
    pendingRef.current = next;
    setPendingNew(next);
  }, []);

  // ── URL ⇄ filters ──
  // The URL changing under the tab (browser Back / Forward, a link) replaces
  // the filters; the tab's own writes come back equal and change nothing.
  const routeFilters = useMemo(
    () => filtersFromRoute(initialQuery, initialCategories, initialActor, initialRange),
    // Keyed by the categories' value, not the array's identity.
    [initialQuery, initialCategories?.join(","), initialActor, initialRange],
  );
  const routeKey = filtersKey(routeFilters);
  const currentKey = filtersKey(filters);
  const appliedRouteKey = useRef(routeKey);
  useEffect(() => {
    if (routeKey === appliedRouteKey.current) return;
    appliedRouteKey.current = routeKey;
    if (routeKey === currentKey) return;
    setFilters(routeFilters);
    setQueryInput(routeFilters.q);
  }, [routeKey, currentKey, routeFilters]);

  const writtenKey = useRef(currentKey);
  useEffect(() => {
    if (currentKey === writtenKey.current) return;
    writtenKey.current = currentKey;
    writeWorkspaceHash(engagementHref(engagementKey, {
      tab: "activity",
      q: filters.q || undefined,
      cats: filters.categories?.join(","),
      actor: filters.actor || undefined,
      range: filters.range || undefined,
    }), "replace");
  }, [currentKey, engagementKey, filters]);

  const query = useCallback((extra: { before?: string; after?: string; limit?: number } = {}) => listActivityFeed(engagementKey, {
    categories: filters.categories ?? undefined,
    actor: filters.actor,
    q: filters.q || undefined,
    since: filters.since,
    limit: PAGE_SIZE,
    ...extra,
  }), [engagementKey, filters]);

  const applyMeta = useCallback((page: ActivityFeedPage) => {
    setTotal(page.total);
    setCategories(page.categories);
  }, []);

  // First page for the current engagement and filters. Previous rows stay
  // visible (dimmed) until the replacement arrives. Returning to the same
  // filters reads as deep as the operator had loaded.
  useEffect(() => {
    const generation = ++generationRef.current;
    // Kept until a load for its filters lands (StrictMode repeats this effect).
    const saved = restoreRef.current?.filters === filtersKey(filters) ? restoreRef.current : null;
    const target = Math.min(saved?.rows ?? 0, MAX_RESTORE_ROWS);
    pageLoadingRef.current = true;
    setLoading(true);
    // An older-page read from the previous generation is discarded on arrival.
    setLoadingOlder(false);
    setError(null);
    void (async () => {
      try {
        let page = await query({ limit: Math.min(MAX_PAGE_SIZE, Math.max(PAGE_SIZE, target)) });
        if (generation !== generationRef.current) return;
        let loaded = page.items;
        while (page.has_more && loaded.length < target && loaded.length) {
          page = await query({ before: loaded[loaded.length - 1].cursor, limit: MAX_PAGE_SIZE });
          if (generation !== generationRef.current) return;
          loaded = appendOlder(loaded, page.items);
        }
        commitRows(loaded);
        commitPending([]);
        setHasOlder(page.has_more);
        setFresh(new Set());
        setNow(Date.now());
        applyMeta(page);
        if (saved) {
          restoreRef.current = null;
          setExpanded(new Set(saved.expanded));
          const top = saved.scrollTop;
          if (top > 0) {
            window.setTimeout(() => {
              if (generation !== generationRef.current || !scrollRef.current) return;
              scrollRef.current.scrollTop = top;
              scrollTopRef.current = top;
              atTopRef.current = top <= AT_TOP_PX;
            }, 0);
          }
        }
      } catch (cause) {
        if (generation === generationRef.current) setError(errorText(cause, "Activity could not be loaded"));
      } finally {
        if (generation === generationRef.current) {
          pageLoadingRef.current = false;
          setLoading(false);
          if (refreshAfterPageRef.current) {
            refreshAfterPageRef.current = false;
            refreshRef.current();
          }
        }
      }
    })();
  }, [query, applyMeta, commitRows, commitPending, filters]);

  // Remember the loaded depth, open entries and scroll for the return trip.
  const saveView = useCallback(() => {
    // Mid-load the rows are the previous filters' (or none): keep the last save.
    if (pageLoadingRef.current) return;
    writeSavedView(engagementKey, {
      filters: filtersKey(filters),
      rows: rowsRef.current.length,
      expanded: [...expanded],
      scrollTop: scrollTopRef.current,
    });
  }, [engagementKey, filters, expanded]);
  useEffect(() => {
    saveView();
  }, [saveView, rows, loading]);
  const saveViewRef = useRef(saveView);
  saveViewRef.current = saveView;
  useEffect(() => () => saveViewRef.current(), []);

  // Live refresh: fetch only rows newer than the newest one held, walking
  // forward page by page so nothing between pages is skipped.
  const catchUp = useCallback(async () => {
    if (pageLoadingRef.current) {
      refreshAfterPageRef.current = true;
      return;
    }
    const generation = generationRef.current;
    const head = pendingRef.current[0] ?? rowsRef.current[0];
    if (!head) {
      const page = await query();
      if (generation !== generationRef.current) return;
      commitRows(page.items);
      setHasOlder(page.has_more);
      applyMeta(page);
      return;
    }
    let cursor = head.cursor;
    let newer: ActivityItem[] = [];
    let last: ActivityFeedPage | null = null;
    for (let pageIndex = 0; pageIndex < MAX_CATCH_UP_PAGES; pageIndex += 1) {
      last = await query({ after: cursor });
      if (generation !== generationRef.current) return;
      newer = [...last.items, ...newer];
      if (!last.has_more || !last.items.length) break;
      cursor = last.items[0].cursor;
    }
    if (!last) return;
    applyMeta(last);
    setNow(Date.now());
    if (last.has_more) {
      // Too far behind to stitch: start again from the newest page.
      const page = await query();
      if (generation !== generationRef.current) return;
      commitRows(page.items);
      commitPending([]);
      setHasOlder(page.has_more);
      applyMeta(page);
      return;
    }
    if (!newer.length) return;
    if (atTopRef.current) {
      commitRows(mergeNewer(rowsRef.current, [...newer, ...pendingRef.current]));
      commitPending([]);
      setFresh((current) => new Set([...current, ...newer.map((row) => row.id)]));
    } else {
      commitPending(mergeNewer(pendingRef.current, newer));
    }
  }, [query, applyMeta, commitRows, commitPending]);

  const runRefresh = useCoalescedRunner(async () => {
    const generation = generationRef.current;
    try {
      await catchUp();
      if (generation === generationRef.current) setError(null);
    } catch (cause) {
      if (generation === generationRef.current) setError(errorText(cause, "Newer activity could not be loaded"));
    }
  });
  refreshRef.current = () => void runRefresh();

  useEffect(() => {
    if (refreshVersion === lastRefreshVersionRef.current) return;
    lastRefreshVersionRef.current = refreshVersion;
    void runRefresh();
  }, [refreshVersion, runRefresh]);

  // New-row highlight fades once; the set clears so later renders stay calm.
  useEffect(() => {
    if (!fresh.size) return;
    const timer = window.setTimeout(() => setFresh(new Set()), FRESH_HIGHLIGHT_MS);
    return () => window.clearTimeout(timer);
  }, [fresh]);

  // Search applies after a short pause in typing.
  useEffect(() => {
    const value = queryInput.trim();
    if (value === filters.q) return;
    const timer = window.setTimeout(() => setFilters((current) => ({ ...current, q: value })), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [queryInput, filters.q]);

  // `/` focuses the search from anywhere on the tab, like the other ledgers.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null;
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      if (target?.closest("input, textarea, select, [contenteditable]:not([contenteditable='false'])")) return;
      event.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // A notice about the category chips belongs to the selection it explains.
  useEffect(() => setCategoryNotice(null), [currentKey]);

  async function loadOlder() {
    const tail = rows[rows.length - 1];
    if (!tail || loadingOlder) return;
    const generation = generationRef.current;
    setLoadingOlder(true);
    try {
      const page = await query({ before: tail.cursor });
      if (generation !== generationRef.current) return;
      commitRows(appendOlder(rowsRef.current, page.items));
      setHasOlder(page.has_more);
      applyMeta(page);
      setError(null);
    } catch (cause) {
      if (generation === generationRef.current) setError(errorText(cause, "Older activity could not be loaded"));
    } finally {
      if (generation === generationRef.current) setLoadingOlder(false);
    }
  }

  function showPending() {
    const arrivals = pendingRef.current;
    commitRows(mergeNewer(rowsRef.current, arrivals));
    setFresh(new Set(arrivals.map((row) => row.id)));
    commitPending([]);
    scrollRef.current?.scrollTo?.({ top: 0 });
    atTopRef.current = true;
  }

  function onScroll() {
    const top = scrollRef.current?.scrollTop ?? 0;
    scrollTopRef.current = top;
    atTopRef.current = top <= AT_TOP_PX;
    if (atTopRef.current && pendingRef.current.length) showPending();
  }

  const defaults = useMemo(() => categories.filter((category) => category.default).map((category) => category.key), [categories]);
  const selected = filters.categories ?? defaults;

  function toggleCategory(key: string) {
    const next = selected.includes(key) ? selected.filter((value) => value !== key) : [...selected, key];
    // An empty selection would mean "defaults" to the server; keep one chip on.
    if (!next.length) {
      setCategoryNotice(LAST_CATEGORY_NOTICE);
      return;
    }
    const ordered = categories.map((category) => category.key).filter((value) => next.includes(value));
    const isDefault = ordered.length === defaults.length && ordered.every((value) => defaults.includes(value));
    setFilters((current) => ({ ...current, categories: isDefault ? null : ordered }));
  }

  function setRange(range: string) {
    setFilters((current) => ({ ...current, range, since: sinceFor(range) }));
  }

  function clearFilters() {
    setQueryInput("");
    setFilters(DEFAULT_FILTERS);
  }

  function clearSearch() {
    setQueryInput("");
    setFilters((current) => (current.q ? { ...current, q: "" } : current));
    searchRef.current?.focus();
  }

  // A row, dispatch card or burst is open when its id (or, for a burst, any
  // member's id) is recorded open; closing clears every alias.
  const toggle = useCallback((id: string, aliases: readonly string[] = []) => {
    setExpanded((current) => {
      const next = new Set(current);
      const keys = [id, ...aliases];
      if (keys.some((key) => next.has(key))) for (const key of keys) next.delete(key);
      else next.add(id);
      return next;
    });
  }, []);

  const days = useMemo(() => buildFeed(rows, now), [rows, now]);
  const categoryLabels = useMemo(() => new Map(categories.map((category) => [category.key, category.label])), [categories]);
  const ui: EntryUi = { engagementKey, categoryLabels, expanded, toggle, fresh };
  const filterCount = (filters.categories !== null ? 1 : 0) + (filters.actor ? 1 : 0) + (filters.q ? 1 : 0) + (filters.range ? 1 : 0);
  const filtered = filterCount > 0;
  const firstLoad = loading && rows.length === 0 && !error;
  const soleCategory = selected.length === 1 ? selected[0] : null;

  return (
    <div className="findings-redesign activity-page">
      <PageHeader
        title="Activity"
        titleId="activity-title"
        purpose="Everything that happened in this engagement — decisions, findings, agent work, notes and files — newest first."
        stats={[{ value: total, label: filtered ? "matching entries" : "entries" }]}
        status={loading && rows.length > 0 ? "Updating…" : null}
      />

      <section className="panel activity-view" aria-labelledby="activity-title">
        <div className="activity-filters">
          <FilterGroup label="Categories" className="activity-categories">
            {categories.length === 0 && Array.from({ length: 6 }, (_, index) => <Skeleton key={index} width={118} height={24} rounded />)}
            {categories.map((category) => {
              const on = selected.includes(category.key);
              return (
                <FilterChip
                  key={category.key}
                  label={category.label}
                  count={category.count}
                  selected={on}
                  onToggle={() => toggleCategory(category.key)}
                  description={category.key === soleCategory ? "The only selected category; select another before turning this one off." : undefined}
                />
              );
            })}
            {filters.categories !== null && (
              <button type="button" className="activity-reset" onClick={() => setFilters((current) => ({ ...current, categories: null }))}>
                Default categories
              </button>
            )}
          </FilterGroup>
          {categoryNotice && <p className="activity-notice" role="status">{categoryNotice}</p>}
          <div className="activity-controls">
            <div className="search-wrap activity-search">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="search-icon" aria-hidden="true">
                <circle cx={11} cy={11} r={7} />
                <path d="M21 21l-4.3-4.3" />
              </svg>
              <input
                ref={searchRef}
                type="search"
                className="search-input"
                aria-label="Search activity"
                placeholder="Search what the log shows: summaries, actors, linked records, commands, results…"
                value={queryInput}
                onChange={(event) => setQueryInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    const value = queryInput.trim();
                    setFilters((current) => (current.q === value ? current : { ...current, q: value }));
                  }
                  if (event.key === "Escape") event.currentTarget.blur();
                }}
              />
              {queryInput && (
                <button type="button" className="icon-btn" onClick={clearSearch} aria-label="Clear activity search" title="Clear" style={{ width: 22, height: 22 }}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
                    <path d="M6 6l12 12M18 6L6 18" />
                  </svg>
                </button>
              )}
              <span className="search-kbd" aria-hidden="true">/</span>
            </div>
            <FilterGroup label="Actor">
              {ACTORS.map(([value, label]) => (
                <FilterChip
                  key={value || "all"}
                  label={label}
                  selected={filters.actor === value}
                  onToggle={() => setFilters((current) => (current.actor === value ? current : { ...current, actor: value }))}
                />
              ))}
            </FilterGroup>
            <FilterGroup label="Time">
              {RANGES.map(([value, label]) => (
                <FilterChip
                  key={value || "all"}
                  label={label}
                  selected={filters.range === value}
                  onToggle={() => {
                    if (filters.range !== value) setRange(value);
                  }}
                />
              ))}
            </FilterGroup>
            <ClearFiltersButton count={filterCount} onClear={clearFilters} />
          </div>
          {total != null && (
            <ResultsSummary
              className="activity-results"
              shown={rows.length}
              total={total}
              noun={filtered ? "matching entries loaded" : "entries loaded"}
              sort={describeSort("Time", "desc", "time")}
            />
          )}
        </div>

        <div
          className={`activity-scroll${loading && rows.length ? " is-reloading" : ""}`}
          ref={scrollRef}
          onScroll={onScroll}
          role="region"
          aria-label="Activity entries"
          aria-busy={loading}
          tabIndex={0}
        >
          {pendingNew.length > 0 && (
            <button type="button" className="activity-new-pill" onClick={showPending}>
              {pendingNew.length === 1 ? "1 new entry" : `${pendingNew.length} new entries`} — show
            </button>
          )}
          {error && <p className="activity-error" role="alert">{error}</p>}
          {firstLoad && (
            <div className="activity-skeleton" role="status" aria-label="Loading activity">
              {Array.from({ length: 10 }, (_, index) => (
                <div key={index} className="activity-skeleton-row">
                  <Skeleton width={58} /><Skeleton width={120} /><Skeleton width={`${40 + ((index * 17) % 45)}%`} />
                </div>
              ))}
            </div>
          )}
          <div className="activity-slow">
            <SlowLoadHint active={loading} what="activity" detail="This engagement has a long history." />
          </div>
          {!loading && !error && rows.length === 0 && (filtered ? (
            <EmptyState variant="filtered" title="No activity matches these filters." onClearFilters={clearFilters}>
              Try another category, actor or time range, or change the search.
            </EmptyState>
          ) : (
            <EmptyState variant="empty" title="No activity recorded yet.">
              Agent dispatches, decisions, findings and notes appear here as the engagement runs.
            </EmptyState>
          ))}
          {days.map((day) => (
            <section key={day.day} className="activity-day" aria-labelledby={`activity-day-${day.day.replace(/[^0-9A-Za-z-]/g, "-")}`}>
              <h3 className="activity-day-head" id={`activity-day-${day.day.replace(/[^0-9A-Za-z-]/g, "-")}`}>
                <span>{day.label}</span>
                <span className="activity-day-meta">{day.label === day.day || day.label.endsWith(day.day) ? "" : `${day.day} · `}{day.count.toLocaleString()} loaded · UTC</span>
              </h3>
              <ul className="activity-list">
                {day.entries.map((entry) => <EntryView key={entry.id} entry={entry} ui={ui} />)}
              </ul>
            </section>
          ))}
          {rows.length > 0 && (
            <footer className="activity-foot">
              {hasOlder ? (
                <button type="button" className="ui-button activity-older" onClick={() => void loadOlder()} disabled={loadingOlder}>
                  {loadingOlder ? "Loading older entries…" : "Load older entries"}
                </button>
              ) : (
                <p className="meta-text">{filtered ? "That is everything matching these filters." : "That is the start of this engagement's activity."}</p>
              )}
            </footer>
          )}
        </div>
      </section>
    </div>
  );
}
