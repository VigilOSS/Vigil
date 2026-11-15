// Activity: the engagement's audit log and structured events as one
// newest-first list (backend /activity). Filters run on the server and live
// in the URL (`q`, `cats`, `actor`, `range`); loaded pages survive live
// refreshes, which only fetch what is newer. Refreshes coalesce (one catch-up
// in flight, one more after it); a refresh that arrives while a first page
// loads runs once that page lands. Leaving the tab (following an entity chip)
// and coming back restores the loaded depth, the open cards and bursts and the
// scroll position for the same filters.
//
// A row opens its entry in the shared record view, which replaces the list;
// Back, Escape and browser Back return to it. The open entry and its section
// live in the URL (`entry=`, `dtab=metadata`). An entry the list has not
// loaded (a link to an old one) is read by id instead of paging the history
// to it. While a record is open, new rows wait behind the "new entries" pill
// so its position among the loaded results holds still.

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import {
  getActivityEntry,
  listActivityFeed,
  type ActivityActorKind,
  type ActivityCategory,
  type ActivityFeedPage,
  type ActivityItem,
} from "../lib/activityApi";
import { ApiError } from "../lib/api";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { RecordView, useResultsScrollMemory, type RecordNavigation } from "./record/RecordView";
import { useWindowedNavigation } from "./record/recordNavigation";
import { Skeleton, SlowLoadHint } from "./Skeletons";
import { ClearFiltersButton, EmptyState, FilterChip, FilterGroup, PageHeader, ResultsSummary, describeSort } from "./ui";
import { EntryView, type EntryUi } from "./activity/ActivityEntries";
import { EntryRecord, isEntrySection, type EntrySection } from "./activity/ActivityRecord";
import { appendOlder, buildFeed, mergeNewer, shownRows } from "./activity/activityModel";
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
  /** `entry=` in the URL: the activity entry (`ActivityItem.id`) whose record is open. */
  initialEntryId?: string;
  /** `dtab=` in the URL: the open entry's section (`metadata`; Details is the default). */
  initialDrawerTab?: string;
};

const RECORD_TITLE_ID = "activity-record-title";

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
/** The longest search the feed accepts (backend `/activity` `q`). */
const SEARCH_MAX_CHARS = 1024;

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

/** An entry read by id because the list does not hold it, or why that read failed. */
type EntryRead = { engagementKey: string; id: string; item: ActivityItem | null; error: string | null };

export function ActivityTab({
  engagementKey,
  refreshVersion = 0,
  initialQuery,
  initialCategories,
  initialActor,
  initialRange,
  initialEntryId,
  initialDrawerTab,
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
  // The last read of an older page failed; the next one retries.
  const [olderError, setOlderError] = useState<string | null>(null);
  // The dispatch cards and bursts showing their member rows.
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  // The entry whose record is open; null while the list shows.
  const [openId, setOpenId] = useState<string | null>(initialEntryId ?? null);
  const [section, setSection] = useState<EntrySection>(isEntrySection(initialDrawerTab) ? initialDrawerTab : "details");
  const [entryRead, setEntryRead] = useState<EntryRead | null>(null);
  // An entry the address named that this engagement's feed does not have.
  const [entryMiss, setEntryMiss] = useState<string | null>(null);
  // Results that replace the list under an open record start in a new scroll box.
  const [scrollEpoch, setScrollEpoch] = useState(0);
  const [fresh, setFresh] = useState<ReadonlySet<string>>(new Set());
  const [now, setNow] = useState(() => Date.now());
  const [categoryNotice, setCategoryNotice] = useState<string | null>(null);
  // Why the selection differs from the one a link named; shown while those filters stand.
  const [linkNotice, setLinkNotice] = useState<{ filters: string; text: string } | null>(null);

  const resultsRef = useRef<HTMLElement | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const openRef = useRef<string | null>(openId);
  openRef.current = openId;
  const sectionRef = useRef(section);
  sectionRef.current = section;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  // The `entry=` and `dtab=` values the open record last followed (or wrote).
  const appliedRoute = useRef({ entry: initialEntryId, section: initialDrawerTab });
  // The row a record was opened from: focus returns there when it closes.
  const invokerRef = useRef<HTMLElement | null>(null);
  const loadingOlderRef = useRef(false);
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
  // The scroll position a restored view returns to once its entries are on screen.
  const restoreScrollRef = useRef<number | null>(null);

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

  const hrefFor = useCallback((shown: Filters, entry: string | null, entrySection: EntrySection) => engagementHref(engagementKey, {
    tab: "activity",
    q: shown.q || undefined,
    cats: shown.categories?.join(","),
    actor: shown.actor || undefined,
    range: shown.range || undefined,
    entry: entry ?? undefined,
    dtab: entry && entrySection !== "details" ? entrySection : undefined,
  }), [engagementKey]);

  // Opening, stepping, closing and changing section each add a history entry.
  const writeEntry = useCallback((entry: string | null, shown: EntrySection = "details", mode: "push" | "replace" = "push") => {
    appliedRoute.current = { entry: entry ?? undefined, section: entry && shown !== "details" ? shown : undefined };
    writeWorkspaceHash(hrefFor(filtersRef.current, entry, shown), mode);
  }, [hrefFor]);

  // Rows held behind the pill join the list, highlighted.
  const takePending = useCallback(() => {
    const arrivals = pendingRef.current;
    if (!arrivals.length) return;
    commitRows(mergeNewer(rowsRef.current, arrivals));
    setFresh(new Set(arrivals.map((row) => row.id)));
    commitPending([]);
  }, [commitRows, commitPending]);

  // Returning to a list that was at its top: it takes the rows that arrived
  // while the record was open, as it would have had it been on screen.
  const settleArrivals = useCallback(() => {
    if (atTopRef.current) takePending();
  }, [takePending]);

  // Closing hands focus to the row the record was opened from, and the
  // record view then lands on the row of the entry last shown. An entry with
  // neither (a link to one the list has not loaded) hands it to the list.
  const keepReturnFocus = useCallback(() => {
    if (!invokerRef.current?.isConnected) invokerRef.current = scrollRef.current;
  }, []);

  // The URL changing under the tab (Back / Forward, a link) opens its entry
  // and section; no `entry=` shows the list.
  useEffect(() => {
    const applied = appliedRoute.current;
    if (applied.entry === initialEntryId && applied.section === initialDrawerTab) return;
    const stepping = openRef.current !== null && initialEntryId !== undefined;
    appliedRoute.current = { entry: initialEntryId, section: initialDrawerTab };
    setEntryMiss(null);
    if (!stepping) invokerRef.current = null;
    if (openRef.current !== null && initialEntryId === undefined) {
      settleArrivals();
      keepReturnFocus();
    }
    openRef.current = initialEntryId ?? null;
    setOpenId(initialEntryId ?? null);
    setSection(isEntrySection(initialDrawerTab) ? initialDrawerTab : "details");
  }, [initialEntryId, initialDrawerTab, settleArrivals, keepReturnFocus]);

  // Filter changes replace the address in place, keeping the open entry.
  const writtenKey = useRef(currentKey);
  useEffect(() => {
    if (currentKey === writtenKey.current) return;
    writtenKey.current = currentKey;
    writeWorkspaceHash(hrefFor(filters, openRef.current, sectionRef.current), "replace");
  }, [currentKey, hrefFor, filters]);

  const query = useCallback((extra: { before?: string; after?: string; limit?: number } = {}) => listActivityFeed(engagementKey, {
    categories: filters.categories ?? undefined,
    actor: filters.actor,
    q: filters.q || undefined,
    since: filters.since,
    limit: PAGE_SIZE,
    ...extra,
  }), [engagementKey, filters]);

  // Whether any read has delivered the category list the chips show.
  const categoriesKnownRef = useRef(false);
  const applyMeta = useCallback((page: ActivityFeedPage) => {
    setTotal(page.total);
    setCategories(page.categories);
    categoriesKnownRef.current = true;
  }, []);

  // A refused first page (a link naming a category the feed does not have, a
  // search it does not accept) delivers no category list. This reads the list
  // without any filter so the chips still show, and drops selected categories
  // the feed does not have. True when the selection changed (a new first page follows).
  const recoverCategories = useCallback(async (generation: number): Promise<boolean> => {
    // Nothing to recover: the chips show and the default selection is in use.
    if (categoriesKnownRef.current && filters.categories === null) return false;
    let known: ActivityCategory[];
    try {
      known = (await listActivityFeed(engagementKey, { limit: 1 })).categories;
    } catch {
      return false;
    }
    if (generation !== generationRef.current) return true;
    if (!categoriesKnownRef.current) {
      setCategories(known);
      categoriesKnownRef.current = true;
    }
    const chosen = filters.categories;
    if (chosen === null) return false;
    const keys = new Set(known.map((category) => category.key));
    const kept = chosen.filter((key) => keys.has(key));
    if (kept.length === chosen.length) return false;
    const unknown = chosen.filter((key) => !keys.has(key));
    const next: Filters = { ...filters, categories: kept.length ? kept : null };
    setLinkNotice({
      filters: filtersKey(next),
      text: `The link named ${unknown.length === 1 ? "a category" : "categories"} this feed does not have (${unknown.join(", ")}); showing ${kept.length ? "the rest of its selection" : "the default categories"}.`,
    });
    setFilters(next);
    return true;
  }, [engagementKey, filters]);

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
    loadingOlderRef.current = false;
    setLoadingOlder(false);
    setOlderError(null);
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
        // New results read from their first entry; a restored view returns
        // to its saved position when these rows are on screen.
        if (openRef.current !== null) setScrollEpoch((epoch) => epoch + 1);
        else if (scrollRef.current) scrollRef.current.scrollTop = 0;
        scrollTopRef.current = 0;
        atTopRef.current = true;
        restoreScrollRef.current = null;
        if (saved) {
          restoreRef.current = null;
          setExpanded(new Set(saved.expanded));
          if (saved.scrollTop > 0) restoreScrollRef.current = saved.scrollTop;
        }
      } catch (cause) {
        if (generation !== generationRef.current) return;
        if (await recoverCategories(generation)) return;
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
  }, [query, applyMeta, commitRows, commitPending, recoverCategories, filters]);

  const investigating = openId !== null;

  // The scroll box cannot reach a saved position before its entries render,
  // or while an open record hides it, so the position is applied with the
  // commit that puts them on screen.
  useLayoutEffect(() => {
    const top = restoreScrollRef.current;
    if (top === null || investigating || !scrollRef.current || rows.length === 0) return;
    restoreScrollRef.current = null;
    scrollRef.current.scrollTop = top;
    scrollTopRef.current = top;
    atTopRef.current = top <= AT_TOP_PX;
  }, [rows, investigating]);

  // Remember the loaded depth, open cards and bursts, and scroll for the return trip.
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

  // Set while a restart of the list waits for the open record to close.
  const restartHeldRef = useRef(false);
  useEffect(() => {
    if (!investigating && restartHeldRef.current) refreshRef.current();
  }, [investigating]);

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
    if (restartHeldRef.current && openRef.current !== null) return;
    restartHeldRef.current = false;
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
      // Too far behind to stitch: start again from the newest page. That
      // replaces the rows an open record is placed among, so it waits for
      // the record to close.
      if (openRef.current !== null) {
        restartHeldRef.current = true;
        return;
      }
      const page = await query();
      if (generation !== generationRef.current) return;
      commitRows(page.items);
      commitPending([]);
      setHasOlder(page.has_more);
      applyMeta(page);
      return;
    }
    if (!newer.length) return;
    // An open record holds arrivals, as a reader scrolled down does.
    if (atTopRef.current && openRef.current === null) {
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
      // The search belongs to the list, which an open record replaces.
      if (openRef.current !== null) return;
      if (target?.closest("input, textarea, select, [contenteditable]:not([contenteditable='false'])")) return;
      event.preventDefault();
      searchRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // A notice about the category chips belongs to the selection it explains.
  useEffect(() => setCategoryNotice(null), [currentKey]);

  // The page after the loaded rows: from the list's button, or when a record
  // steps past the loaded edge.
  const loadOlder = useCallback(async () => {
    const tail = rowsRef.current[rowsRef.current.length - 1];
    if (!tail || loadingOlderRef.current) return;
    const generation = generationRef.current;
    loadingOlderRef.current = true;
    setLoadingOlder(true);
    setOlderError(null);
    try {
      const page = await query({ before: tail.cursor });
      if (generation !== generationRef.current) return;
      commitRows(appendOlder(rowsRef.current, page.items));
      setHasOlder(page.has_more);
      applyMeta(page);
    } catch (cause) {
      if (generation === generationRef.current) setOlderError(errorText(cause, "Older activity could not be loaded"));
    } finally {
      if (generation === generationRef.current) {
        loadingOlderRef.current = false;
        setLoadingOlder(false);
      }
    }
  }, [query, applyMeta, commitRows]);

  function showPending() {
    takePending();
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

  // A dispatch card or burst is open when its id (or, for a burst, any
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

  // Opening from the list remembers the row; stepping from an open record
  // keeps the row the first one was opened from. Each entry opens on Details.
  const openEntry = useCallback((id: string, invoker?: HTMLElement | null) => {
    if (openRef.current === null) invokerRef.current = invoker ?? null;
    setEntryMiss(null);
    openRef.current = id;
    setOpenId(id);
    setSection("details");
    writeEntry(id);
  }, [writeEntry]);

  const closeEntry = useCallback(() => {
    settleArrivals();
    keepReturnFocus();
    openRef.current = null;
    setOpenId(null);
    writeEntry(null);
  }, [settleArrivals, keepReturnFocus, writeEntry]);

  const chooseSection = useCallback((next: EntrySection) => {
    setSection(next);
    if (openRef.current) writeEntry(openRef.current, next);
  }, [writeEntry]);

  const days = useMemo(() => buildFeed(rows, now), [rows, now]);
  const categoryLabels = useMemo(() => new Map(categories.map((category) => [category.key, category.label])), [categories]);
  const ui: EntryUi = { engagementKey, categoryLabels, expanded, toggle, open: openEntry, fresh };

  // The open entry: a row the list holds (shown, or waiting behind the pill),
  // else the one read by id.
  const held = useMemo(() => new Map([...pendingNew, ...rows].map((row) => [row.id, row])), [pendingNew, rows]);
  const read = entryRead && entryRead.engagementKey === engagementKey && entryRead.id === openId ? entryRead : null;
  const openItem = openId === null ? null : held.get(openId) ?? read?.item ?? null;
  const unread = openId !== null && !openItem && !read;
  useEffect(() => {
    if (!unread || openId === null) return undefined;
    let superseded = false;
    getActivityEntry(engagementKey, openId).then(
      (item) => {
        if (!superseded) setEntryRead({ engagementKey, id: openId, item, error: null });
      },
      (cause) => {
        if (superseded) return;
        if (cause instanceof ApiError && (cause.status === 404 || cause.status === 422)) {
          // Not an entry of this engagement's feed: the list shows and says so.
          setEntryMiss(openId);
          invokerRef.current = null;
          openRef.current = null;
          setOpenId(null);
          writeEntry(null, "details", "replace");
        } else {
          setEntryRead({ engagementKey, id: openId, item: null, error: errorText(cause, "The entry could not be read") });
        }
      },
    );
    return () => {
      superseded = true;
    };
  }, [unread, engagementKey, openId, writeEntry]);

  // Previous / Next walk the loaded rows as the list shows them, members of
  // cards and bursts included. Stepping past the last one loads older entries.
  const shown = useMemo(() => shownRows(days), [days]);
  const listPending = loading && rows.length === 0;
  const ledger = useMemo(() => ({
    rows: listPending ? null : rows,
    complete: !hasOlder,
    extending: loadingOlder,
    extendError: olderError,
    loadOlder,
  }), [listPending, rows, hasOlder, loadingOlder, olderError, loadOlder]);
  const stepNavigation = useWindowedNavigation({
    order: shown.order,
    current: openId,
    // An entry outside the loaded rows is read by id, never paged to.
    loaded: true,
    window: ledger,
    growsAt: "end",
    open: openEntry,
  });
  const navigation: RecordNavigation = !openItem
    ? { index: undefined, total: undefined, error: read?.error ?? undefined }
    : error && rows.length === 0
      ? { index: undefined, total: undefined, error }
      : stepNavigation;
  const outsideLoaded = openItem && navigation.index === null ? rows.length : null;

  // Returning lands on the entry last shown; a row inside a collapsed card or
  // burst is revealed by opening the groups that hold it.
  const groupsRef = useRef(shown.groups);
  groupsRef.current = shown.groups;
  const revealRow = useCallback((id: string) => {
    const groups = groupsRef.current.get(id);
    if (!groups) return;
    setExpanded((current) => (groups.every((group) => current.has(group)) ? current : new Set([...current, ...groups])));
  }, []);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: openId, reveal: revealRow });

  const filterCount = (filters.categories !== null ? 1 : 0) + (filters.actor ? 1 : 0) + (filters.q ? 1 : 0) + (filters.range ? 1 : 0);
  const filtered = filterCount > 0;
  const firstLoad = loading && rows.length === 0 && !error;
  const soleCategory = selected.length === 1 ? selected[0] : null;

  return (
    <div className={`findings-redesign activity-page${investigating ? " is-record" : ""}`}>
      <PageHeader
        title="Activity"
        titleId="activity-title"
        purpose="Everything that happened in this engagement — decisions, findings, agent work, notes and files — newest first."
        stats={[{ value: total, label: filtered ? "matching entries" : "entries" }]}
        status={loading && rows.length > 0 ? "Updating…" : null}
        hidden={investigating}
      />

      {/* The list (an open record replaces it; it stays mounted behind) */}
      <section ref={resultsRef} className="panel activity-view" aria-labelledby="activity-title" hidden={investigating}>
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
          {linkNotice?.filters === currentKey && <p className="activity-notice" role="status">{linkNotice.text}</p>}
          {entryMiss && (
            <p className="activity-notice" role="status">
              <strong>{entryMiss} is not one of this engagement&apos;s activity entries.</strong> The list is shown.
            </p>
          )}
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
                maxLength={SEARCH_MAX_CHARS}
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
          key={scrollEpoch}
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
              {olderError && <p className="activity-error" role="alert">Older entries could not be loaded: {olderError}</p>}
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
      {!investigating && rows.length > 0 && <div className="findings-shortcuts">
        <span><code>/</code> search</span>
        <span><code>Enter</code> open</span>
        <span><code>[ / ]</code> previous / next in a record</span>
        <span><code>Esc</code> back to results</span>
      </div>}

      {openId !== null && (
        <RecordView
          label="Activity entry"
          noun="entry"
          navigation={navigation}
          onBack={closeEntry}
          titleId={RECORD_TITLE_ID}
          returnFocusRef={invokerRef}
        >
          <EntryRecord
            key={openId}
            entryId={openId}
            item={openItem}
            loadError={read?.error ?? null}
            onRetry={() => setEntryRead(null)}
            outsideLoaded={outsideLoaded}
            engagementKey={engagementKey}
            categoryLabels={categoryLabels}
            section={section}
            onSectionChange={chooseSection}
            titleId={RECORD_TITLE_ID}
          />
        </RecordView>
      )}
    </div>
  );
}
