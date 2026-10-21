// ── OastTab ───────────────────────────────────────────────────────────
// The engagement's OAST (out-of-band) probes. One grid row per probe
// (assessment_oob_probes); the list endpoint embeds a derived
// interaction_count + last_interaction_at. Opening a probe replaces the list
// with the shared record view (Probe / Callbacks); it fetches
// getOobProbe(nonce) for the full interactions[] history and the operator
// verdict — the LIST endpoint only carries counts. Back, Escape and browser
// Back return to the list.
//
// Default scope is "Needs attention": probes that received a callback and
// have no operator verdict yet, newest callback first; when none needs
// attention the tab opens on "All", the full inventory with status chips.
// Scope, status chips, search and grid sort survive leaving the tab
// (sessionStorage, per engagement). Filtering is client-side: the probe list
// is small and already in memory. The record records the operator verdict
// (Confirm / Ignore, `recordOobVerdict`), which moves a probe out of Needs
// attention. The grid is lazy-loaded so ag-grid lands in the shared
// code-split chunk.
//
// Callback receipts and payload hosts are operator evidence and render
// verbatim (ADR 0019); receipt text is target-influenced and only ever shown
// as text (ADR 0018).

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { OobInteraction, OobProbe, OobProbeDetail, OobVerdict } from "../lib/api";
import { ApiError, getOobProbe, listOobProbes } from "../lib/api";
import {
  callbackHistogram,
  callbackTime,
  canRecordVerdict,
  countCallbacksToReview,
  groupCallbacks,
  isCallbackToReview,
  isPrivateAddress,
  linkedToParts,
  oobStatus,
  recordOobVerdict,
  sortByLastHit,
} from "../lib/oastApi";
import { compareServerTime, formatAbsoluteTime, formatAge } from "../lib/serverTime";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { useToast } from "../contexts/ToastContext";
import { CodeBlock, TimeStamp } from "./formatting";
import { KV, KVTime, ProseSection } from "./drawer/DrawerKit";
import { Skeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  StatusPill,
  describeSort,
  statusEntry,
  statusLabel,
  statusOrder,
  statusTone,
  type Scope,
  type SortKind,
} from "./ui";
import {
  RecordBody,
  RecordCopyLinkButton,
  RecordHeader,
  RecordTabs,
  RecordView,
  useResultsScrollMemory,
} from "./record/RecordView";
import { listNavigation, useGridView, type GridSort } from "./record/recordNavigation";
import "../styles/oast.css";

const OastGrid = lazy(() => import("./OastGrid"));

const ATTENTION_RULE = "Probes that received a callback and have no operator verdict yet.";

// ── Protocol colors ───────────────────────────────────────────────────
// dns/http/https/ftp/ldap/smtp. Drives the colored .oob-proto-badge.
const PROTOCOL_CLASSES: Record<string, string> = {
  dns: "p-dns",
  http: "p-http",
  https: "p-https",
  ftp: "p-ftp",
  ldap: "p-ldap",
  smtp: "p-smtp",
};

function protocolClass(proto: string): string {
  return PROTOCOL_CLASSES[(proto || "").toLowerCase()] || "p-other";
}

// A raw_request that looks base64-encoded gets decoded for display; anything
// else (or a decode failure) renders verbatim.
function decodedInterpretation(raw: string): string | null {
  const text = (raw || "").trim();
  if (!text) return null;
  // Heuristic: base64 alphabet only, length a multiple of 4, reasonably long.
  if (text.length >= 8 && text.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    try {
      const decoded = atob(text);
      // Only swap in the decoded form if it's mostly printable — otherwise
      // the original was probably not base64 (or was binary).
      const printable = decoded.replace(/[^\x20-\x7e\r\n\t]/g, "");
      if (printable.length >= decoded.length * 0.85 && decoded !== raw) return decoded;
    } catch {
      // fall through to raw
    }
  }
  return null;
}

// ── Icons (match the other tabs) ──────────────────────────────────────
const IconSearch = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    className="search-icon"
    aria-hidden="true"
  >
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
const IconClose = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);

type OastTabProps = {
  engagementKey: string;
  // Bumped by EngagementPage after every successful page refresh (including
  // WebSocket-driven ones). A change triggers a silent background reload so
  // this tab stays live alongside the others without flickering to a spinner.
  refreshVersion?: number;
  initialProbeId?: number;
  initialDrawerTab?: string;
  /** Reports the probes awaiting a verdict after each read or verdict, for the rail badge while open. */
  onToReviewCount?: (count: number) => void;
};

type OastRecordTab = "probe" | "callbacks";

function isOastRecordTab(value: string | undefined): value is OastRecordTab {
  return value === "probe" || value === "callbacks";
}

// Grid columns as the results line names their order.
const SORT_COLUMNS: Record<string, { label: string; kind: SortKind }> = {
  status: { label: "Status", kind: "status" },
  lasthit: { label: "Last callback", kind: "time" },
  created: { label: "Planted", kind: "time" },
  hits: { label: "Callbacks", kind: "number" },
  linked: { label: "Linked to", kind: "text" },
  client: { label: "Client", kind: "text" },
  "payload-host": { label: "Payload host", kind: "text" },
};

function sortText(sort: GridSort | undefined): string | undefined {
  if (!sort) return undefined;
  const column = SORT_COLUMNS[sort.colId];
  return column ? describeSort(column.label, sort.sort, column.kind) : undefined;
}

// ── Saved view ────────────────────────────────────────────────────────
// Scope, status chips, search and the grid's sort, per engagement. A missing
// scope means "not chosen yet": the first list read picks it.
type SavedView = { scope: Scope | null; status: string[]; query: string; sort: GridSort[] | null };

const viewKey = (engagementKey: string) => `oast.view.${engagementKey}`;

function readSavedView(engagementKey: string): SavedView {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(viewKey(engagementKey)) || "{}") as Record<string, unknown>;
    const sort = Array.isArray(value.sort)
      ? value.sort.filter((entry): entry is GridSort => Boolean(entry) && typeof entry.colId === "string" && (entry.sort === "asc" || entry.sort === "desc"))
      : null;
    return {
      scope: value.scope === "attention" || value.scope === "all" ? value.scope : null,
      status: Array.isArray(value.status) ? value.status.filter((item): item is string => typeof item === "string") : [],
      query: typeof value.query === "string" ? value.query : "",
      sort,
    };
  } catch {
    return { scope: null, status: [], query: "", sort: null };
  }
}

function searchCorpus(probe: OobProbe): string {
  return [
    probe.target_url,
    probe.technique,
    probe.nonce,
    probe.oob_domain,
    probe.param,
    probe.probe_kind,
    probe.client_name,
    probe.client_payload_host,
    probe.notes,
    probe.request_hash,
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
}

function verdictFailure(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return "This probe is no longer in the engagement's probe ledger.";
  return error instanceof Error && error.message ? error.message : "The verdict could not be recorded.";
}

type VerdictDraft = { nonce: string; verdict: OobVerdict };

// Each engagement gets its own workspace state (and its own saved view).
export function OastTab(props: OastTabProps) {
  return <OastWorkspace key={props.engagementKey} {...props} />;
}

function OastWorkspace({ engagementKey, refreshVersion, initialProbeId, initialDrawerTab, onToReviewCount }: OastTabProps) {
  const { toast } = useToast();
  const [saved] = useState(() => readSavedView(engagementKey));
  const [probes, setProbes] = useState<OobProbe[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState(saved.query);
  const [scope, setScope] = useState<Scope>(saved.scope ?? "attention");
  // False until the operator (or a saved view) picks the scope; the first read picks it otherwise.
  const scopeChosen = useRef(saved.scope !== null);
  const [statusFilters, setStatusFilters] = useState<Set<string>>(() => new Set(saved.status));
  // Why a deep link changed the scope or filters, shown above the results.
  const [routeNotice, setRouteNotice] = useState<string | null>(null);
  // The open probe, by nonce (unique per engagement). The URL names it by
  // its id (`probe`) and names the open section (`dtab`).
  const [selectedNonce, setSelectedNonce] = useState<string | null>(null);
  const [recordTab, setRecordTab] = useState<OastRecordTab>(isOastRecordTab(initialDrawerTab) ? initialDrawerTab : "probe");
  const [gridView, reportGridView] = useGridView<string>();
  // Probes given a verdict while their record is open stay in the stepping
  // order until the record closes, so Previous / Next keep working.
  const [reviewedOpen, setReviewedOpen] = useState<ReadonlySet<string>>(new Set());

  // Detail cache keyed by nonce — full interactions[] and the verdict, read
  // when a probe's record opens.
  const [detailCache, setDetailCache] = useState<Map<string, OobProbeDetail>>(() => new Map());
  const [detailLoading, setDetailLoading] = useState<Set<string>>(() => new Set());
  const [detailErrors, setDetailErrors] = useState<Map<string, string>>(() => new Map());

  const [verdictDraft, setVerdictDraft] = useState<VerdictDraft | null>(null);
  const [verdictSaving, setVerdictSaving] = useState(false);
  const [verdictError, setVerdictError] = useState<string | null>(null);

  const searchRef = useRef<HTMLInputElement | null>(null);
  const invokerRef = useRef<HTMLElement | null>(null);
  const revealRef = useRef<((nonce: string) => void) | null>(null);

  // One probe-list read in flight at a time. A refresh that arrives meanwhile
  // collapses into a single re-run after it settles; the mount load (which
  // StrictMode repeats for the same key) joins the in-flight read instead.
  const keyRef = useRef(engagementKey);
  keyRef.current = engagementKey;
  const reload = useCoalescedRunner(async () => {
    setRefreshing(true);
    const key = keyRef.current;
    try {
      const items = await listOobProbes(key);
      if (keyRef.current === key) {
        setProbes(items);
        setLoadError(null);
      }
    } catch (err) {
      // Previous rows stay visible; the banner explains the stale state.
      if (keyRef.current === key) setLoadError(err instanceof Error ? err.message : "Failed to load OAST probes");
    } finally {
      if (keyRef.current === key) setLoaded(true);
    }
  }, () => setRefreshing(false));

  // The mount load (StrictMode repeats it) joins the read already in flight.
  // Later reads follow `refreshVersion`, which the page also bumps when the
  // browser tab regains focus.
  useEffect(() => {
    void reload("join");
  }, [reload]);

  const fetchDetail = useCallback(
    (nonce: string, failure: string) => {
      const key = keyRef.current;
      return getOobProbe(key, nonce)
        .then((detail) => {
          if (keyRef.current !== key) return;
          setDetailCache((m) => new Map(m).set(nonce, detail));
          setDetailErrors((errors) => {
            const next = new Map(errors);
            next.delete(nonce);
            return next;
          });
        })
        .catch((error: unknown) => {
          if (keyRef.current !== key) return;
          setDetailErrors((errors) => new Map(errors).set(nonce, error instanceof Error ? error.message : failure));
        });
    },
    [],
  );

  // Cache-first read when a probe's record first opens.
  const ensureDetail = useCallback(
    (nonce: string) => {
      if (detailCache.has(nonce) || detailLoading.has(nonce)) return;
      setDetailLoading((s) => new Set(s).add(nonce));
      void fetchDetail(nonce, "Failed to load callback history").finally(() => {
        setDetailLoading((s) => {
          const next = new Set(s);
          next.delete(nonce);
          return next;
        });
      });
    },
    [detailCache, detailLoading, fetchDetail],
  );

  const ensureDetailRef = useRef(ensureDetail);
  ensureDetailRef.current = ensureDetail;
  useEffect(() => {
    if (selectedNonce) ensureDetailRef.current(selectedNonce);
    else setReviewedOpen((current) => (current.size ? new Set() : current));
  }, [selectedNonce]);

  // Silent background reload whenever the parent's refresh version bumps
  // (poll tick / WebSocket event); the open record's history is re-read too
  // so newly correlated callbacks and verdicts appear without re-opening it.
  const lastVersionRef = useRef(refreshVersion);
  const selectedNonceRef = useRef<string | null>(null);
  selectedNonceRef.current = selectedNonce;
  useEffect(() => {
    if (lastVersionRef.current === refreshVersion) return;
    lastVersionRef.current = refreshVersion;
    void reload();
    const openNonce = selectedNonceRef.current;
    if (openNonce) void fetchDetail(openNonce, "Failed to refresh callback history");
  }, [refreshVersion, reload, fetchDetail]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of probes) {
      const k = oobStatus(p);
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [probes]);

  const reviewCount = useMemo(() => countCallbacksToReview(probes), [probes]);
  // The list has never been read (the first read failed): counts are unknown, not zero.
  const listUnavailable = Boolean(loadError) && probes.length === 0;
  const counted = loaded && !listUnavailable;
  useEffect(() => {
    if (counted) onToReviewCount?.(reviewCount);
  }, [counted, reviewCount, onToReviewCount]);
  // A work queue opens on Needs attention, or on All when nothing needs attention.
  useEffect(() => {
    if (!counted || scopeChosen.current) return;
    scopeChosen.current = true;
    if (reviewCount === 0 && probes.length > 0) setScope("all");
  }, [counted, reviewCount, probes.length]);

  const searchTerm = query.trim().toLowerCase();
  const matchesSearch = useCallback((p: OobProbe) => !searchTerm || searchCorpus(p).includes(searchTerm), [searchTerm]);
  const filtered = useMemo(() => {
    const rows = probes.filter((p) => {
      if (scope === "attention" && !isCallbackToReview(p) && !reviewedOpen.has(p.nonce)) return false;
      if (scope === "all" && statusFilters.size && !statusFilters.has(oobStatus(p))) return false;
      return matchesSearch(p);
    });
    return scope === "attention" ? sortByLastHit(rows) : rows;
  }, [probes, statusFilters, matchesSearch, scope, reviewedOpen]);
  // Probes the search finds in the whole ledger: an empty Needs attention
  // list can point at them.
  const searchMatchesAll = useMemo(() => probes.filter(matchesSearch).length, [probes, matchesSearch]);

  const selected = selectedNonce === null ? null : probes.find((probe) => probe.nonce === selectedNonce) ?? null;
  const investigating = selected !== null;

  // From the list: remember the row for the return trip and start on Probe.
  // Stepping between records keeps the open section.
  const openProbe = useCallback((probe: OobProbe, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setSelectedNonce(probe.nonce);
    setRecordTab("probe");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "oast", probe: probe.id }));
  }, [engagementKey]);
  const stepToProbe = useCallback((nonce: string) => {
    const probe = probes.find((item) => item.nonce === nonce);
    if (!probe) return;
    setSelectedNonce(nonce);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "oast", probe: probe.id, dtab: recordTab === "probe" ? undefined : recordTab }));
  }, [engagementKey, probes, recordTab]);
  const closeProbe = useCallback((mode: "push" | "replace" = "push") => {
    setSelectedNonce(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "oast" }), mode);
  }, [engagementKey]);
  const chooseRecordTab = useCallback((next: OastRecordTab) => {
    setRecordTab(next);
    if (selected) writeWorkspaceHash(engagementHref(engagementKey, { tab: "oast", probe: selected.id, dtab: next === "probe" ? undefined : next }));
  }, [engagementKey, selected]);

  // The URL owns which probe is open. A link to a probe the list hides (the
  // scope, a status filter or the search excludes it) widens the list so the
  // record has a place in the results, and says so above them. A link to a
  // probe the ledger does not hold shows no record at all.
  const listStateRef = useRef({ scope, statusFilters, searchTerm });
  listStateRef.current = { scope, statusFilters, searchTerm };
  const appliedRouteProbe = useRef<number | null>(null);
  useEffect(() => {
    if (initialProbeId === undefined) {
      if (appliedRouteProbe.current !== null) {
        appliedRouteProbe.current = null;
        setSelectedNonce(null);
      }
      return;
    }
    if (appliedRouteProbe.current === initialProbeId) return;
    const linked = probes.find((probe) => probe.id === initialProbeId);
    if (!linked) {
      if (loaded) {
        appliedRouteProbe.current = null;
        setSelectedNonce(null);
      }
      return;
    }
    appliedRouteProbe.current = initialProbeId;
    if (selectedNonceRef.current === null) invokerRef.current = searchRef.current;
    setSelectedNonce(linked.nonce);
    const { scope: shownScope, statusFilters: shownStatuses, searchTerm: shownSearch } = listStateRef.current;
    const status = oobStatus(linked);
    const changes: string[] = [];
    let widenedScope = false;
    if (shownScope === "attention" && !isCallbackToReview(linked)) {
      scopeChosen.current = true;
      setScope("all");
      widenedScope = true;
    }
    if ((widenedScope || shownScope === "all") && shownStatuses.size && !shownStatuses.has(status)) {
      setStatusFilters(new Set());
      changes.push("cleared the status filter");
    }
    if (shownSearch && !searchCorpus(linked).includes(shownSearch)) {
      setQuery("");
      changes.push("cleared the search");
    }
    if (widenedScope) {
      const reason = `Showing all probes: probe #${linked.id} is ${statusLabel("oast", status).toLowerCase()}, so it has no callback to review`;
      setRouteNotice(changes.length ? `${reason}; ${changes.join(" and ")}.` : `${reason}.`);
    } else if (changes.length) {
      setRouteNotice(`Opened probe #${linked.id}, which the list hid: ${changes.join(" and ")}.`);
    }
  }, [initialProbeId, probes, loaded]);
  useEffect(() => {
    setRecordTab(isOastRecordTab(initialDrawerTab) ? initialDrawerTab : "probe");
  }, [initialDrawerTab]);
  const routeMissing = initialProbeId !== undefined && loaded && !loadError && !probes.some((probe) => probe.id === initialProbeId);

  // A refreshed list that no longer holds the open probe returns to the list.
  useEffect(() => {
    if (selectedNonce !== null && loaded && !probes.some((probe) => probe.nonce === selectedNonce)) closeProbe("replace");
  }, [closeProbe, loaded, probes, selectedNonce]);

  const chooseScope = (next: Scope) => {
    scopeChosen.current = true;
    setScope(next);
    setRouteNotice(null);
  };

  const toggleStatus = (s: string) => {
    setStatusFilters((cur) => {
      const next = new Set(cur);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const clearAll = () => {
    setQuery("");
    setStatusFilters(new Set());
  };

  const activeFilterCount = (scope === "all" ? statusFilters.size : 0) + (query ? 1 : 0);

  // ── Verdicts ────
  const startVerdict = useCallback((nonce: string, verdict: OobVerdict) => {
    setVerdictError(null);
    setVerdictDraft({ nonce, verdict });
  }, []);
  const cancelVerdict = useCallback(() => {
    if (!verdictSaving) setVerdictDraft(null);
  }, [verdictSaving]);
  const submitVerdict = useCallback(async (note: string) => {
    if (!verdictDraft) return;
    const { nonce, verdict } = verdictDraft;
    const key = keyRef.current;
    setVerdictSaving(true);
    setVerdictError(null);
    try {
      const updated = await recordOobVerdict(key, nonce, { verdict, note });
      if (keyRef.current !== key) return;
      setDetailCache((cache) => new Map(cache).set(nonce, updated));
      setProbes((rows) => rows.map((row) => (row.nonce === nonce ? { ...row, status: updated.status, updated_at: updated.updated_at || row.updated_at } : row)));
      setReviewedOpen((current) => new Set(current).add(nonce));
      setVerdictDraft(null);
      toast(`Verdict recorded: ${statusLabel("oast", verdict)}`, "success");
      void reload();
    } catch (error) {
      if (keyRef.current === key) setVerdictError(verdictFailure(error));
    } finally {
      setVerdictSaving(false);
    }
  }, [verdictDraft, reload, toast]);

  // Previous / Next walk the list as shown: current scope and filters, grid
  // sort. Until the grid reports its order (a deep link opens the record
  // before the hidden grid has laid out its rows), walk the scope's default
  // order: newest callback first, or newest probe first.
  const reviewOrder = useMemo(() => {
    const visible = new Set(filtered.map((probe) => probe.nonce));
    const shown = gridView?.ids.filter((nonce) => visible.has(nonce));
    if (shown && shown.length === visible.size) return shown;
    const ordered = scope === "attention"
      ? filtered
      : [...filtered].sort((a, b) => compareServerTime(a.created_at, b.created_at, "desc"));
    return ordered.map((probe) => probe.nonce);
  }, [filtered, gridView, scope]);
  const reviewNavigation = listNavigation(reviewOrder, selectedNonce, stepToProbe);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(resultsRef, investigating, {
    recordKey: selectedNonce,
    reveal: (nonce) => revealRef.current?.(nonce),
  });

  // `/` focuses search (leaving an open record); Escape leaves the search
  // box. The open record handles its own Escape.
  const investigatingRef = useRef(investigating);
  investigatingRef.current = investigating;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea" || tag === "select";
      if (document.querySelector('[aria-modal="true"]')) return;
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        if (investigatingRef.current) closeProbe();
        queueMicrotask(() => {
          searchRef.current?.focus({ preventScroll: true });
          searchRef.current?.scrollIntoView?.({ block: "center" });
        });
        return;
      }
      if (e.key === "Escape" && isTyping && target === searchRef.current) searchRef.current?.blur();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeProbe]);

  // Chip order: urgency order first, then any other present status.
  const statusChips = useMemo(() => {
    const present = new Set(Object.keys(statusCounts));
    const ordered: string[] = [];
    for (const s of statusOrder("oast")) {
      if (present.has(s) || statusFilters.has(s)) ordered.push(s);
    }
    for (const s of present) if (!ordered.includes(s)) ordered.push(s);
    return ordered;
  }, [statusCounts, statusFilters]);

  const shownSort = sortText(gridView?.sort[0]) ?? (scope === "attention" ? "Last callback, newest first" : "Planted, newest first");
  // The order a rebuilt grid starts in (after an empty state, or on return to the tab).
  const gridSortState = gridView?.sort ?? saved.sort;
  useEffect(() => {
    if (!scopeChosen.current) return;
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify({
        scope,
        status: [...statusFilters],
        query,
        sort: gridSortState,
      } satisfies SavedView));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, scope, statusFilters, query, gridSortState]);
  let emptyState: ReactNode = null;
  if (loaded && !listUnavailable && filtered.length === 0) {
    const showAll = <button type="button" className="ui-button" onClick={() => chooseScope("all")}>Show all probes{searchTerm ? ` (${searchMatchesAll} match)` : ""}</button>;
    if (probes.length === 0) {
      emptyState = (
        <EmptyState variant="empty" title="No OAST probes planted yet.">
          Agents mint a probe before planting an out-of-band payload; its callbacks appear here once they are polled.
        </EmptyState>
      );
    } else if (activeFilterCount === 0) {
      emptyState = (
        <EmptyState variant="empty" title="No callbacks to review." action={showAll}>
          {probes.length} probe{probes.length === 1 ? "" : "s"} planted; none has a callback waiting for an operator verdict.
        </EmptyState>
      );
    } else {
      emptyState = (
        <EmptyState
          variant="filtered"
          title={scope === "attention" ? "No probes need attention that match these filters." : "No probes match these filters."}
          onClearFilters={clearAll}
          action={scope === "attention" && searchMatchesAll > 0 ? showAll : undefined}
        />
      );
    }
  }

  return (
    <div className="findings-redesign oast-view">
      <PageHeader
        title="OAST"
        purpose="Out-of-band probes Vigil planted and the callbacks they received. A callback means something reached out to the probe's host; review it and record a verdict."
        stats={[
          { value: counted ? probes.length : null, label: probes.length === 1 ? "probe" : "probes" },
          { value: counted ? reviewCount : null, label: "need attention", tone: reviewCount ? "warning" : undefined, title: ATTENTION_RULE },
        ]}
        status={refreshing && loaded ? "Updating…" : null}
        hidden={investigating}
      >
        <ScopeToggle
          scope={scope}
          onChange={chooseScope}
          attentionCount={counted ? reviewCount : null}
          allCount={counted ? probes.length : null}
          attentionRule={ATTENTION_RULE}
          label="OAST probe scope"
        />
      </PageHeader>
      <div ref={resultsRef} className="oast-results" hidden={investigating}>
      {routeMissing && (
        <p className="oast-route-missing error-text" role="alert">
          OAST probe #{initialProbeId} is not in this engagement's probe ledger.
        </p>
      )}
      {routeNotice && (
        <p className="oast-route-notice" role="status">
          <span>{routeNotice}</span>
          <button type="button" className="ui-button" onClick={() => setRouteNotice(null)}>Dismiss</button>
        </p>
      )}
      <div className="panel findings-toolbar-panel oast-toolbar">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search target, client, payload host, notes, nonce…"
              type="search"
              aria-label="Search OAST probes"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                aria-label="Clear OAST search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd" aria-hidden="true">/</span>
          </div>
        </div>
        <div className="filter-row">
          {scope === "all" && statusChips.length > 0 && (
            <FilterGroup label="Status">
              {statusChips.map((s) => (
                <FilterChip
                  key={s}
                  label={statusLabel("oast", s)}
                  status={{ domain: "oast", value: s }}
                  count={statusCounts[s] || 0}
                  selected={statusFilters.has(s)}
                  onToggle={() => toggleStatus(s)}
                />
              ))}
            </FilterGroup>
          )}
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
          <details className="oast-legend">
            <summary>What do the statuses mean?</summary>
            <dl>
              {statusOrder("oast").map((s) => (
                <div key={s}>
                  <dt><StatusPill domain="oast" value={s} size="sm" /></dt>
                  <dd>{statusEntry("oast", s).meaning}{s === "fired" ? " Until an operator records a verdict, the probe needs attention." : ""}</dd>
                </div>
              ))}
            </dl>
          </details>
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel oast-banner">
          <p className="error-text" role="alert">
            {probes.length ? `Probe list refresh failed: ${loadError} (showing the last loaded list)` : `OAST probes could not be loaded: ${loadError}`}
          </p>
          <button type="button" className="ui-button" onClick={() => void reload()} disabled={refreshing}>Try again</button>
        </div>
      )}

      <section className="panel oast-grid-panel" aria-label="OAST probes">
        {!loaded ? (
          <>
            <TableSkeleton rows={8} showHeader={false} />
            <SlowLoadHint active what="the probe ledger" />
          </>
        ) : listUnavailable ? null : emptyState ?? (
          <>
            <ResultsSummary shown={filtered.length} total={probes.length} noun={probes.length === 1 ? "probe" : "probes"} sort={shownSort} className="oast-results-summary" />
            <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
              <OastGrid
                rows={filtered}
                sortColumn={scope === "attention" ? "lasthit" : "created"}
                initialSort={gridSortState}
                selectedNonce={selectedNonce}
                onRowOpen={openProbe}
                onViewChange={reportGridView}
                onReady={(reveal) => { revealRef.current = reveal; }}
              />
            </Suspense>
          </>
        )}
      </section>

      <div className="findings-shortcuts">
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>Esc</code> close detail
        </span>
      </div>
      </div>

      {selected && (
        <RecordView
          label="OAST probe record"
          noun="probe"
          navigation={reviewNavigation}
          onBack={closeProbe}
          titleId="oast-record-title"
          returnFocusRef={invokerRef}
        >
          <OastRecord
            key={selected.nonce}
            probe={selected}
            detail={detailCache.get(selected.nonce) ?? null}
            detailLoading={detailLoading.has(selected.nonce)}
            detailError={detailErrors.get(selected.nonce) ?? null}
            tab={recordTab}
            onTabChange={chooseRecordTab}
            onVerdict={(verdict) => startVerdict(selected.nonce, verdict)}
            titleId="oast-record-title"
          />
        </RecordView>
      )}
      {verdictDraft && selected && verdictDraft.nonce === selected.nonce && (
        <VerdictDialog
          probe={selected}
          verdict={verdictDraft.verdict}
          callbackCount={detailCache.get(selected.nonce)?.interactions.length ?? selected.interaction_count ?? 0}
          saving={verdictSaving}
          error={verdictError}
          onConfirm={(note) => void submitVerdict(note)}
          onClose={cancelVerdict}
        />
      )}
    </div>
  );
}

// ── Linked-to summary ─────────────────────────────────────────────────
export function LinkedTo({ probe }: { probe: Pick<OobProbe, "target_url" | "param" | "technique"> }) {
  const parts = linkedToParts(probe);
  if (parts.length === 0) {
    return (
      <span className="oast-unattributed" title="No target URL, parameter, or technique was recorded when this probe was minted">
        Unattributed
      </span>
    );
  }
  return <span className="oast-linked">{parts.join(" · ")}</span>;
}

function lifecycleSentence(probe: OobProbe, callbackCount: number, verdict: OobProbeDetail["verdict"]): string {
  const status = oobStatus(probe);
  switch (status) {
    case "fired":
      return `The target side reached out ${callbackCount} time${callbackCount === 1 ? "" : "s"}. Review the callbacks and record a verdict.`;
    case "pending": {
      const age = formatAge(probe.created_at);
      return age ? `Planted ${age}; no callback yet.` : "No callback yet.";
    }
    case "expired":
      return "Expired before any callback was observed.";
    case "confirmed":
    case "ignored":
      return verdict
        ? `Operator verdict by ${verdict.actor || "an operator"}; ${callbackCount} callback${callbackCount === 1 ? "" : "s"}.`
        : `${callbackCount} callback${callbackCount === 1 ? "" : "s"}; reviewed by an operator.`;
    default:
      return statusLabel("oast", status);
  }
}

// ── Callback summary + table ──────────────────────────────────────────
const CALLBACK_PAGE_SIZE = 25;

function CallbackHistogram({ interactions }: { interactions: OobInteraction[] }) {
  const buckets = useMemo(() => callbackHistogram(interactions), [interactions]);
  if (buckets.length === 0 || interactions.length < 2) return null;
  const max = Math.max(...buckets.map((bucket) => bucket.count));
  const width = 240;
  const height = 36;
  const gap = 2;
  const barWidth = (width - gap * (buckets.length - 1)) / buckets.length;
  const first = new Date(buckets[0].start).toISOString();
  const last = new Date(buckets.at(-1)!.end).toISOString();
  return (
    <figure className="oast-histogram">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Callbacks over time, ${formatAbsoluteTime(first, "second")} to ${formatAbsoluteTime(last, "second")}; busiest interval ${max}`}
      >
        {buckets.map((bucket, index) => {
          const barHeight = bucket.count ? Math.max(2, (bucket.count / max) * height) : 0;
          return (
            <g key={index}>
              <title>
                {`${bucket.count} callback${bucket.count === 1 ? "" : "s"} · ${formatAbsoluteTime(new Date(bucket.start).toISOString(), "second")} – ${formatAbsoluteTime(new Date(bucket.end).toISOString(), "second")}`}
              </title>
              <rect x={index * (barWidth + gap)} y={0} width={barWidth} height={height} fill="transparent" />
              {barHeight > 0 && (
                <rect
                  className="oast-histogram-bar"
                  x={index * (barWidth + gap)}
                  y={height - barHeight}
                  width={barWidth}
                  height={barHeight}
                  rx={1.5}
                />
              )}
            </g>
          );
        })}
      </svg>
      <figcaption>
        <span>{formatAbsoluteTime(first, "second")}</span>
        <span>{formatAbsoluteTime(last, "second")}</span>
      </figcaption>
    </figure>
  );
}

function SourceSummary({ interactions }: { interactions: OobInteraction[] }) {
  const sources = [...new Set(interactions.map((item) => item.remote_address).filter(Boolean))];
  if (sources.length === 0) return <span>Source not recorded</span>;
  const privateSources = sources.filter(isPrivateAddress);
  if (privateSources.length === sources.length) {
    return (
      <span className="oast-source-masked">
        Every callback arrived from {sources.join(", ")} — a private address. The real origin is masked by relay NAT.
      </span>
    );
  }
  return (
    <span>
      {sources.length} source{sources.length === 1 ? "" : "s"}
      {privateSources.length ? ` (${privateSources.length} private, masked by relay NAT)` : ""}
    </span>
  );
}

function CallbackRow({ item, toast }: { item: OobInteraction; toast: (message: string, type?: "success" | "error" | "info") => void }) {
  const [open, setOpen] = useState(false);
  const decoded = open ? decodedInterpretation(item.raw_request) : null;
  return (
    <>
      <tr>
        <td><TimeStamp value={callbackTime(item)} mode="absolute" precision="second" /></td>
        <td>
          <span className={`oob-proto-badge ${protocolClass(item.protocol)}`}>{item.protocol?.toUpperCase() || "—"}</span>
        </td>
        <td className="mono">{item.query_type || "—"}</td>
        <td className="mono">
          {item.remote_address || "—"}
          {isPrivateAddress(item.remote_address) && (
            <span className="oast-private-tag" title="Private address: the real origin is masked by relay NAT">private</span>
          )}
        </td>
        <td>
          {item.raw_request ? (
            <button type="button" className="oast-receipt-toggle" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
              {open ? "Hide receipt" : "Show receipt"}
            </button>
          ) : (
            <span className="meta-text">None</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="oast-receipt-row">
          <td colSpan={5}>
            <CodeBlock label="Raw callback receipt" text={item.raw_request} onCopied={() => toast("Copied", "success")} />
            {decoded && (
              <CodeBlock label="Decoded interpretation" text={decoded} onCopied={() => toast("Copied", "success")} />
            )}
            <p className="oast-receipt-meta">
              Interaction hash <code>{item.interaction_hash}</code> · recorded{" "}
              <TimeStamp value={item.created_at} mode="absolute" precision="second" />
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

function CallbackLedger({
  interactions,
  toast,
}: {
  interactions: OobInteraction[];
  toast: (message: string, type?: "success" | "error" | "info") => void;
}) {
  const [group, setGroup] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const groups = useMemo(() => groupCallbacks(interactions), [interactions]);
  const ordered = useMemo(
    () => [...interactions].sort((a, b) => compareServerTime(callbackTime(a), callbackTime(b), "desc") || b.id - a.id),
    [interactions],
  );
  const times = ordered.map(callbackTime);
  const rows = group
    ? ordered.filter((item) => `${(item.protocol || "").toLowerCase()}|${(item.query_type || "").toUpperCase()}` === group)
    : ordered;
  const pageCount = Math.max(1, Math.ceil(rows.length / CALLBACK_PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = rows.slice(currentPage * CALLBACK_PAGE_SIZE, (currentPage + 1) * CALLBACK_PAGE_SIZE);

  const selectGroup = (key: string | null) => {
    setGroup(key);
    setPage(0);
  };

  return (
    <>
      <div className="oast-callback-summary" aria-label="Callback summary">
        <div className="oast-callback-facts">
          <strong>{interactions.length} callback{interactions.length === 1 ? "" : "s"}</strong>
          {times.at(-1) && <span>First {formatAbsoluteTime(times.at(-1), "second")}</span>}
          {times[0] && <span>Latest {formatAbsoluteTime(times[0], "second")}</span>}
          <SourceSummary interactions={interactions} />
        </div>
        <CallbackHistogram interactions={interactions} />
      </div>
      <FilterGroup label="Protocol" className="oast-groups">
        <FilterChip label="All" count={interactions.length} selected={group === null} onToggle={() => selectGroup(null)} />
        {groups.map((item) => (
          <FilterChip
            key={item.key}
            label={`${item.protocol.toUpperCase() || "Unknown"}${item.queryType ? ` ${item.queryType}` : ""}`}
            count={item.count}
            selected={group === item.key}
            onToggle={() => selectGroup(group === item.key ? null : item.key)}
          />
        ))}
      </FilterGroup>
      <div className="oast-callback-table-wrap">
        <table className="oast-callback-table">
          <caption className="sr-only">Callbacks, newest first. Times in UTC.</caption>
          <thead>
            <tr>
              <th scope="col">Time (UTC)</th>
              <th scope="col">Protocol</th>
              <th scope="col">Type</th>
              <th scope="col">Source</th>
              <th scope="col">Receipt</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((item) => <CallbackRow key={item.id} item={item} toast={toast} />)}
          </tbody>
        </table>
      </div>
      {pageCount > 1 && (
        <div className="oast-pager">
          <span className="meta-text">
            {currentPage * CALLBACK_PAGE_SIZE + 1}–{currentPage * CALLBACK_PAGE_SIZE + visible.length} of {rows.length}
          </span>
          <button type="button" className="ghost-button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
            Newer
          </button>
          <button type="button" className="ghost-button" disabled={currentPage >= pageCount - 1} onClick={() => setPage(currentPage + 1)}>
            Older
          </button>
        </div>
      )}
    </>
  );
}

// ── Operator verdict ──────────────────────────────────────────────────
// The verdict an operator gives a probe that called back: confirmed (the
// target made the callback) or ignored (noise). Pending and expired probes
// have nothing to review.

const VERDICT_ACTIONS: Record<OobVerdict, { label: string; switchLabel: string }> = {
  confirmed: { label: "Confirm callback…", switchLabel: "Confirm instead…" },
  ignored: { label: "Ignore callback…", switchLabel: "Ignore instead…" },
};

/** The verdict buttons a probe offers: both while it waits for review, the other one once reviewed. */
function verdictChoices(status: string): Array<{ verdict: OobVerdict; label: string }> {
  if (status === "confirmed") return [{ verdict: "ignored", label: VERDICT_ACTIONS.ignored.switchLabel }];
  if (status === "ignored") return [{ verdict: "confirmed", label: VERDICT_ACTIONS.confirmed.switchLabel }];
  return [
    { verdict: "confirmed", label: VERDICT_ACTIONS.confirmed.label },
    { verdict: "ignored", label: VERDICT_ACTIONS.ignored.label },
  ];
}

function VerdictButtons({ status, onVerdict }: { status: string; onVerdict: (verdict: OobVerdict) => void }) {
  return (
    <>
      {verdictChoices(status).map((choice) => (
        <button
          key={choice.verdict}
          type="button"
          className={`ui-button oast-verdict-button oast-verdict-${choice.verdict}`}
          onClick={() => onVerdict(choice.verdict)}
        >
          {choice.label}
        </button>
      ))}
    </>
  );
}

function VerdictSection({
  probe,
  verdict,
  detailLoaded,
  callbackCount,
}: {
  probe: OobProbe;
  verdict: OobProbeDetail["verdict"];
  detailLoaded: boolean;
  callbackCount: number;
}) {
  const status = oobStatus(probe);
  if (!canRecordVerdict(probe)) {
    return (
      <section className="section oast-verdict" aria-labelledby="oast-verdict-title">
        <h3 className="section-title" id="oast-verdict-title">Operator verdict</h3>
        <p className="meta-text">
          {status === "expired"
            ? "This probe expired before any callback, so there is nothing to review."
            : "A verdict can be recorded once a callback arrives."}
        </p>
      </section>
    );
  }
  return (
    <section className="section oast-verdict" aria-labelledby="oast-verdict-title">
      <h3 className="section-title" id="oast-verdict-title">Operator verdict</h3>
      {status === "fired" ? (
        <p className="oast-verdict-text">
          No verdict yet. This probe received {callbackCount} callback{callbackCount === 1 ? "" : "s"}: use Confirm callback
          when the target made them, or Ignore callback when they are noise (scanners, relays, your own traffic). Until
          then it needs attention.
        </p>
      ) : verdict ? (
        <div className="oast-verdict-recorded">
          <p className="oast-verdict-text">
            <StatusPill domain="oast" value={status} />
            <span>
              Recorded by <strong>{verdict.actor || "an operator"}</strong> <TimeStamp value={verdict.recorded_at} mode="both" />
            </span>
          </p>
          {verdict.note ? <p className="oast-verdict-note">{verdict.note}</p> : <p className="meta-text">No note recorded.</p>}
        </div>
      ) : (
        <p className="oast-verdict-text">
          <StatusPill domain="oast" value={status} />
          <span>{detailLoaded ? "No operator verdict entry was found in the audit log for this status." : "Loading the recorded verdict…"}</span>
        </p>
      )}
    </section>
  );
}

// Confirmation for recording a verdict: states exactly what is written and
// what changes before anything is sent.
function VerdictDialog({
  probe,
  verdict,
  callbackCount,
  saving,
  error,
  onConfirm,
  onClose,
}: {
  probe: OobProbe;
  verdict: OobVerdict;
  callbackCount: number;
  saving: boolean;
  error: string | null;
  onConfirm: (note: string) => void;
  onClose: () => void;
}) {
  const [note, setNote] = useState("");
  const panelRef = useRef<HTMLDivElement | null>(null);
  useModalFocus(panelRef, onClose);
  useBodyScrollLock();
  const status = oobStatus(probe);
  const target = linkedToParts(probe).join(" · ") || "an unattributed probe";
  const label = statusLabel("oast", verdict);
  const titleId = "oast-verdict-dialog-title";
  const summaryId = "oast-verdict-dialog-summary";
  return (
    <div
      className="oast-dialog-overlay"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div ref={panelRef} className="oast-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={summaryId} tabIndex={-1}>
        <h2 id={titleId}>{verdict === "confirmed" ? "Confirm" : "Ignore"} the callback on probe #{probe.id}?</h2>
        <p id={summaryId} className="oast-dialog-lede">
          This records the operator verdict <strong>{label}</strong> for probe #{probe.id}. The verdict and your note are
          written to the engagement's audit log, and the probe {status === "fired" ? "leaves Needs attention" : "stays out of Needs attention"}.
          {" "}You can change the verdict later.
        </p>
        <dl className="oast-dialog-facts">
          <div><dt>Probe</dt><dd className="mono">{target}</dd></div>
          <div><dt>Callbacks</dt><dd>{callbackCount}</dd></div>
          <div>
            <dt>Status</dt>
            <dd className="oast-dialog-change">
              <StatusPill domain="oast" value={status} size="sm" />
              <span aria-hidden="true">→</span>
              <span className="sr-only">becomes</span>
              <StatusPill domain="oast" value={verdict} size="sm" />
            </dd>
          </div>
        </dl>
        <label className="oast-dialog-note">
          <span>Note (optional)</span>
          <textarea
            value={note}
            maxLength={4096}
            rows={3}
            placeholder={verdict === "confirmed" ? "What shows the target made the callback" : "Why the callback is noise"}
            onChange={(event) => setNote(event.target.value)}
            disabled={saving}
          />
        </label>
        {error && <p className="oast-dialog-error" role="alert">{error}</p>}
        <footer className="oast-dialog-actions">
          <button type="button" className="ghost-button" onClick={onClose} disabled={saving}>Cancel</button>
          <button type="button" className="primary-button" onClick={() => onConfirm(note)} disabled={saving}>
            {saving ? "Recording…" : `Record verdict: ${label}`}
          </button>
        </footer>
      </div>
    </div>
  );
}

// ── Probe record ──────────────────────────────────────────────────────
// One probe inside the shared RecordView (OastTab owns the view, the list
// order and the URL). The header carries the status, why, and the verdict
// actions; Probe holds the verdict, its metadata and notes; Callbacks holds
// the callback ledger from the DETAIL fetch, falling back to the list row's
// interaction_count while it loads.
function OastRecord({
  probe,
  detail,
  detailLoading,
  detailError,
  tab,
  onTabChange,
  onVerdict,
  titleId,
}: {
  probe: OobProbe;
  detail: OobProbeDetail | null;
  detailLoading: boolean;
  detailError: string | null;
  tab: OastRecordTab;
  onTabChange: (tab: OastRecordTab) => void;
  onVerdict: (verdict: OobVerdict) => void;
  titleId: string;
}) {
  const { toast } = useToast();
  const status = oobStatus(probe);
  const interactions: OobInteraction[] = detail?.interactions ?? [];
  const callbackCount = detail ? interactions.length : probe.interaction_count ?? 0;
  const linkedParts = linkedToParts(probe);
  const verdict = detail?.verdict ?? null;

  return (
    <>
      <RecordHeader
        id={`Probe #${probe.id}`}
        copyId={probe.nonce}
        copyIdLabel="Copy probe nonce"
        title={linkedParts.length ? <span className="mono">{linkedParts.join(" · ")}</span> : "Unattributed probe"}
        titleId={titleId}
        tone={statusTone("oast", status)}
        actions={
          <>
            {canRecordVerdict(probe) && <VerdictButtons status={status} onVerdict={onVerdict} />}
            <RecordCopyLinkButton noun="probe" />
          </>
        }
        pills={
          <>
            <StatusPill domain="oast" value={status} reason={lifecycleSentence(probe, callbackCount, verdict)} />
            {linkedParts.length === 0 && <LinkedTo probe={probe} />}
            {probe.probe_kind && <span className="tag">{probe.probe_kind}</span>}
            {probe.client_name && <span className="tag">{probe.client_name}</span>}
          </>
        }
        datesLabel="OAST probe dates"
        dates={[
          { label: "Planted", value: probe.created_at },
          { label: "Last callback", value: probe.last_interaction_at || null, fallback: status === "pending" ? "none yet" : "none" },
          { label: "Updated", value: probe.updated_at },
        ]}
      />
      <RecordTabs
        label="OAST probe sections"
        active={tab}
        onChange={onTabChange}
        tabs={[
          { id: "probe", label: "Probe" },
          { id: "callbacks", label: "Callbacks", count: callbackCount },
        ]}
      />
      <RecordBody busy={tab === "callbacks" && detailLoading}>
        {tab === "probe" && (
          <>
            <VerdictSection
              probe={probe}
              verdict={verdict}
              detailLoaded={detail !== null || detailError !== null}
              callbackCount={callbackCount}
            />
            <section className="section">
              <h3 className="section-title">Probe</h3>
              <div className="kv-grid">
                <KV k="Target URL" v={probe.target_url} mono toast={probe.target_url ? toast : undefined} />
                <KV k="Param" v={probe.param} mono />
                <KV k="Technique" v={probe.technique} />
                <KV k="Probe kind" v={probe.probe_kind} />
                <KV k="Client" v={probe.client_name} mono />
                {!(probe.client_name?.trim() && probe.client_payload_host?.trim()) && (
                  <KV k="Client binding" v="Not recorded — callbacks cannot be matched to an OAST client" />
                )}
                <KV k="Client payload host" v={probe.client_payload_host} mono toast={probe.client_payload_host ? toast : undefined} />
                <KV k="Nonce" v={probe.nonce} mono toast={probe.nonce ? toast : undefined} />
                <KV k="OOB domain" v={probe.oob_domain} mono toast={probe.oob_domain ? toast : undefined} />
                <KV k="Request hash" v={probe.request_hash} mono toast={probe.request_hash ? toast : undefined} />
                <KV k="Status" v={statusLabel("oast", status)} />
                {status === "pending" && <KVTime k="Waiting since" v={probe.created_at} precision="minute" />}
              </div>
            </section>

            {probe.notes && probe.notes.trim() && (
              <ProseSection title="Notes" text={probe.notes} mode="rendered" toast={toast} kind="callout" />
            )}
          </>
        )}

        {tab === "callbacks" && (
          <section className="section">
            <h3 className="section-title">
              Callbacks <span className="count">{callbackCount}</span>
            </h3>
            {detailLoading && !detail ? (
              <div className="oast-callbacks-loading">
                <Skeleton height={48} />
                <Skeleton height={120} />
              </div>
            ) : detailError && !detail ? (
              <p className="error-text oast-callbacks-error" role="alert">
                Callback history unavailable: {detailError}
              </p>
            ) : (
              <>
                {detailError ? (
                  <p className="error-text oast-callbacks-error" role="alert">
                    Callback history refresh failed: {detailError} (showing the last loaded history)
                  </p>
                ) : null}
                {interactions.length === 0 ? (
                  <EmptyState variant="empty" compact title={status === "pending" ? "No callbacks observed for this probe yet." : "No callbacks were observed for this probe."} />
                ) : (
                  <CallbackLedger interactions={interactions} toast={toast} />
                )}
              </>
            )}
          </section>
        )}
      </RecordBody>
    </>
  );
}
