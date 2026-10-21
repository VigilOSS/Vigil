// ── SurfacesTab ───────────────────────────────────────────────────────
// The attack-surface ledger: every entry point Vigil discovered and how far
// its testing has come. "Needs attention" (the default while any surface is
// open; All otherwise) shows the surfaces the server marks open (`open` on
// each row; the same rule as the rail badge). Scope, search and filters
// survive leaving the tab (sessionStorage, per engagement). Opening a surface
// replaces the list with the shared record view; Back, Escape and browser
// Back return to the list.

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GridApi } from "ag-grid-community";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import type {
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentFindingLink,
  AssessmentSurface,
  SurfacePatchPayload,
  SurfaceRequestVariantLink,
} from "../lib/api";
import {
  listAssessmentFindingLinks,
  listAssessmentSurfaces,
  listSurfaceRequestVariantLinks,
  patchAssessmentSurface,
} from "../lib/api";
import { useToast } from "../contexts/ToastContext";
import { KV, ProseSection, SectionHead } from "./drawer/DrawerKit";
import { SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FacetChipGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  StatusPill,
  describeSort,
  humanizeStatus,
  SeverityTag,
  statusLabel,
  statusOrder,
  statusTone,
  type FacetChipValue,
  type Scope,
  type SortKind,
} from "./ui";
import {
  RecordBody,
  RecordCopyButton,
  RecordCopyLinkButton,
  RecordHeader,
  RecordTabs,
  RecordView,
  useResultsScrollMemory,
} from "./record/RecordView";
import { listNavigation, useGridView } from "./record/recordNavigation";
import "../styles/surfaces.css";

// The workspace reads at most this many surfaces (EngagementPage's surface
// fetch limit); a ledger that fills it may hold more.
const SURFACE_SNAPSHOT_LIMIT = 5000;
// A record shown this long reads its request-variant links (for the section
// count) without waiting for the section; stepping past it reads nothing.
const VARIANT_LINKS_DWELL_MS = 400;

/** A surface row as the API returns it; `open` is the server's open-surface rule. */

/** Open (still needs testing), by the server's rule. */
function isOpen(surface: AssessmentSurface): boolean {
  return surface.open === true;
}

// Why the status reads as it does, shown in text beside the status pill.
function surfaceStatusReason(surface: AssessmentSurface): string | null {
  if (surface.status === "administratively-closed") return "Closed without coverage; still an open obligation";
  if (surface.status === "partially-covered" && surface.followup_condition) return `Follow-up: ${surface.followup_condition}`;
  return null;
}

type SurfaceRecordTab = "overview" | "findings" | "requests" | "status";
const SURFACE_RECORD_TABS: readonly SurfaceRecordTab[] = ["overview", "findings", "requests", "status"];

function isSurfaceRecordTab(value: string | undefined): value is SurfaceRecordTab {
  return (SURFACE_RECORD_TABS as readonly string[]).includes(value ?? "");
}

type FindingLike = AssessmentFinding | AssessmentFindingDetail;

// Heuristic: does a rationale string read like prose worth rendering as
// markdown (sentences / markdown markers), vs. a short flat label? Long or
// multi-sentence rationales render through MarkdownBlock; terse ones stay
// plain. Errs toward markdown for anything substantive.
function looksLikeProse(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (/[*_`#>\[\]]|\n/.test(t)) return true; // markdown markers / multi-line
  if (t.length > 120) return true; // long enough to be a paragraph
  return /[.!?]\s/.test(t); // multiple sentences
}

// ag-grid is heavy (~470 kB) — lazy-load the grid into a code-split chunk
// so the main entry bundle stays lean. Shares the chunk with the other
// grids via the common ../lib/agGrid import.
const SurfacesGrid = lazy(() => import("./SurfacesGrid"));

type SurfacesTabProps = {
  engagementKey: string;
  /** The surface ledger; null until the workspace has read it. */
  surfaces: AssessmentSurface[] | null;
  /** How many surfaces the workspace reads at most; a ledger this size may be cut off. */
  snapshotLimit?: number;
  loadError?: string | null;
  // Findings list (already loaded by the parent) used to resolve a linked
  // finding's severity + title for the record's "Linked findings" section.
  // Optional so the tab still renders standalone (count-only, no severity).
  findings?: FindingLike[];
  // Optional: parent refresh hook so a successful PATCH triggers a fresh
  // list fetch instead of waiting for the next polling tick.
  onSurfaceUpdated?: (surface: AssessmentSurface) => void;
  initialSurfaceId?: number;
  initialDrawerTab?: string;
};

const ATTENTION_RULE = "Surfaces still open: anything not yet covered and not ruled not applicable, including administratively closed ones.";

// Grid column → how "Sorted by …" names it.
const SORT_LABELS: Record<string, { label: string; kind: SortKind }> = {
  target: { label: "Target", kind: "text" },
  type: { label: "Type", kind: "text" },
  status: { label: "Status", kind: "status" },
  source: { label: "Source", kind: "text" },
  rationale: { label: "Rationale", kind: "text" },
  followup: { label: "Follow-up", kind: "text" },
  updated: { label: "Updated", kind: "time" },
};

// ── Search tokenizer ──────────────────────────────────────────────────

const SCOPES = ["type", "status", "source", "host"] as const;
type QueryScope = (typeof SCOPES)[number];

type ParsedQuery = {
  tokens: { scope: QueryScope; value: string }[];
  freeTerms: string[];
};

function parseQuery(q: string): ParsedQuery {
  const tokens: ParsedQuery["tokens"] = [];
  const freeTerms: string[] = [];
  const re = /(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q || "")) !== null) {
    const tok = m[1];
    const idx = tok.indexOf(":");
    if (idx > 0) {
      const scope = tok.slice(0, idx).toLowerCase();
      if ((SCOPES as readonly string[]).includes(scope)) {
        tokens.push({ scope: scope as QueryScope, value: tok.slice(idx + 1).toLowerCase() });
        continue;
      }
    }
    freeTerms.push(tok.toLowerCase());
  }
  return { tokens, freeTerms };
}

function extractHost(target: string): string {
  if (!target) return "";
  try {
    // Try as a URL
    return new URL(target).host.toLowerCase();
  } catch {
    // Fallback: treat `host:port`, `host/path` or a bare host
    const trimmed = target.trim();
    const noScheme = trimmed.replace(/^[a-zA-Z]+:\/\//, "");
    const hostPart = noScheme.split(/[\/?#]/)[0];
    return (hostPart.split(":")[0] || "").toLowerCase();
  }
}

function buildSearchCorpus(s: AssessmentSurface): string {
  return [
    s.surface_type,
    s.target_descriptor,
    s.source_name,
    s.rationale,
    s.evidence_ref,
    s.status,
    s.followup_condition,
    extractHost(s.target_descriptor),
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
}

/** Value → count, most common first. */
function countValues(rows: AssessmentSurface[], valueOf: (surface: AssessmentSurface) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const value = valueOf(row);
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function byCount(counts: Map<string, number>): FacetChipValue[] {
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
}

// ── Icons ─────────────────────────────────────────────────────────────

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

// ── Saved view ────────────────────────────────────────────────────────

type SurfacesView = {
  /** The scope the operator chose; null follows the default. */
  scope: Scope | null;
  query: string;
  type: string[];
  status: string[];
  source: string[];
};

const viewKey = (engagementKey: string) => `surfaces.view.${engagementKey}`;

function readView(engagementKey: string): SurfacesView {
  const strings = (value: unknown) => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);
  let value: Record<string, unknown> = {};
  try {
    value = JSON.parse(window.sessionStorage.getItem(viewKey(engagementKey)) || "{}") as Record<string, unknown>;
  } catch {
    // Browser storage may be unavailable or hold something else; start fresh.
  }
  return {
    scope: value.scope === "attention" || value.scope === "all" ? value.scope : null,
    query: typeof value.query === "string" ? value.query : "",
    type: strings(value.type),
    status: strings(value.status),
    source: strings(value.source),
  };
}

// ── Component ─────────────────────────────────────────────────────────

const typeOf = (s: AssessmentSurface) => s.surface_type || "unknown";
const statusOf = (s: AssessmentSurface) => s.status || "";
const sourceOf = (s: AssessmentSurface) => s.source_name || "";

export function SurfacesTab(props: SurfacesTabProps) {
  // Each engagement keeps its own saved view.
  return <SurfacesWorkspace key={props.engagementKey} {...props} />;
}

function SurfacesWorkspace({
  engagementKey,
  surfaces,
  snapshotLimit = SURFACE_SNAPSHOT_LIMIT,
  loadError = null,
  findings = [],
  onSurfaceUpdated,
  initialSurfaceId,
  initialDrawerTab,
}: SurfacesTabProps) {
  const [findingLinks, setFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [linksError, setLinksError] = useState<string | null>(null);
  const [linksLoading, setLinksLoading] = useState(true);
  // The URL owns which surface is open (`surface`) and its section (`dtab`).
  const [selectedId, setSelectedId] = useState<number | null>(initialSurfaceId ?? null);
  const [recordTab, setRecordTab] = useState<SurfaceRecordTab>(isSurfaceRecordTab(initialDrawerTab) ? initialDrawerTab : "overview");
  const [gridView, reportGridView] = useGridView<number>();
  const gridApiRef = useRef<GridApi<AssessmentSurface> | null>(null);
  // Track the in-flight PATCH so the inline button shows a busy state and
  // disables itself until the network round-trip resolves.
  const [pendingResolution, setPendingResolution] = useState<string | null>(null);
  const [resolutionError, setResolutionError] = useState<string | null>(null);
  const [resolutionRationale, setResolutionRationale] = useState<string>("");
  const [followupCondition, setFollowupCondition] = useState<string>("");
  // Local shadow of the parent ``surfaces`` prop. The parent does not
  // currently wire ``onSurfaceUpdated`` back into its list, so without a
  // shadow the table goes stale until the next polling tick. We seed
  // from the prop and merge updates locally; whenever the prop changes
  // (poll refresh) it wins.
  const [localSurfaces, setLocalSurfaces] = useState<AssessmentSurface[]>(surfaces ?? []);
  useEffect(() => {
    if (surfaces !== null) setLocalSurfaces(surfaces);
  }, [surfaces]);
  // Nothing read yet: the list shows a loading table, never a false empty state.
  const awaitingLedger = surfaces === null && !loadError && localSurfaces.length === 0;

  const selected = selectedId === null ? null : localSurfaces.find((surface) => surface.id === selectedId) ?? null;

  const mergeLocalSurface = useCallback((updated: AssessmentSurface) => {
    setLocalSurfaces((current) => {
      const idx = current.findIndex((s) => s.id === updated.id);
      if (idx === -1) return [updated, ...current];
      const next = current.slice();
      next[idx] = updated;
      return next;
    });
  }, []);

  const resolveSurfaceStatus = useCallback(
    async (status: SurfacePatchPayload["status"]) => {
      if (!selected || !status) return;
      const submittedRationale = resolutionRationale.trim();
      if (!submittedRationale) {
        setResolutionError("Rationale is required to change surface status.");
        return;
      }
      if (submittedRationale.length > 4096) {
        setResolutionError("Rationale must be at most 4096 characters.");
        return;
      }
      const submittedFollowup = followupCondition.trim();
      if (status === "partially-covered" && !submittedFollowup) {
        setResolutionError("A follow-up condition is required for partially covered surfaces.");
        return;
      }
      if (status === "partially-covered" && submittedFollowup.length > 4096) {
        setResolutionError("Follow-up condition must be at most 4096 characters.");
        return;
      }
      setResolutionError(null);
      setPendingResolution(status);
      try {
        const payload: SurfacePatchPayload = {
          status,
          rationale: submittedRationale,
        };
        if (status === "partially-covered") payload.followup_condition = submittedFollowup;
        const updated = await patchAssessmentSurface(engagementKey, selected.id, payload);
        mergeLocalSurface(updated);
        setResolutionRationale("");
        setFollowupCondition("");
        onSurfaceUpdated?.(updated);
      } catch (err: unknown) {
        // Network errors are ambiguous: the PATCH may have already landed
        // server-side. Refetch the list so we can tell, then either treat
        // the operation as successful (the change is durable) or surface
        // the error so the operator can retry without double-appending
        // the rationale.
        const errorMessage =
          err instanceof Error ? err.message : "Failed to update surface status";
        try {
          const fresh = await listAssessmentSurfaces(engagementKey, {
            limit: snapshotLimit,
          });
          const refreshed = fresh.find((s) => s.id === selected.id) ?? null;
          if (refreshed) {
            const rationaleLanded =
              !submittedRationale ||
              (refreshed.rationale ?? "").includes(submittedRationale);
            const statusLanded = refreshed.status === status;
            if (statusLanded && rationaleLanded) {
              // The first PATCH succeeded server-side despite the network
              // error. Reflect the persisted state and do not surface an
              // error — retrying would double-append the rationale.
              mergeLocalSurface(refreshed);
              setResolutionRationale("");
              setFollowupCondition("");
              onSurfaceUpdated?.(refreshed);
              return;
            }
            // The change did not land. Reseed the record with what is
            // actually persisted (so subsequent retries diff against the
            // server's truth) and surface the error so the operator can
            // retry safely.
            mergeLocalSurface(refreshed);
          }
        } catch {
          // Refetch failed too — fall through to surface the original
          // error. The operator will see "Failed to update" and can
          // retry; the server-side substring dedup on rationale will
          // prevent a double-append on the happy path.
        }
        setResolutionError(errorMessage);
      } finally {
        setPendingResolution(null);
      }
    },
    [engagementKey, followupCondition, mergeLocalSurface, onSurfaceUpdated, resolutionRationale, selected, snapshotLimit],
  );

  const [savedView] = useState(() => readView(engagementKey));
  const [query, setQuery] = useState(savedView.query);
  const [chosenScope, setScope] = useState<Scope | null>(savedView.scope);
  const [typeFilters, setTypeFilters] = useState<Set<string>>(() => new Set(savedView.type));
  const [statusFilters, setStatusFilters] = useState<Set<string>>(() => new Set(savedView.status));
  const [sourceFilters, setSourceFilters] = useState<Set<string>>(() => new Set(savedView.source));
  useEffect(() => {
    const view: SurfacesView = { scope: chosenScope, query, type: [...typeFilters], status: [...statusFilters], source: [...sourceFilters] };
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(view));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, chosenScope, query, typeFilters, statusFilters, sourceFilters]);
  const openSurfaceCount = useMemo(
    () => localSurfaces.reduce((count, surface) => count + (isOpen(surface) ? 1 : 0), 0),
    [localSurfaces],
  );
  // Needs attention while any surface is open, else All, until the operator chooses.
  const scope: Scope = chosenScope ?? (openSurfaceCount > 0 ? "attention" : "all");

  const searchRef = useRef<HTMLInputElement | null>(null);
  const invokerRef = useRef<HTMLElement | null>(null);
  const canSubmitResolution = resolutionRationale.trim().length > 0;

  useEffect(() => {
    setResolutionRationale("");
    setFollowupCondition("");
    setResolutionError(null);
  }, [selectedId]);

  useEffect(() => {
    setSelectedId(initialSurfaceId ?? null);
  }, [initialSurfaceId]);
  useEffect(() => {
    setRecordTab(isSurfaceRecordTab(initialDrawerTab) ? initialDrawerTab : "overview");
  }, [initialDrawerTab]);
  // A linked surface the default view hides (no longer open) is shown among
  // All rather than as outside the results. Once per link.
  const shownRouteSurface = useRef<number | null>(null);
  useEffect(() => {
    if (initialSurfaceId === undefined) {
      shownRouteSurface.current = null;
      return;
    }
    if (shownRouteSurface.current === initialSurfaceId) return;
    const linked = localSurfaces.find((surface) => surface.id === initialSurfaceId);
    if (!linked) return;
    shownRouteSurface.current = initialSurfaceId;
    if (!isOpen(linked)) setScope("all");
  }, [initialSurfaceId, localSurfaces]);

  // From the list: remember the row for the return trip and start on
  // Overview. Stepping between records keeps the open section.
  const openSurface = useCallback((surface: AssessmentSurface, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    setSelectedId(surface.id);
    setRecordTab("overview");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "surfaces", surface: surface.id }));
  }, [engagementKey]);
  const stepToSurface = useCallback((id: number) => {
    setSelectedId(id);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "surfaces", surface: id, dtab: recordTab === "overview" ? undefined : recordTab }));
  }, [engagementKey, recordTab]);
  const closeSurface = useCallback(() => {
    setSelectedId(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "surfaces" }));
  }, [engagementKey]);
  const chooseRecordTab = useCallback((next: SurfaceRecordTab) => {
    setRecordTab(next);
    if (selectedId !== null) {
      writeWorkspaceHash(engagementHref(engagementKey, { tab: "surfaces", surface: selectedId, dtab: next === "overview" ? undefined : next }));
    }
  }, [engagementKey, selectedId]);

  useEffect(() => {
    let cancelled = false;
    setLinksLoading(true);
    setLinksError(null);
    listAssessmentFindingLinks(engagementKey)
      .then((rows) => {
        if (cancelled) return;
        setFindingLinks(rows);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setFindingLinks([]);
        setLinksError(err instanceof Error ? err.message : "Failed to load finding links");
      })
      .finally(() => { if (!cancelled) setLinksLoading(false); });
    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  // surface_id -> linked findings map
  const linksBySurfaceId = useMemo(() => {
    const map = new Map<number, AssessmentFindingLink[]>();
    for (const link of findingLinks) {
      if (link.target_kind !== "surface") continue;
      const id = link.target_id ?? (/^\d+$/.test(link.target_ref) ? Number(link.target_ref) : NaN);
      if (!Number.isSafeInteger(id) || id <= 0) continue;
      const list = map.get(id) ?? [];
      list.push(link);
      map.set(id, list);
    }
    return map;
  }, [findingLinks]);

  // slug -> finding, so the record's Linked findings list can resolve a
  // link's severity + title for its badge + deep link.
  const findingBySlug = useMemo(() => {
    const m = new Map<string, FindingLike>();
    for (const f of findings) m.set(f.slug, f);
    return m;
  }, [findings]);

  // Pre-compute searchable corpus per surface
  const corpusBySurfaceId = useMemo(() => {
    const m = new Map<number, string>();
    for (const s of localSurfaces) m.set(s.id, buildSearchCorpus(s));
    return m;
  }, [localSurfaces]);

  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (s: AssessmentSurface, parsed: ParsedQuery): boolean => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "type":
            if (!(s.surface_type || "").toLowerCase().includes(v)) return false;
            break;
          case "status":
            if ((s.status || "").toLowerCase() !== v) return false;
            break;
          case "source":
            if (!(s.source_name || "").toLowerCase().includes(v)) return false;
            break;
          case "host": {
            const host = extractHost(s.target_descriptor);
            if (!host.includes(v)) return false;
            break;
          }
        }
      }
      if (parsed.freeTerms.length) {
        const corpus = corpusBySurfaceId.get(s.id) || "";
        for (const t of parsed.freeTerms) if (!corpus.includes(t)) return false;
      }
      return true;
    },
    [corpusBySurfaceId],
  );

  // The scope and search narrow everything; each chip group then counts the
  // rows the OTHER chip groups leave, so a chip never offers a value that
  // cannot match in the current view.
  const scoped = useMemo(
    () => localSurfaces.filter((s) => (scope === "all" || isOpen(s)) && matchesQuery(s, parsedQuery)),
    [localSurfaces, scope, parsedQuery, matchesQuery],
  );
  const passes = useCallback((s: AssessmentSurface, skip: "type" | "status" | "source" | null) => (
    (skip === "type" || !typeFilters.size || typeFilters.has(typeOf(s)))
    && (skip === "status" || !statusFilters.size || statusFilters.has(statusOf(s)))
    && (skip === "source" || !sourceFilters.size || sourceFilters.has(sourceOf(s)))
  ), [typeFilters, statusFilters, sourceFilters]);
  const filteredSurfaces = useMemo(() => scoped.filter((s) => passes(s, null)), [scoped, passes]);
  const typeValues = useMemo(() => byCount(countValues(scoped.filter((s) => passes(s, "type")), typeOf)), [scoped, passes]);
  const statusValues = useMemo(() => {
    const counts = countValues(scoped.filter((s) => passes(s, "status")), statusOf);
    const order = statusOrder("surface");
    const rank = (value: string) => (order.indexOf(value) < 0 ? order.length : order.indexOf(value));
    return [...counts].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
  }, [scoped, passes]);
  const sourceValues = useMemo(() => byCount(countValues(scoped.filter((s) => passes(s, "source")), sourceOf)), [scoped, passes]);

  // surface id → linked-findings count, for the grid's Findings column.
  const linkCounts = useMemo(() => {
    const m = new Map<number, number>();
    for (const [id, list] of linksBySurfaceId) m.set(id, list.length);
    return m;
  }, [linksBySurfaceId]);

  function toggleChip(set: Set<string>, setter: (s: Set<string>) => void, val: string) {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
  }

  function clearAll() {
    setQuery("");
    setTypeFilters(new Set());
    setStatusFilters(new Set());
    setSourceFilters(new Set());
  }

  const activeFilterCount =
    typeFilters.size + statusFilters.size + sourceFilters.size + (query ? 1 : 0);
  const snapshotLimitReached = localSurfaces.length >= snapshotLimit;

  const selectedLinks = selected ? linksBySurfaceId.get(selected.id) ?? [] : [];
  const investigating = selected !== null;
  const routeMissing = initialSurfaceId !== undefined && selectedId === initialSurfaceId && !selected && surfaces !== null && localSurfaces.length > 0;

  // Previous / Next walk the list as shown: current filters, grid sort.
  // Until the grid reports its order (a deep link opens the record before
  // the hidden grid has laid out its rows), walk the ledger's order.
  const reviewOrder = useMemo(() => {
    const visible = new Set(filteredSurfaces.map((surface) => surface.id));
    const shown = gridView?.ids.filter((id) => visible.has(id));
    if (shown && shown.length === visible.size) return shown;
    return filteredSurfaces.map((surface) => surface.id);
  }, [filteredSurfaces, gridView]);
  const reviewNavigation = listNavigation(reviewOrder, selectedId, stepToSurface);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const reveal = useCallback((key: string) => {
    const api = gridApiRef.current;
    const node = api?.getRowNode(key);
    if (api && node) api.ensureNodeVisible(node, "middle");
  }, []);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: selectedId, reveal });

  // Keyboard shortcuts: `/` focuses search (leaving an open record), `Esc`
  // leaves the search box. The open record handles its own Escape.
  const investigatingRef = useRef(investigating);
  investigatingRef.current = investigating;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea" || tag === "select";
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        if (investigatingRef.current) closeSurface();
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
  }, [closeSurface]);

  const empty = !awaitingLedger && localSurfaces.length === 0;
  const sortEntry = gridView?.sort[0];
  const sortLabel = SORT_LABELS[sortEntry?.colId ?? "updated"] ?? SORT_LABELS.updated;
  const unavailable = Boolean(loadError) && empty;

  return (
    <div className="findings-redesign surfaces-page">
      <PageHeader
        title="Surfaces"
        purpose="Every entry point Vigil found on the target and how far its testing has come. Open surfaces still need testing or a decision."
        stats={empty || awaitingLedger ? [] : [
          { value: openSurfaceCount, label: "open", tone: openSurfaceCount > 0 ? "warning" : undefined, title: ATTENTION_RULE },
          { value: localSurfaces.length, label: "surfaces" },
        ]}
        hidden={investigating}
      >
        {!empty && !awaitingLedger && (
          <ScopeToggle
            scope={scope}
            onChange={setScope}
            attentionCount={openSurfaceCount}
            allCount={localSurfaces.length}
            attentionRule={ATTENTION_RULE}
            label="Surface scope"
          />
        )}
      </PageHeader>
      {routeMissing && (
        <p className="surfaces-route-missing error-text" role="alert">
          Surface #{initialSurfaceId} is not in the loaded surface ledger.
        </p>
      )}
      <div ref={resultsRef} className="surfaces-results" hidden={investigating}>
      {/* Toolbar */}
      <div className="panel findings-toolbar-panel" hidden={empty}>
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              type="search"
              className="search-input"
              aria-label="Search surfaces"
              placeholder="Search surfaces — target, rationale, source… (try type:api status:deferred host:example.com)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                aria-label="Clear surface search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
        </div>
        <div className="filter-row surfaces-filter-row">
          {(statusValues.length > 0 || statusFilters.size > 0) && (
            <FacetChipGroup
              label="Status"
              values={statusValues}
              selected={statusFilters}
              onToggle={(value) => toggleChip(statusFilters, setStatusFilters, value)}
              labelFor={(value) => statusLabel("surface", value)}
              statusDomain="surface"
              collapsedLimit={12}
            />
          )}
          {(typeValues.length > 0 || typeFilters.size > 0) && (
            <FacetChipGroup
              label="Type"
              values={typeValues}
              selected={typeFilters}
              onToggle={(value) => toggleChip(typeFilters, setTypeFilters, value)}
              labelFor={(value) => humanizeStatus(value)}
              collapsedLimit={12}
            />
          )}
          {(sourceValues.length > 0 || sourceFilters.size > 0) && (
            <FacetChipGroup
              label="Source"
              values={sourceValues}
              selected={sourceFilters}
              onToggle={(value) => toggleChip(sourceFilters, setSourceFilters, value)}
            />
          )}
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
        </div>
      </div>

      {/* Surfaces table */}
      <section className="panel surfaces-list-panel">
        {!empty && !awaitingLedger && (
          <div className="surfaces-list-head">
            <ResultsSummary
              shown={filteredSurfaces.length}
              total={localSurfaces.length}
              noun="surfaces"
              sort={describeSort(sortLabel.label, sortEntry?.sort ?? "desc", sortLabel.kind)}
            />
            <span className="meta-text">
              {linksError ? "Finding links unavailable" : ""}
              {snapshotLimitReached ? " · surface limit reached · results may be incomplete" : ""}
            </span>
          </div>
        )}

        {loadError ? (
          <p className="error-text surfaces-load-error" role="alert">
            Surface ledger unavailable: {loadError}
          </p>
        ) : null}

        {awaitingLedger ? (
          <>
            <TableSkeleton rows={8} showHeader={false} />
            <SlowLoadHint active what="the surface ledger" />
          </>
        ) : unavailable ? null : empty ? (
          <EmptyState variant="empty" title="No surfaces discovered yet.">
            Agents record each entry point they find (login forms, APIs, upload handlers) as a surface to test.
          </EmptyState>
        ) : (
          <>
            {filteredSurfaces.length === 0 && (activeFilterCount > 0 ? (
              <EmptyState variant="filtered" title="No surfaces match these filters." onClearFilters={clearAll} />
            ) : (
              <EmptyState
                variant="empty"
                title="No surfaces need attention."
                action={<button type="button" className="ui-button" onClick={() => setScope("all")}>Show all {localSurfaces.length.toLocaleString()}</button>}
              >
                Every surface is covered or ruled not applicable.
              </EmptyState>
            ))}
            {/* The grid stays mounted behind an empty result, so its sort survives. */}
            <div className="surfaces-grid-wrap" hidden={filteredSurfaces.length === 0}>
              <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
                <SurfacesGrid
                  rows={filteredSurfaces}
                  linkCounts={linkCounts}
                  selectedId={selectedId}
                  onRowOpen={openSurface}
                  onViewChange={reportGridView}
                  onApi={(api) => { gridApiRef.current = api; }}
                />
              </Suspense>
            </div>
          </>
        )}
      </section>
      </div>

      {selected && (
        <RecordView
          label="Surface record"
          noun="surface"
          navigation={reviewNavigation}
          onBack={closeSurface}
          titleId="surface-record-title"
          returnFocusRef={invokerRef}
        >
          <SurfaceRecord
            key={selected.id}
            engagementKey={engagementKey}
            surface={selected}
            tab={recordTab}
            onTabChange={chooseRecordTab}
            titleId="surface-record-title"
            links={selectedLinks}
            linksLoading={linksLoading}
            linksError={linksError}
            findingBySlug={findingBySlug}
            resolutionRationale={resolutionRationale}
            setResolutionRationale={setResolutionRationale}
            followupCondition={followupCondition}
            setFollowupCondition={setFollowupCondition}
            pendingResolution={pendingResolution}
            canSubmitResolution={canSubmitResolution}
            resolutionError={resolutionError}
            resolveSurfaceStatus={resolveSurfaceStatus}
          />
        </RecordView>
      )}
    </div>
  );
}

// ── Surface record ────────────────────────────────────────────────────
// One surface inside the shared RecordView (SurfacesTab owns the view, the
// list order and the URL). Sections: what the surface is and why it was
// recorded (Overview), the findings and HTTP request variants tied to it,
// and the evidence-backed status change (Change status). Request-variant
// links are read once the record settles or their section opens, so stepping
// quickly through records reads nothing.
function SurfaceRecord({
  engagementKey,
  surface,
  tab,
  onTabChange,
  titleId,
  links,
  linksLoading,
  linksError,
  findingBySlug,
  resolutionRationale,
  setResolutionRationale,
  followupCondition,
  setFollowupCondition,
  pendingResolution,
  canSubmitResolution,
  resolutionError,
  resolveSurfaceStatus,
}: {
  engagementKey: string;
  surface: AssessmentSurface;
  tab: SurfaceRecordTab;
  onTabChange: (tab: SurfaceRecordTab) => void;
  titleId: string;
  links: AssessmentFindingLink[];
  linksLoading: boolean;
  linksError: string | null;
  findingBySlug: Map<string, FindingLike>;
  resolutionRationale: string;
  setResolutionRationale: (v: string) => void;
  followupCondition: string;
  setFollowupCondition: (v: string) => void;
  pendingResolution: string | null;
  canSubmitResolution: boolean;
  resolutionError: string | null;
  resolveSurfaceStatus: (status: SurfacePatchPayload["status"]) => void | Promise<void>;
}) {
  const { toast } = useToast();
  const [variantLinks, setVariantLinks] = useState<SurfaceRequestVariantLink[]>([]);
  const [variantLinksError, setVariantLinksError] = useState<string | null>(null);
  const [variantLinksLoading, setVariantLinksLoading] = useState(true);
  const rationale = surface.rationale || "";
  const reason = surfaceStatusReason(surface);
  const findingHref = (slug: string) => engagementHref(engagementKey, { tab: "findings", finding: slug });
  const httpHref = (requestVariantId: number) => engagementHref(engagementKey, { tab: "http", request: requestVariantId });

  // Read on opening the section, or once the record has been shown a moment.
  const [variantLinksWanted, setVariantLinksWanted] = useState(tab === "requests");
  useEffect(() => {
    if (tab === "requests") {
      setVariantLinksWanted(true);
      return undefined;
    }
    const timer = window.setTimeout(() => setVariantLinksWanted(true), VARIANT_LINKS_DWELL_MS);
    return () => window.clearTimeout(timer);
  }, [tab]);
  useEffect(() => {
    if (!variantLinksWanted) return undefined;
    let cancelled = false;
    setVariantLinks([]);
    setVariantLinksError(null);
    setVariantLinksLoading(true);
    listSurfaceRequestVariantLinks(engagementKey, surface.id)
      .then((rows) => {
        if (!cancelled) setVariantLinks(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setVariantLinksError(err instanceof Error ? err.message : "Request-variant links unavailable");
        }
      })
      .finally(() => {
        if (!cancelled) setVariantLinksLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, surface.id, variantLinksWanted]);

  return (
    <>
      <RecordHeader
        id={`Surface #${surface.id}`}
        copyId={String(surface.id)}
        copyIdLabel="Copy surface ID"
        title={<span className="mono">{surface.target_descriptor}</span>}
        titleId={titleId}
        tone={statusTone("surface", surface.status)}
        actions={
          <>
            <RecordCopyButton
              label="Copy target descriptor"
              text={() => surface.target_descriptor}
              successMessage="Copied target descriptor"
              failureMessage="Could not copy the target descriptor. Select it from the title."
              disabled={!surface.target_descriptor}
            />
            <RecordCopyLinkButton noun="surface" />
          </>
        }
        pills={
          <>
            <StatusPill domain="surface" value={surface.status} reason={reason} />
            {surface.surface_type && <span className="tag" title="Surface type">{humanizeStatus(surface.surface_type)}</span>}
            {surface.vendor_saas && <span className="tag">Vendor SaaS</span>}
            {surface.source_name && <span className="tag">{surface.source_name}</span>}
          </>
        }
        datesLabel="Surface dates"
        dates={[
          { label: "Created", value: surface.created_at },
          { label: "Updated", value: surface.updated_at },
        ]}
      />
      <RecordTabs
        label="Surface sections"
        active={tab}
        onChange={onTabChange}
        tabs={[
          { id: "overview", label: "Overview" },
          { id: "findings", label: "Linked findings", count: linksLoading || linksError ? undefined : links.length },
          { id: "requests", label: "Request variants", count: variantLinksLoading || variantLinksError ? undefined : variantLinks.length },
          { id: "status", label: "Change status" },
        ]}
      />
      <RecordBody>
        {tab === "overview" && (
          <>
            <section className="section">
              <h3 className="section-title">Surface</h3>
              <div className="kv-grid">
                <KV k="Surface type" v={surface.surface_type} />
                {/* The architecture axis: how the host framework registers this
                    code. Empty on an ordinary web surface, and KV drops empties. */}
                <KV k="Framework registration" v={surface.framework_registration} />
                <KV k="Status" v={statusLabel("surface", surface.status)} />
                <KV k="Follow-up condition" v={surface.followup_condition} />
                <KV k="Source" v={surface.source_name} toast={surface.source_name ? toast : undefined} />
                <KV k="Vendor SaaS" v={surface.vendor_saas == null ? "" : surface.vendor_saas ? "yes" : "no"} />
                <KV
                  k="Evidence ref"
                  v={surface.evidence_ref}
                  mono
                  toast={surface.evidence_ref ? toast : undefined}
                />
              </div>
            </section>

            {/* Rationale: markdown when it reads like prose, plain otherwise. */}
            {rationale && looksLikeProse(rationale) ? (
              <ProseSection title="Rationale" text={rationale} mode="rendered" toast={toast} kind="callout" />
            ) : rationale ? (
              <div className="callout">
                <SectionHead title="Rationale" copyText={rationale} toast={toast} />
                <p>{rationale}</p>
              </div>
            ) : (
              <EmptyState variant="empty" compact title="No rationale recorded." />
            )}
          </>
        )}

        {tab === "findings" && (
          <section className="section">
            <h3 className="section-title">
              Linked findings {!linksLoading && !linksError && <span className="count">{links.length}</span>}
            </h3>
            {linksLoading ? (
              <p className="meta-text" role="status">Loading finding links…</p>
            ) : linksError ? (
              <p className="error-text" role="alert">Finding links unavailable: {linksError}</p>
            ) : links.length === 0 ? (
              <EmptyState variant="empty" compact title="No findings linked to this surface yet." />
            ) : (
              <div className="link-grid">
                {links.map((link) => {
                  const finding = findingBySlug.get(link.finding_slug);
                  const severity = finding?.severity;
                  return (
                    <a
                      key={link.id}
                      className="link-card"
                      href={findingHref(link.finding_slug)}
                      title="Open this finding"
                    >
                      <span className="link-kind">{humanizeStatus(link.link_kind || "")}</span>
                      <span>
                        <span className="link-title">{finding?.title || link.finding_slug}</span>
                        <br />
                        <span className="link-sub">
                          {link.finding_slug}
                          {link.notes ? ` · ${link.notes}` : ""}
                        </span>
                      </span>
                      {severity ? <SeverityTag severity={severity} size="sm" /> : <span />}
                      <span className="link-go">›</span>
                    </a>
                  );
                })}
              </div>
            )}
          </section>
        )}

        {tab === "requests" && (
          <section className="section">
            <h3 className="section-title">
              Request variants {!variantLinksLoading && !variantLinksError && <span className="count">{variantLinks.length}</span>}
            </h3>
            {variantLinksLoading ? (
              <p className="meta-text" role="status">Loading request-variant links…</p>
            ) : variantLinksError ? (
              <p className="error-text" role="alert">Request-variant links unavailable: {variantLinksError}</p>
            ) : variantLinks.length === 0 ? (
              <EmptyState variant="empty" compact title="No durable request-variant links." />
            ) : (
              <div className="link-grid">
                {variantLinks.map((link) => (
                  <a
                    key={link.id}
                    className="link-card"
                    href={httpHref(link.request_variant_id)}
                    title="Open request variant in HTTP workspace"
                  >
                    <span className="link-kind">HTTP</span>
                    <span>
                      <span className="link-title">Request variant #{link.request_variant_id}</span>
                      <br />
                      <span className="link-sub">{humanizeStatus(link.relation || "related")}</span>
                      {link.evidence_ref && <span className="link-notes mono">{link.evidence_ref}</span>}
                    </span>
                    <span className="link-go">›</span>
                  </a>
                ))}
              </div>
            )}
          </section>
        )}

        {tab === "status" && (
          <>
            <section className="section surface-lifecycle">
              <h3 className="section-title">Coverage lifecycle</h3>
              <p className="meta-text">
                Record the evidence-backed state. A rationale is required for every transition and is appended to the audit trail.
              </p>
              <textarea
                className="surface-rationale-field"
                aria-label="Transition rationale"
                rows={3}
                placeholder="Required rationale appended to the audit trail"
                value={resolutionRationale}
                onChange={(e) => setResolutionRationale(e.target.value)}
                maxLength={4096}
              />
              <label className="surface-followup-field">
                <span>Required follow-up condition</span>
                <input
                  aria-label="Required follow-up condition"
                  type="text"
                  placeholder="Required when marking partially covered"
                  value={followupCondition}
                  onChange={(event) => setFollowupCondition(event.target.value)}
                  maxLength={4096}
                />
              </label>
              <div className="surface-status-actions">
                {(["covered", "partially-covered", "deferred", "not_applicable"] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`filter-chip ${pendingResolution === s ? "is-active" : ""}`}
                    disabled={pendingResolution != null || !canSubmitResolution}
                    title={!canSubmitResolution ? "Enter rationale to change status" : undefined}
                    aria-label={`Mark ${statusLabel("surface", s).toLowerCase()}`}
                    onClick={() => void resolveSurfaceStatus(s)}
                  >
                    {pendingResolution === s ? "Saving…" : `Mark ${statusLabel("surface", s).toLowerCase()}`}
                  </button>
                ))}
              </div>
              {resolutionError && (
                <p role="alert" className="error-text surface-status-error">
                  {resolutionError}
                </p>
              )}
            </section>

            <section className="section surface-admin-closure">
              <h3 className="section-title">Administrative closure</h3>
              <p className="meta-text">
                Administrative closure does not establish coverage. It closes queue handling while preserving this surface as an uncovered obligation.
              </p>
              <button
                type="button"
                className={`filter-chip ${pendingResolution === "administratively-closed" ? "is-active" : ""}`}
                disabled={pendingResolution != null || !canSubmitResolution}
                title={!canSubmitResolution ? "Enter rationale to change status" : undefined}
                aria-label="Mark administratively closed"
                onClick={() => void resolveSurfaceStatus("administratively-closed")}
              >
                {pendingResolution === "administratively-closed" ? "Saving…" : "Mark administratively closed"}
              </button>
            </section>
          </>
        )}
      </RecordBody>
    </>
  );
}
