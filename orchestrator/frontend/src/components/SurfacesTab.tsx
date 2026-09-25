import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
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
import { Copy } from "lucide-react";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { useToast } from "../contexts/ToastContext";
import { RelTime } from "./formatting";
import { KV, ProseSection, SectionHead } from "./drawer/DrawerKit";
import { TableSkeleton } from "./Skeletons";

const SURFACE_RETRY_FETCH_LIMIT = 5000;
const RETIRED_SURFACE_STATUSES = new Set(["covered", "not_applicable"]);

function surfaceNeedsAction(surface: AssessmentSurface): boolean {
  return !RETIRED_SURFACE_STATUSES.has(surface.status || "discovered");
}

function surfaceStatusLabel(status: string): string {
  return status.replace(/[-_]/g, " ");
}

function surfaceStatusPill(status: string): string {
  if (status === "covered") return "pill-confirmed";
  if (status === "not_applicable") return "pill-false_positive";
  if (status === "administratively-closed") return "pill-blocked";
  if (status === "partially-covered") return "pill-active";
  if (status === "deferred") return "pill-unreviewed";
  return "pill-unreviewed";
}

// Severity palette + dot color, mirrored from FindingsTab so the linked-
// findings list reads consistently with the Findings drawer's severity dots.
const SEV_COLORS: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};
function sevDotColor(sev: string): string {
  return SEV_COLORS[sev] || "var(--sev-info)";
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
  surfaces: AssessmentSurface[];
  loadError?: string | null;
  // Findings list (already loaded by the parent) used to resolve a linked
  // finding's severity + title for the drawer's "Linked findings" section.
  // Optional so the tab still renders standalone (count-only, no severity).
  findings?: FindingLike[];
  // Optional: parent refresh hook so a successful PATCH triggers a fresh
  // list fetch instead of waiting for the next polling tick.
  onSurfaceUpdated?: (surface: AssessmentSurface) => void;
};

// ── Search tokenizer ──────────────────────────────────────────────────

const SCOPES = ["type", "status", "source", "host"] as const;
type Scope = (typeof SCOPES)[number];

type ParsedQuery = {
  tokens: { scope: Scope; value: string }[];
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
        tokens.push({ scope: scope as Scope, value: tok.slice(idx + 1).toLowerCase() });
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
    extractHost(s.target_descriptor),
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
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

// ── Component ─────────────────────────────────────────────────────────

export function SurfacesTab({
  engagementKey,
  surfaces,
  loadError = null,
  findings = [],
  onSurfaceUpdated,
}: SurfacesTabProps) {
  const { toast } = useToast();
  const [findingLinks, setFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [linksError, setLinksError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AssessmentSurface | null>(null);
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
  const [localSurfaces, setLocalSurfaces] = useState<AssessmentSurface[]>(surfaces);
  useEffect(() => {
    setLocalSurfaces(surfaces);
  }, [surfaces]);

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
        setSelected(updated);
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
            limit: SURFACE_RETRY_FETCH_LIMIT,
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
              setSelected(refreshed);
              mergeLocalSurface(refreshed);
              setResolutionRationale("");
              setFollowupCondition("");
              onSurfaceUpdated?.(refreshed);
              return;
            }
            // The change did not land. Reseed selected with what is
            // actually persisted (so subsequent retries diff against the
            // server's truth) and surface the error so the operator can
            // retry safely.
            setSelected(refreshed);
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
    [engagementKey, followupCondition, mergeLocalSurface, onSurfaceUpdated, resolutionRationale, selected],
  );

  const [query, setQuery] = useState("");
  const [viewMode, setViewMode] = useState<"needs_action" | "all">("needs_action");
  const [typeFilters, setTypeFilters] = useState<Set<string>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [sourceFilters, setSourceFilters] = useState<Set<string>>(new Set());

  const searchRef = useRef<HTMLInputElement | null>(null);
  const drawerInvokerRef = useRef<HTMLElement | null>(null);
  const canSubmitResolution = resolutionRationale.trim().length > 0;

  useEffect(() => {
    setResolutionRationale("");
    setFollowupCondition("");
    setResolutionError(null);
  }, [selected?.id]);

  useEffect(() => {
    let cancelled = false;
    listAssessmentFindingLinks(engagementKey)
      .then((rows) => {
        if (cancelled) return;
        setFindingLinks(rows);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setFindingLinks([]);
        setLinksError(err instanceof Error ? err.message : "Failed to load finding links");
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  // surface_id -> linked findings map
  const linksBySurfaceId = useMemo(() => {
    const map = new Map<number, AssessmentFindingLink[]>();
    for (const link of findingLinks) {
      if (link.target_kind !== "surface") continue;
      const id = Number.parseInt(link.target_ref, 10);
      if (!Number.isFinite(id)) continue;
      const list = map.get(id) ?? [];
      list.push(link);
      map.set(id, list);
    }
    return map;
  }, [findingLinks]);

  // slug -> finding, so the drawer's Linked-findings list can resolve a
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

  const filteredSurfaces = useMemo(() => {
    return localSurfaces.filter((s) => {
      if (viewMode === "needs_action" && !surfaceNeedsAction(s)) return false;
      if (typeFilters.size && !typeFilters.has(s.surface_type || "unknown")) return false;
      if (statusFilters.size && !statusFilters.has(s.status || "")) return false;
      if (sourceFilters.size && !sourceFilters.has(s.source_name || "")) return false;
      if (!matchesQuery(s, parsedQuery)) return false;
      return true;
    });
  }, [localSurfaces, viewMode, typeFilters, statusFilters, sourceFilters, parsedQuery, matchesQuery]);

  // surface id → linked-findings count, for the grid's Findings column.
  const linkCounts = useMemo(() => {
    const m = new Map<number, number>();
    for (const [id, list] of linksBySurfaceId) m.set(id, list.length);
    return m;
  }, [linksBySurfaceId]);

  // Counts computed over unfiltered list so chips remain meaningful
  const typeCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of localSurfaces) {
      const k = s.surface_type || "unknown";
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [localSurfaces]);
  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of localSurfaces) {
      const k = s.status || "";
      if (!k) continue;
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [localSurfaces]);
  const sourceCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of localSurfaces) {
      const k = s.source_name || "";
      if (!k) continue;
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [localSurfaces]);

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
  const snapshotLimitReached = localSurfaces.length >= SURFACE_RETRY_FETCH_LIMIT;
  const openSurfaceCount = useMemo(
    () => localSurfaces.reduce((count, surface) => count + (surfaceNeedsAction(surface) ? 1 : 0), 0),
    [localSurfaces],
  );

  const selectedLinks = selected ? linksBySurfaceId.get(selected.id) ?? [] : [];

  // Keyboard shortcuts: `/` focuses search, `Esc` blurs / closes drawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea";
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (e.key === "Escape") {
        if (isTyping) {
          searchRef.current?.blur();
        } else if (selected) {
          setSelected(null);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected]);

  return (
    <div className="findings-redesign">
      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search surfaces — target, rationale, source… (try type:api status:open host:foo.com)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
          <div className="toolbar-right">
            <span
              className="surface-ledger-counts"
              aria-label={`${openSurfaceCount} open / ${localSurfaces.length} total`}
            >
              <strong>{openSurfaceCount}</strong> open / <strong>{localSurfaces.length}</strong> total
            </span>
            <span className="meta-text">
              {filteredSurfaces.length} shown
              {linksError ? " · links unavailable" : ""}
              {snapshotLimitReached
                ? " · surface limit reached · results may be incomplete"
                : ""}
            </span>
          </div>
        </div>
        <div className="filter-row">
          <div className="filter-group" aria-label="Surface view">
            <span className="filter-label">View</span>
            <button
              type="button"
              className={`filter-chip ${viewMode === "needs_action" ? "is-active" : ""}`}
              aria-pressed={viewMode === "needs_action"}
              aria-label="Needs action"
              onClick={() => setViewMode("needs_action")}
            >
              Needs action <span className="filter-count">{openSurfaceCount}</span>
            </button>
            <button
              type="button"
              className={`filter-chip ${viewMode === "all" ? "is-active" : ""}`}
              aria-pressed={viewMode === "all"}
              aria-label="All surfaces"
              onClick={() => setViewMode("all")}
            >
              All <span className="filter-count">{localSurfaces.length}</span>
            </button>
          </div>
          {Object.keys(typeCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Type</span>
              {Object.keys(typeCounts)
                .sort((a, b) => typeCounts[b] - typeCounts[a] || a.localeCompare(b))
                .map((t) => (
                  <button
                    key={t}
                    type="button"
                    className={`filter-chip ${typeFilters.has(t) ? "is-active" : ""}`}
                    aria-label={`Filter type ${surfaceStatusLabel(t)}`}
                    aria-pressed={typeFilters.has(t)}
                    onClick={() => toggleChip(typeFilters, setTypeFilters, t)}
                  >
                    {surfaceStatusLabel(t)}
                    <span className="filter-count">{typeCounts[t]}</span>
                  </button>
                ))}
            </div>
          )}
          {Object.keys(statusCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Status</span>
              {Object.keys(statusCounts)
                .sort((a, b) => statusCounts[b] - statusCounts[a] || a.localeCompare(b))
                .map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`filter-chip ${statusFilters.has(s) ? "is-active" : ""}`}
                    aria-label={`Filter status ${surfaceStatusLabel(s)}`}
                    aria-pressed={statusFilters.has(s)}
                    onClick={() => toggleChip(statusFilters, setStatusFilters, s)}
                  >
                    {surfaceStatusLabel(s)}
                    <span className="filter-count">{statusCounts[s]}</span>
                  </button>
                ))}
            </div>
          )}
          {Object.keys(sourceCounts).length > 0 && (
            <label className="filter-group">
              <span className="filter-label">Source</span>
              <select
                className="surface-source-select"
                aria-label="Source"
                value={sourceFilters.values().next().value || ""}
                onChange={(event) => setSourceFilters(event.target.value ? new Set([event.target.value]) : new Set())}
              >
                <option value="">All sources ({Object.keys(sourceCounts).length})</option>
                {Object.keys(sourceCounts)
                  .sort((a, b) => sourceCounts[b] - sourceCounts[a] || a.localeCompare(b))
                  .map((src) => (
                    <option key={src} value={src}>{src} ({sourceCounts[src]})</option>
                  ))}
              </select>
            </label>
          )}
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {/* Surfaces table */}
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surfaces</h2>
          <p className="meta-text">
            {filteredSurfaces.length} surface{filteredSurfaces.length === 1 ? "" : "s"}
            {linksError ? " · links unavailable" : ""}
          </p>
        </div>

        {loadError ? (
          <p className="error-text" role="alert" style={{ padding: "12px 20px" }}>
            Surface ledger unavailable: {loadError}
          </p>
        ) : null}

        {loadError && localSurfaces.length === 0 ? null : localSurfaces.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px" }}>
            No surfaces discovered yet.
          </p>
        ) : (
          <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
            <SurfacesGrid
              rows={filteredSurfaces}
              linkCounts={linkCounts}
              selectedId={selected?.id ?? null}
              onRowOpen={(surface, invoker) => {
                drawerInvokerRef.current = invoker ?? searchRef.current;
                setSelected(surface);
              }}
            />
          </Suspense>
        )}
      </section>

      {/* Detail modal — styled to match the Findings drawer */}
      {selected && (
        <SurfaceDrawer
          engagementKey={engagementKey}
          surface={selected}
          links={selectedLinks}
          findingBySlug={findingBySlug}
          toast={toast}
          onClose={() => setSelected(null)}
          returnFocusRef={drawerInvokerRef}
          resolutionRationale={resolutionRationale}
          setResolutionRationale={setResolutionRationale}
          followupCondition={followupCondition}
          setFollowupCondition={setFollowupCondition}
          pendingResolution={pendingResolution}
          canSubmitResolution={canSubmitResolution}
          resolutionError={resolutionError}
          resolveSurfaceStatus={resolveSurfaceStatus}
        />
      )}
    </div>
  );
}

// ── Surface detail drawer ─────────────────────────────────────────────
// Centred modal styled to match the Findings drawer (reuses .finding-overlay
// + .drawer-panel CSS). Calls useBodyScrollLock so background scroll is
// frozen while open, matching the Findings/Intel DetailModal behavior. The
// existing resolve-status PATCH flow is preserved verbatim (read-only product
// elsewhere; this control already existed — no NEW mutation controls added).
function SurfaceDrawer({
  engagementKey,
  surface,
  links,
  findingBySlug,
  toast,
  onClose,
  returnFocusRef,
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
  links: AssessmentFindingLink[];
  findingBySlug: Map<string, FindingLike>;
  toast: (message: string, type?: "success" | "error" | "info") => void;
  onClose: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
  resolutionRationale: string;
  setResolutionRationale: (v: string) => void;
  followupCondition: string;
  setFollowupCondition: (v: string) => void;
  pendingResolution: string | null;
  canSubmitResolution: boolean;
  resolutionError: string | null;
  resolveSurfaceStatus: (status: SurfacePatchPayload["status"]) => void | Promise<void>;
}) {
  useBodyScrollLock();
  const panelRef = useRef<HTMLElement | null>(null);
  useModalFocus(panelRef, onClose, true, returnFocusRef);
  const [variantLinks, setVariantLinks] = useState<SurfaceRequestVariantLink[]>([]);
  const [variantLinksError, setVariantLinksError] = useState<string | null>(null);
  const rationale = surface.rationale || "";
  const findingHref = (slug: string) =>
    `#/engagements/${encodeURIComponent(engagementKey)}?tab=findings&finding=${encodeURIComponent(slug)}`;
  const httpHref = (requestVariantId: number) =>
    `#/engagements/${encodeURIComponent(engagementKey)}?tab=http&request=${requestVariantId}`;

  useEffect(() => {
    let cancelled = false;
    setVariantLinks([]);
    setVariantLinksError(null);
    listSurfaceRequestVariantLinks(engagementKey, surface.id)
      .then((rows) => {
        if (!cancelled) setVariantLinks(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setVariantLinksError(err instanceof Error ? err.message : "Request-variant links unavailable");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, surface.id]);

  return (
    <div className="finding-overlay" role="presentation" onClick={onClose}>
      <article
        ref={panelRef}
        className="drawer-panel panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="surface-detail-modal-title"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        style={{ maxWidth: "720px", width: "min(92vw, 720px)", maxHeight: "90vh", overflow: "auto" }}
      >
        <div className="drawer-hero">
          <div className="drawer-top">
            <div className="drawer-slug">
              <span>{surface.surface_type || "surface"}</span>
              <button
                type="button"
                className="copy-btn"
                onClick={() => {
                  try {
                    void navigator.clipboard?.writeText(surface.target_descriptor);
                    toast("Copied", "success");
                  } catch {
                    /* best-effort */
                  }
                }}
                title="Copy target"
                aria-label="Copy target descriptor"
              >
                <Copy size={12} />
              </button>
            </div>
            <div className="drawer-nav">
              <button
                type="button"
                className="icon-btn"
                onClick={onClose}
                title="Close (Esc)"
                aria-label="Close surface detail"
              >
                <IconClose />
              </button>
            </div>
          </div>
          <h2 id="surface-detail-modal-title" className="drawer-title">
            {surface.target_descriptor}
          </h2>
          <div className="hero-meta">
            {surface.surface_type && (
              <span className="hero-sev info">{surface.surface_type}</span>
            )}
            <span className={`pill ${surfaceStatusPill(surface.status)}`}>
              {surfaceStatusLabel(surface.status)}
            </span>
            {surface.status === "administratively-closed" && <span className="tag">no coverage</span>}
            {surface.vendor_saas && <span className="tag">vendor SaaS</span>}
            {surface.source_name && <span className="tag">{surface.source_name}</span>}
          </div>
        </div>
        <div className="drawer-body">
          <div className="section">
            <p className="section-title">Metadata</p>
            <div className="kv-grid">
              <KV k="Surface type" v={surface.surface_type} />
              {/* The architecture axis: how the host framework registers this
                  code. Empty on an ordinary web surface, and KV drops empties. */}
              <KV k="Framework registration" v={surface.framework_registration} />
              <KV k="Status" v={surfaceStatusLabel(surface.status)} />
              <KV k="Follow-up condition" v={surface.followup_condition} />
              <KV k="Source" v={surface.source_name} toast={surface.source_name ? toast : undefined} />
              <div className="kv">
                <p className="k">Updated</p>
                <p className="v">{surface.updated_at ? <RelTime iso={surface.updated_at} /> : "—"}</p>
              </div>
              <KV k="Vendor SaaS" v={surface.vendor_saas == null ? "" : surface.vendor_saas ? "yes" : "no"} />
              <KV
                k="Evidence ref"
                v={surface.evidence_ref}
                mono
                toast={surface.evidence_ref ? toast : undefined}
              />
            </div>
          </div>

          {/* Rationale: markdown when it reads like prose, plain otherwise. */}
          {rationale && looksLikeProse(rationale) ? (
            <ProseSection title="Rationale" text={rationale} mode="rendered" toast={toast} kind="callout" />
          ) : rationale ? (
            <div className="callout">
              <SectionHead title="Rationale" copyText={rationale} toast={toast} />
              <p>{rationale}</p>
            </div>
          ) : null}

          <div className="section">
            <p className="section-title">Coverage lifecycle</p>
            <p className="meta-text" style={{ margin: "0 0 8px" }}>
              Record the evidence-backed state. A rationale is required for every transition and is appended to the audit trail.
            </p>
            <textarea
              aria-label="Transition rationale"
              rows={2}
              placeholder="Required rationale appended to the audit trail"
              value={resolutionRationale}
              onChange={(e) => setResolutionRationale(e.target.value)}
              maxLength={4096}
              style={{
                width: "100%",
                boxSizing: "border-box",
                fontSize: "0.85rem",
                padding: "6px 8px",
                marginBottom: "8px",
              }}
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
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
              {(["covered", "partially-covered", "deferred", "not_applicable"] as const).map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`filter-chip ${pendingResolution === s ? "is-active" : ""}`}
                  disabled={pendingResolution != null || !canSubmitResolution}
                  title={!canSubmitResolution ? "Enter rationale to change status" : undefined}
                  aria-label={`Mark ${surfaceStatusLabel(s)}`}
                  onClick={() => void resolveSurfaceStatus(s)}
                >
                  {pendingResolution === s ? "Saving…" : `Mark ${surfaceStatusLabel(s)}`}
                </button>
              ))}
            </div>
            {resolutionError && (
              <p role="alert" className="meta-text" style={{ color: "var(--c-error, #c33)", margin: "8px 0 0" }}>
                {resolutionError}
              </p>
            )}
          </div>

          <div className="section surface-admin-closure">
            <p className="section-title">Administrative closure</p>
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
          </div>

          <div className="section">
            <p className="section-title">
              Request variants <span className="count">{variantLinks.length}</span>
            </p>
            {variantLinksError ? (
              <p className="meta-text" role="alert">Request-variant links unavailable: {variantLinksError}</p>
            ) : variantLinks.length === 0 ? (
              <p className="empty" style={{ padding: "12px 0" }}>No durable request-variant links.</p>
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
                      <span className="link-sub">{surfaceStatusLabel(link.relation || "related")}</span>
                      {link.evidence_ref && <span className="link-notes mono">{link.evidence_ref}</span>}
                    </span>
                    <span className="link-go">›</span>
                  </a>
                ))}
              </div>
            )}
          </div>

          <div className="section">
            <p className="section-title">
              Linked findings <span className="count">{links.length}</span>
            </p>
            {links.length === 0 ? (
              <p className="empty" style={{ padding: "12px 0" }}>
                No findings linked to this surface yet.
              </p>
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
                      <span className="link-kind">{(link.link_kind || "").replace(/_/g, " ")}</span>
                      <span>
                        <span className="link-title">{finding?.title || link.finding_slug}</span>
                        <br />
                        <span className="link-sub">
                          {link.finding_slug}
                          {severity ? ` · ${severity}` : ""}
                          {link.notes ? ` · ${link.notes}` : ""}
                        </span>
                      </span>
                      {severity && (
                        <span className="sev-dot" style={{ background: sevDotColor(severity) }} />
                      )}
                      <span className="link-go">›</span>
                    </a>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </article>
    </div>
  );
}
