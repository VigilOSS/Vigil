// ── HttpTab ───────────────────────────────────────────────────────────
// Read-only view over the engagement's HTTP traffic. One grid row per
// REQUEST VARIANT (assessment_request_variants); the per-variant detail
// drawer lists the request_observations recorded against that variant.
//
// Data is fetched once at the tab level (variants + observations) and
// filtered client-side via method chips + a text search on path/host —
// mirroring CommandsTab/SurfacesTab's React-state filter pipeline (NOT
// ag-grid column filters). The grid itself is lazy-loaded so ag-grid lands
// in the shared code-split chunk and never bloats the main entry bundle.

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
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
  listRequestObservations,
  listRequestVariants,
  setCapturePolicy,
} from "../lib/api";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { useToast } from "../contexts/ToastContext";
import { CodeBlock, RelTime } from "./formatting";
import { KV, ProseSection } from "./drawer/DrawerKit";
import { TableSkeleton } from "./Skeletons";

const HttpGrid = lazy(() => import("./HttpGrid"));
const HttpFlowsGrid = lazy(() => import("./HttpFlowsGrid"));

// Compact human byte size — shared with the flows grid / drawer.
function fmtBytes(n: number | null | undefined): string {
  if (n == null || n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb < 10 ? kb.toFixed(1) : Math.round(kb)} KB`;
  const mb = kb / 1024;
  return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`;
}

// Which sub-view of the HTTP tab is active: the legacy request-variant list
// or the Phase-5 canonical full-flow store.
type HttpView = "variants" | "flows";

// ── HTTP method colors ────────────────────────────────────────────────
// Mapped onto the Vigil palette. The class drives the colored .method-badge in
// both the grid and the drawer hero — see app.css "HTTP method colors".
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

// Map an HTTP status code to a status-class bucket (2xx/3xx/4xx/5xx).
export function statusClass(status: number | null | undefined): string {
  if (status == null) return "";
  const bucket = Math.floor(status / 100);
  if (bucket === 2) return "s-2xx";
  if (bucket === 3) return "s-3xx";
  if (bucket === 4) return "s-4xx";
  if (bucket >= 5) return "s-5xx";
  return "s-1xx";
}

// ── Schema pretty-print ───────────────────────────────────────────────
// The *_schema_json columns are JSON-encoded strings. Parse + re-stringify
// with 2-space indent for the drawer; fall back to the raw string when it
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

type HttpTabProps = {
  engagementKey: string;
  initialRequestVariantId?: number;
  // Bumped by EngagementPage after every successful page refresh (including
  // WebSocket-driven ones). A change triggers a silent background reload so
  // this tab stays live alongside the others without flickering to a spinner.
  refreshVersion?: number;
};

const INITIAL_FETCH_LIMIT = 5000;

export function HttpTab({ engagementKey, refreshVersion, initialRequestVariantId }: HttpTabProps) {
  const { toast } = useToast();
  const [variants, setVariants] = useState<RequestVariant[]>([]);
  const [observations, setObservations] = useState<RequestObservation[]>([]);
  const [observationsLoaded, setObservationsLoaded] = useState(false);
  const [observationError, setObservationError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [methodFilters, setMethodFilters] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<RequestVariant | null>(null);
  const [view, setView] = useState<HttpView>("variants");

  const searchRef = useRef<HTMLInputElement | null>(null);
  const drawerInvokerRef = useRef<HTMLElement | null>(null);
  const consumedRequestVariantRef = useRef<number | undefined>(undefined);
  const closeRequest = useCallback(() => {
    setSelected(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "http" }));
  }, [engagementKey]);

  // Fetch variants + observations together. Both are read-only and the
  // observations are grouped to variants client-side, so a single fetch
  // covers the whole tab. `showSpinner=false` is used for background
  // refreshes (WS tick / visibility) so the list doesn't flicker.
  const reloadInFlightRef = useRef(false);
  const reloadQueuedRef = useRef<{ engagementKey: string; showSpinner: boolean } | null>(null);
  const activeEngagementKeyRef = useRef(engagementKey);
  activeEngagementKeyRef.current = engagementKey;
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) {
        const queued = reloadQueuedRef.current;
        reloadQueuedRef.current = {
          engagementKey,
          showSpinner: showSpinner || queued?.showSpinner === true,
        };
        return;
      }
      reloadInFlightRef.current = true;
      try {
        let next: { engagementKey: string; showSpinner: boolean } | null = {
          engagementKey,
          showSpinner,
        };
        while (next) {
          const request = next;
          reloadQueuedRef.current = null;
          if (request.showSpinner && activeEngagementKeyRef.current === request.engagementKey) {
            setLoading(true);
          }
          try {
            const [variantResult, observationResult] = await Promise.allSettled([
              listRequestVariants(request.engagementKey, { limit: INITIAL_FETCH_LIMIT }),
              listRequestObservations(request.engagementKey, { limit: INITIAL_FETCH_LIMIT }),
            ]);
            if (activeEngagementKeyRef.current === request.engagementKey) {
              if (variantResult.status === "rejected") throw variantResult.reason;
              setVariants(variantResult.value);
              setLoadError(null);
              if (observationResult.status === "fulfilled") {
                setObservations(observationResult.value);
                setObservationsLoaded(true);
                setObservationError(null);
              } else {
                setObservationError(
                  observationResult.reason instanceof Error
                    ? observationResult.reason.message
                    : "Failed to load request observations",
                );
              }
            }
          } catch (err) {
            if (
              activeEngagementKeyRef.current === request.engagementKey
              && request.showSpinner
            ) {
              setVariants([]);
              setObservations([]);
              setObservationsLoaded(false);
            }
            if (activeEngagementKeyRef.current === request.engagementKey) {
              setLoadError(err instanceof Error ? err.message : "Failed to load HTTP traffic");
            }
          } finally {
            if (
              request.showSpinner
              && activeEngagementKeyRef.current === request.engagementKey
            ) {
              setLoading(false);
            }
          }
          next = reloadQueuedRef.current;
        }
      } finally {
        reloadInFlightRef.current = false;
      }
    },
    [engagementKey],
  );

  useEffect(() => {
    void reload(true);
  }, [reload]);

  // Silent background reload whenever the parent's refresh version bumps
  // (poll tick / WebSocket event). Skip the very first render so it doesn't
  // double-fetch alongside the mount load above. matches how other tabs ride
  // the page-level WS refresh.
  const didInitialMountRef = useRef(false);
  useEffect(() => {
    if (!didInitialMountRef.current) {
      didInitialMountRef.current = true;
      return;
    }
    void reload(false);
  }, [refreshVersion, reload]);

  // Background refresh when visibility returns so the tab stays live alongside
  // the EngagementPage WS refresh (which re-mounts/keeps this tab and the
  // parent throttle owns the cadence). A light visibility refresh matches
  // CommandsTab's self-owned refresh approach.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void reload(false);
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [reload]);

  // Group observations by request_variant_id (fetched once at tab level).
  const observationsByVariant = useMemo(() => {
    const m = new Map<number, RequestObservation[]>();
    for (const o of observations) {
      const list = m.get(o.request_variant_id) ?? [];
      list.push(o);
      m.set(o.request_variant_id, list);
    }
    // Newest observation first within each variant.
    for (const list of m.values()) {
      list.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    }
    return m;
  }, [observations]);

  const observationCounts = useMemo(() => {
    const m = new Map<number, number>();
    for (const [id, list] of observationsByVariant) m.set(id, list.length);
    return m;
  }, [observationsByVariant]);

  // Resolve exact cross-workspace links only after the bounded variant ledger
  // has loaded. Consume each id once so closing the drawer does not reopen it.
  useEffect(() => {
    if (!initialRequestVariantId) {
      if (consumedRequestVariantRef.current !== undefined) setSelected(null);
      consumedRequestVariantRef.current = undefined;
      return;
    }
    if (loading) return;
    if (consumedRequestVariantRef.current === initialRequestVariantId) return;
    const variant = variants.find((candidate) => candidate.id === initialRequestVariantId);
    if (variant) {
      consumedRequestVariantRef.current = initialRequestVariantId;
      setView("variants");
      setSelected(variant);
    } else {
      consumedRequestVariantRef.current = undefined;
      setSelected(null);
    }
  }, [initialRequestVariantId, loading, variants]);

  // Method counts over the unfiltered set so chips stay meaningful.
  const methodCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const v of variants) {
      const k = (v.method || "GET").toUpperCase();
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [variants]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return variants.filter((v) => {
      if (methodFilters.size && !methodFilters.has((v.method || "GET").toUpperCase()))
        return false;
      if (q) {
        const corpus = [
          v.normalized_path,
          v.host,
          v.canonical_url,
          v.path_template,
          v.content_type_family,
          v.auth_context,
          v.discovery_source,
        ]
          .filter(Boolean)
          .join(" \n ")
          .toLowerCase();
        if (!corpus.includes(q)) return false;
      }
      return true;
    });
  }, [variants, methodFilters, query]);

  // Keep selection valid if it drops out of the variant set on refresh.
  useEffect(() => {
    if (selected && !variants.some((v) => v.id === selected.id)) {
      setSelected(null);
    }
  }, [variants, selected]);

  const toggleMethod = (m: string) => {
    setMethodFilters((cur) => {
      const next = new Set(cur);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });
  };

  const clearAll = () => {
    setQuery("");
    setMethodFilters(new Set());
  };

  const activeFilterCount = methodFilters.size + (query ? 1 : 0);

  // `/` focuses search, Esc blurs / closes the drawer. Only active in the
  // variants view — the flows view (HttpFlowsView) owns its own shortcuts.
  useEffect(() => {
    if (view !== "variants") return;
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
        if (isTyping) searchRef.current?.blur();
        else if (selected) closeRequest();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected, view, closeRequest]);

  const variantLimitReached = variants.length >= INITIAL_FETCH_LIMIT;
  const observationLimitReached = observations.length >= INITIAL_FETCH_LIMIT;

  return (
    <div className="findings-redesign">
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
        <HttpViewToggle view={view} onChange={setView} />
      </div>
      {view === "flows" ? (
        <HttpFlowsView
          engagementKey={engagementKey}
          refreshVersion={refreshVersion}
          toast={toast}
        />
      ) : (
        <>
      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search endpoint inventory — path, host, URL…"
              aria-label="Search endpoint inventory"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                aria-label="Clear endpoint search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
          <div className="toolbar-right">
            <span className="meta-text">
              {filtered.length} of {variants.length} variant
              {variants.length === 1 ? "" : "s"}
              {loading && " · loading…"}
              {variantLimitReached && " · variant limit reached · results may be incomplete"}
            </span>
          </div>
        </div>
        <div className="filter-row">
          {Object.keys(methodCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Method</span>
              {Object.keys(methodCounts)
                .sort((a, b) => methodCounts[b] - methodCounts[a] || a.localeCompare(b))
                .map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={`filter-chip method-chip ${methodClass(m)} ${
                      methodFilters.has(m) ? "is-active" : ""
                    }`}
                    aria-pressed={methodFilters.has(m)}
                    onClick={() => toggleMethod(m)}
                  >
                    <span className={`sev-dot method-dot ${methodClass(m)}`} />
                    {m}
                    <span className="filter-count">{methodCounts[m]}</span>
                  </button>
                ))}
            </div>
          )}
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
          <p className="error-text" role="alert" style={{ textAlign: "left" }}>
            {loadError}
          </p>
        </div>
      )}
      {!loading && initialRequestVariantId != null && !variants.some((variant) => variant.id === initialRequestVariantId) && <p className="meta-text" role="status">Request #{initialRequestVariantId} cannot be resolved from the loaded endpoint inventory. The bounded snapshot may be incomplete; refresh or inspect the full ledger.</p>}
      {observationError && (
        <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
          <p className="error-text" role="alert" style={{ textAlign: "left" }}>
            Request observations unavailable: {observationError}
            {observationsLoaded ? " (showing the last loaded observation history)" : ""}
          </p>
        </div>
      )}

      {/* Variants table */}
      <section className="panel">
        <div className="panel-header">
          <h2>Endpoint inventory</h2>
          <p className="meta-text">
            {filtered.length} variant{filtered.length === 1 ? "" : "s"}
            {observationsLoaded
              ? ` · ${observations.length} observations`
              : " · observations unavailable"}
            {observationLimitReached
              ? " · observation limit reached · results may be incomplete"
              : ""}
          </p>
        </div>

        {loading ? (
          <TableSkeleton rows={8} showHeader={false} />
        ) : loadError && variants.length === 0 ? null : variants.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px", color: "var(--muted)" }}>
            No endpoint inventory recorded yet.
          </p>
        ) : (
          <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
            <HttpGrid
              rows={filtered}
              observationCounts={observationCounts}
              selectedId={selected?.id ?? null}
              onRowOpen={(variant, invoker) => {
                drawerInvokerRef.current = invoker ?? searchRef.current;
                setSelected(variant);
                writeWorkspaceHash(engagementHref(engagementKey, { tab: "http", request: variant.id }));
              }}
            />
          </Suspense>
        )}
      </section>

      {selected && (
        <HttpDrawer
          variant={selected}
          observations={observationsByVariant.get(selected.id) ?? []}
          observationsLoaded={observationsLoaded}
          observationError={observationError}
          toast={toast}
          onClose={closeRequest}
          returnFocusRef={drawerInvokerRef}
        />
      )}

      <div className="findings-shortcuts">
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>Esc</code> close detail
        </span>
      </div>
        </>
      )}
    </div>
  );
}

// ── View toggle ───────────────────────────────────────────────────────
// Segmented control (reuses the Findings .view-toggle styling) switching
// between the legacy request-variant list and the Phase-5 flow store.
function HttpViewToggle({
  view,
  onChange,
}: {
  view: HttpView;
  onChange: (v: HttpView) => void;
}) {
  return (
    <div className="view-toggle" role="group" aria-label="HTTP view">
      <button
        type="button"
        className={view === "variants" ? "is-active" : ""}
        onClick={() => onChange("variants")}
        aria-pressed={view === "variants"}
      >
        Endpoint inventory
      </button>
      <button
        type="button"
        className={view === "flows" ? "is-active" : ""}
        onClick={() => onChange("flows")}
        aria-pressed={view === "flows"}
      >
        Captured exchanges
      </button>
    </div>
  );
}

// ── Variant detail drawer ─────────────────────────────────────────────
// Centred modal styled to match the Surface drawer (.finding-overlay +
// .drawer-panel). Hero = method badge + path; KV grid of the variant
// metadata; the parsed schema JSON blocks; and the Observations section
// listing the request_observations recorded for this variant.
function HttpDrawer({
  variant,
  observations,
  observationsLoaded,
  observationError,
  toast,
  onClose,
  returnFocusRef,
}: {
  variant: RequestVariant;
  observations: RequestObservation[];
  observationsLoaded: boolean;
  observationError: string | null;
  toast: (message: string, type?: "success" | "error" | "info") => void;
  onClose: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
}) {
  useBodyScrollLock();
  const panelRef = useRef<HTMLElement | null>(null);
  useModalFocus(panelRef, onClose, true, returnFocusRef);
  const method = (variant.method || "GET").toUpperCase();

  const schemaBlocks: { label: string; text: string }[] = [];
  const schemaFields: [string, string | undefined][] = [
    ["Query schema", variant.query_schema_json],
    ["Body schema", variant.body_schema_json],
    ["Path schema", variant.path_schema_json],
    ["Cookie schema", variant.cookie_schema_json],
    ["Header schema", variant.header_schema_json],
  ];
  for (const [label, raw] of schemaFields) {
    const pretty = prettyJson(raw);
    if (pretty) schemaBlocks.push({ label, text: pretty });
  }

  return (
    <div className="finding-overlay" role="presentation" onClick={onClose}>
      <article
        ref={panelRef}
        className="drawer-panel panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="http-detail-modal-title"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        style={{ maxWidth: "760px", width: "min(94vw, 760px)", maxHeight: "90vh", overflow: "auto" }}
      >
        <div className="drawer-hero">
          <div className="drawer-top">
            <div className="drawer-slug">
              <span className={`method-badge ${methodClass(method)}`}>{method}</span>
            </div>
            <div className="drawer-nav">
              <button type="button" className="icon-btn" onClick={onClose} title="Close (Esc)">
                <IconClose />
              </button>
            </div>
          </div>
          <h2 id="http-detail-modal-title" className="drawer-title mono">
            {variant.normalized_path || "/"}
          </h2>
          <div className="hero-meta">
            <span className="tag">{variant.host}</span>
            {variant.content_type_family && variant.content_type_family !== "unknown" && (
              <span className="tag">{variant.content_type_family}</span>
            )}
            {variant.auth_context && <span className="tag">{variant.auth_context}</span>}
            {variant.discovery_source && <span className="tag">{variant.discovery_source}</span>}
          </div>
        </div>

        <div className="drawer-body">
          <div className="section">
            <p className="section-title">Metadata</p>
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
              <div className="kv">
                <p className="k">First seen</p>
                <p className="v">
                  {variant.first_seen_at ? <RelTime iso={variant.first_seen_at} /> : "—"}
                </p>
              </div>
              <div className="kv">
                <p className="k">Last seen</p>
                <p className="v">
                  {variant.last_seen_at ? <RelTime iso={variant.last_seen_at} /> : "—"}
                </p>
              </div>
            </div>
          </div>

          {variant.notes && variant.notes.trim() && (
            <ProseSection title="Notes" text={variant.notes} mode="rendered" toast={toast} kind="callout" />
          )}

          {schemaBlocks.length > 0 && (
            <div className="section">
              <p className="section-title">Request schema</p>
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
            </div>
          )}

          <div className="section">
            <p className="section-title">
              Observations <span className="count">{observations.length}</span>
            </p>
            {observationError && !observationsLoaded ? (
              <p className="error-text" role="alert" style={{ padding: "12px 0" }}>
                Observation history unavailable: {observationError}
              </p>
            ) : observations.length === 0 ? (
              <p className="empty" style={{ padding: "12px 0" }}>
                No observations recorded for this variant yet.
              </p>
            ) : (
              <div className="http-obs-list">
                {observations.map((o) => {
                  const payload = prettyJson(o.raw_payload);
                  return (
                    <div key={o.id} className="http-obs-card">
                      <div className="http-obs-head">
                        <span className="http-obs-url mono">{o.observed_url}</span>
                        {o.response_status != null && (
                          <span className={`status-badge ${statusClass(o.response_status)}`}>
                            {o.response_status}
                          </span>
                        )}
                      </div>
                      <div className="http-obs-meta">
                        {o.source_name && <span className="tag">{o.source_name}</span>}
                        {o.evidence_ref && <span className="tag">{o.evidence_ref}</span>}
                        <RelTime iso={o.created_at} />
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
          </div>
        </div>
      </article>
    </div>
  );
}

// ── Flows view (Phase-5 canonical full-flow store) ────────────────────
// A second sub-view of the HTTP tab rendering assessment_http_flows. Unlike
// the variants view (fetch-once + filter-in-React), the filter set here is
// pushed to the backend as query params so large corpora filter server-side.
// An unfiltered snapshot (`allFlows`) drives the facet chips/dropdowns +
// counts; the grid renders `results` (the server-filtered slice, or the full
// snapshot when no filter is active).
type ToastFn = (message: string, type?: "success" | "error" | "info") => void;

const FLOWS_FETCH_LIMIT = 5000;

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

function HttpFlowsView({
  engagementKey,
  refreshVersion,
  toast,
}: {
  engagementKey: string;
  refreshVersion?: number;
  toast: ToastFn;
}) {
  const [allFlows, setAllFlows] = useState<HttpFlow[]>([]);
  const [results, setResults] = useState<HttpFlow[]>([]);
  const [loading, setLoading] = useState(true);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Server-side filter axes (names align 1:1 with the backend query params).
  const [host, setHost] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState(""); // exact response_status; "" = any
  const [ctype, setCtype] = useState("");
  const [auth, setAuth] = useState("");
  const [truncated, setTruncated] = useState<"" | "true" | "false">("");
  const [query, setQuery] = useState("");

  const [selected, setSelected] = useState<HttpFlow | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const drawerInvokerRef = useRef<HTMLElement | null>(null);

  // ── Unfiltered facet snapshot ────
  const reloadInFlightRef = useRef(false);
  const reloadQueuedRef = useRef<{ engagementKey: string; showSpinner: boolean } | null>(null);
  const activeEngagementKeyRef = useRef(engagementKey);
  activeEngagementKeyRef.current = engagementKey;
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) {
        const queued = reloadQueuedRef.current;
        reloadQueuedRef.current = {
          engagementKey,
          showSpinner: showSpinner || queued?.showSpinner === true,
        };
        return;
      }
      reloadInFlightRef.current = true;
      try {
        let next: { engagementKey: string; showSpinner: boolean } | null = {
          engagementKey,
          showSpinner,
        };
        while (next) {
          const request = next;
          reloadQueuedRef.current = null;
          if (request.showSpinner && activeEngagementKeyRef.current === request.engagementKey) {
            setLoading(true);
          }
          try {
            const items = await listHttpFlows(request.engagementKey, {
              limit: FLOWS_FETCH_LIMIT,
            });
            if (activeEngagementKeyRef.current === request.engagementKey) {
              setAllFlows(items);
              setLoadError(null);
            }
          } catch (err) {
            if (
              request.showSpinner
              && activeEngagementKeyRef.current === request.engagementKey
            ) {
              setAllFlows([]);
            }
            if (activeEngagementKeyRef.current === request.engagementKey) {
              setLoadError(err instanceof Error ? err.message : "Failed to load HTTP flows");
            }
          } finally {
            if (
              request.showSpinner
              && activeEngagementKeyRef.current === request.engagementKey
            ) {
              setLoading(false);
            }
          }
          next = reloadQueuedRef.current;
        }
      } finally {
        reloadInFlightRef.current = false;
      }
    },
    [engagementKey],
  );

  useEffect(() => {
    void reload(true);
  }, [reload]);

  const didMountRef = useRef(false);
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    void reload(false);
  }, [refreshVersion, reload]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void reload(false);
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [reload]);

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

  const filtersActive = Object.keys(serverFilters).length > 0;

  // ── Server-side filtered results (debounced so typing `q` doesn't spam
  // the backend). When nothing is filtered we reuse the snapshot directly. ──
  useEffect(() => {
    if (!filtersActive) {
      setResults(allFlows);
      setResultsLoading(false);
      return;
    }
    let cancelled = false;
    setResultsLoading(true);
    const handle = window.setTimeout(() => {
      listHttpFlows(engagementKey, { ...serverFilters, limit: FLOWS_FETCH_LIMIT })
        .then((items) => {
          if (!cancelled) {
            setResults(items);
            setLoadError(null);
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setResults([]);
            setLoadError(err instanceof Error ? err.message : "Failed to filter HTTP flows");
          }
        })
        .finally(() => {
          if (!cancelled) setResultsLoading(false);
        });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(handle);
    };
  }, [engagementKey, filtersActive, serverFilters, allFlows]);

  // Drop the selection only when the flow leaves the full set (not merely the
  // filtered view) so the drawer survives a filter change.
  useEffect(() => {
    if (selected && !allFlows.some((f) => f.flow_uid === selected.flow_uid)) {
      setSelected(null);
    }
  }, [allFlows, selected]);

  // ── Facets from the unfiltered snapshot ────
  const methodCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of allFlows) {
      const k = (f.method || "GET").toUpperCase();
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [allFlows]);

  const hostOptions = useMemo(
    () => Array.from(new Set(allFlows.map((f) => f.host).filter(Boolean))).sort(),
    [allFlows],
  );
  const ctypeOptions = useMemo(
    () => Array.from(new Set(allFlows.map((f) => f.content_type_family).filter(Boolean))).sort(),
    [allFlows],
  );
  const authOptions = useMemo(
    () => Array.from(new Set(allFlows.map((f) => f.auth_context).filter(Boolean))).sort(),
    [allFlows],
  );
  const statusOptions = useMemo(
    () =>
      Array.from(
        new Set(
          allFlows
            .map((f) => f.response_status)
            .filter((s): s is number => s != null),
        ),
      ).sort((a, b) => a - b),
    [allFlows],
  );

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

  const toggleMethod = (m: string) => setMethod((cur) => (cur === m ? "" : m));

  // `/` focuses search, Esc blurs / closes the drawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea" || tag === "select";
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (e.key === "Escape") {
        if (isTyping) (target as HTMLElement).blur();
        else if (selected) setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected]);

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

  const snapshotLimitReached = allFlows.length >= FLOWS_FETCH_LIMIT;

  return (
    <>
      <CapturePolicyControl engagementKey={engagementKey} toast={toast} />

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
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
          <div className="toolbar-right">
            <span className="meta-text">
              {results.length} of {allFlows.length} flow
              {allFlows.length === 1 ? "" : "s"}
              {(loading || resultsLoading) && " · loading…"}
              {snapshotLimitReached && " · flow limit reached · results may be incomplete"}
            </span>
            <button type="button" className="qa-btn" onClick={onExportHar}>
              Export HAR
            </button>
          </div>
        </div>

        <div className="filter-row">
          {Object.keys(methodCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Method</span>
              {Object.keys(methodCounts)
                .sort((a, b) => methodCounts[b] - methodCounts[a] || a.localeCompare(b))
                .map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={`filter-chip method-chip ${methodClass(m)} ${
                      method === m ? "is-active" : ""
                    }`}
                    aria-pressed={method === m}
                    onClick={() => toggleMethod(m)}
                  >
                    <span className={`sev-dot method-dot ${methodClass(m)}`} />
                    {m}
                    <span className="filter-count">{methodCounts[m]}</span>
                  </button>
                ))}
            </div>
          )}

          {hostOptions.length > 0 && (
            <div className="filter-select-group">
              <span className="filter-label">Host</span>
              <select
                className="filter-select"
                aria-label="Filter captured exchanges by host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              >
                <option value="">All hosts</option>
                {hostOptions.map((h) => (
                  <option key={h} value={h}>
                    {h}
                  </option>
                ))}
              </select>
            </div>
          )}

          {statusOptions.length > 0 && (
            <div className="filter-select-group">
              <span className="filter-label">Status</span>
              <select
                className="filter-select"
                aria-label="Filter captured exchanges by status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                <option value="">Any</option>
                {statusOptions.map((s) => (
                  <option key={s} value={String(s)}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
          )}

          {ctypeOptions.length > 0 && (
            <div className="filter-select-group">
              <span className="filter-label">Type</span>
              <select
                className="filter-select"
                aria-label="Filter captured exchanges by content type"
                value={ctype}
                onChange={(e) => setCtype(e.target.value)}
              >
                <option value="">All types</option>
                {ctypeOptions.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          )}

          {authOptions.length > 0 && (
            <div className="filter-select-group">
              <span className="filter-label">Auth</span>
              <select
                className="filter-select"
                aria-label="Filter captured exchanges by authentication context"
                value={auth}
                onChange={(e) => setAuth(e.target.value)}
              >
                <option value="">All</option>
                {authOptions.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="filter-select-group">
            <span className="filter-label">Body</span>
            <select
              className="filter-select"
              aria-label="Filter captured exchanges by body truncation"
              value={truncated}
              onChange={(e) => setTruncated(e.target.value as "" | "true" | "false")}
              title="Filter by body-truncation state"
            >
              <option value="">Any</option>
              <option value="true">Truncated ({truncatedCount})</option>
              <option value="false">Complete</option>
            </select>
          </div>

          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
          <p className="error-text" role="alert" style={{ textAlign: "left" }}>
            {loadError}
          </p>
        </div>
      )}

      {/* Flows table */}
      <section className="panel">
        <div className="panel-header">
          <h2>Captured exchanges</h2>
          <p className="meta-text">
            {results.length} flow{results.length === 1 ? "" : "s"}
            {truncatedCount ? ` · ${truncatedCount} truncated` : ""}
          </p>
        </div>

        {loading ? (
          <TableSkeleton rows={8} showHeader={false} />
        ) : loadError && allFlows.length === 0 ? null : allFlows.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px", color: "var(--muted)" }}>
            No full HTTP exchanges captured yet. Enable full-flow capture above and route
            future traffic through the Vigil proxy to populate this view.
          </p>
        ) : (
          <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
            <HttpFlowsGrid
              rows={results}
              selectedUid={selected?.flow_uid ?? null}
              onRowOpen={(flow, invoker) => {
                drawerInvokerRef.current = invoker ?? searchRef.current;
                setSelected(flow);
              }}
            />
          </Suspense>
        )}
      </section>

      {selected && (
        <FlowDrawer
          engagementKey={engagementKey}
          flow={selected}
          toast={toast}
          onClose={() => setSelected(null)}
          returnFocusRef={drawerInvokerRef}
        />
      )}

      <div className="findings-shortcuts">
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>Esc</code> close detail
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
        <span className="meta-text">Loading capture policy…</span>
      </div>
    );
  }
  if (!policy) {
    return (
      <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
        <p className="empty" style={{ textAlign: "left" }}>
          {error ?? "Capture policy unavailable."}
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
          <span
            className={`pill ${enabled ? "pill-reported" : "pill-unreviewed"}`}
            role="status"
          >
            Full-flow capture {enabled ? "ON" : "OFF"}
          </span>
          <span className="meta-text">
            Request bodies {policy.capture_request_bodies ? "ON" : "OFF"} · Response bodies {policy.capture_response_bodies ? "ON" : "OFF"} · {fmtBytes(policy.max_body_bytes)} cap
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

// ── Flow detail drawer ────────────────────────────────────────────────
// Centred modal (same .finding-overlay + .drawer-panel shell as HttpDrawer)
// showing the selected flow's request/response metadata, routing-integrity
// indicators (host_mismatch), body metadata + truncation flags, and the
// captured header maps. Raw body bytes are engagement-local artifacts, not
// inlined here — the operator materialises them via Export HAR. On open we
// re-hydrate from GET /http-flows/{flow_uid} for the canonical row.
function FlowDrawer({
  engagementKey,
  flow,
  toast,
  onClose,
  returnFocusRef,
}: {
  engagementKey: string;
  flow: HttpFlow;
  toast: ToastFn;
  onClose: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
}) {
  useBodyScrollLock();
  const panelRef = useRef<HTMLElement | null>(null);
  useModalFocus(panelRef, onClose, true, returnFocusRef);
  const [row, setRow] = useState<HttpFlow>(flow);
  useEffect(() => {
    setRow(flow);
  }, [flow]);
  useEffect(() => {
    let cancelled = false;
    if (!flow.flow_uid) return;
    getHttpFlow(engagementKey, flow.flow_uid)
      .then((full) => {
        if (!cancelled) setRow(full);
      })
      .catch(() => {
        // Keep the list row on failure — it already carries the full shape.
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, flow.flow_uid]);

  const method = (row.method || "GET").toUpperCase();
  const reqHeaders = row.request_headers && Object.keys(row.request_headers).length > 0
    ? JSON.stringify(row.request_headers, null, 2)
    : null;
  const respHeaders = row.response_headers && Object.keys(row.response_headers).length > 0
    ? JSON.stringify(row.response_headers, null, 2)
    : null;

  return (
    <div className="finding-overlay" role="presentation" onClick={onClose}>
      <article
        ref={panelRef}
        className="drawer-panel panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="http-flow-modal-title"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        style={{ maxWidth: "820px", width: "min(94vw, 820px)", maxHeight: "90vh", overflow: "auto" }}
      >
        <div className="drawer-hero">
          <div className="drawer-top">
            <div className="drawer-slug">
              <span className={`method-badge ${methodClass(method)}`}>{method}</span>
              {row.response_status != null && (
                <span className={`status-badge ${statusClass(row.response_status)}`}>
                  {row.response_status}
                </span>
              )}
            </div>
            <div className="drawer-nav">
              <button type="button" className="icon-btn" onClick={onClose} title="Close (Esc)">
                <IconClose />
              </button>
            </div>
          </div>
          <h2 id="http-flow-modal-title" className="drawer-title mono">
            {row.path || row.url || "/"}
          </h2>
          <div className="hero-meta">
            {row.host && <span className="tag">{row.host}</span>}
            {row.content_type_family && row.content_type_family !== "unknown" && (
              <span className="tag">{row.content_type_family}</span>
            )}
            {row.auth_context && <span className="tag">{row.auth_context}</span>}
            {row.request_variant_id != null && (
              <a className="tag" href={engagementHref(engagementKey, { tab: "http", request: row.request_variant_id })}>Request variant #{row.request_variant_id}</a>
            )}
            {row.host_mismatch && (
              <span className="tag warning" title="URL authority / Host header / SNI disagree">
                host mismatch
              </span>
            )}
          </div>
        </div>

        <div className="drawer-body">
          <div className="section">
            <p className="section-title">Evidence</p>
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
          </div>

          <div className="section">
            <p className="section-title">Metadata</p>
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
              <div className="kv">
                <p className="k">Started</p>
                <p className="v">{row.started_at ? <RelTime iso={row.started_at} /> : "—"}</p>
              </div>
              <div className="kv">
                <p className="k">Captured</p>
                <p className="v">{row.created_at ? <RelTime iso={row.created_at} /> : "—"}</p>
              </div>
            </div>
          </div>

          <div className="section">
            <p className="section-title">Routing integrity</p>
            <div className="kv-grid">
              <KV k="URL authority" v={row.url_authority} mono />
              <KV k="Host header" v={row.host_header} mono />
              <KV k="SNI" v={row.sni} mono />
              <div className="kv">
                <p className="k">Host mismatch</p>
                <p className="v" style={{ color: row.host_mismatch ? "var(--warn)" : undefined }}>
                  {row.host_mismatch ? "yes" : "no"}
                </p>
              </div>
            </div>
          </div>

          <div className="section">
            <p className="section-title">Bodies</p>
            <p className="meta-text" style={{ margin: "0 0 8px" }}>
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
          </div>

          {(reqHeaders || respHeaders) && (
            <div className="section">
              <p className="section-title">Headers</p>
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
            </div>
          )}
        </div>
      </article>
    </div>
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
        <KV k="Size" v={fmtBytes(bytes)} />
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
