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

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { RequestObservation, RequestVariant } from "../lib/api";
import { listRequestObservations, listRequestVariants } from "../lib/api";
import { useBodyScrollLock } from "../lib/modalScrollLock";
import { useToast } from "../contexts/ToastContext";
import { CodeBlock, RelTime } from "./formatting";
import { KV, ProseSection, SectionHead } from "./drawer/DrawerKit";
import { TableSkeleton } from "./Skeletons";

const HttpGrid = lazy(() => import("./HttpGrid"));

// ── HTTP method colors ────────────────────────────────────────────────
// Mapped onto our palette (the reference-project reference used --m-* vars that
// don't exist in our theme). The class drives the colored .method-badge in
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
  // Bumped by EngagementPage after every successful page refresh (including
  // WebSocket-driven ones). A change triggers a silent background reload so
  // this tab stays live alongside the others without flickering to a spinner.
  refreshVersion?: number;
};

const INITIAL_FETCH_LIMIT = 5000;

export function HttpTab({ engagementKey, refreshVersion }: HttpTabProps) {
  const { toast } = useToast();
  const [variants, setVariants] = useState<RequestVariant[]>([]);
  const [observations, setObservations] = useState<RequestObservation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [methodFilters, setMethodFilters] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<RequestVariant | null>(null);

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Fetch variants + observations together. Both are read-only and the
  // observations are grouped to variants client-side, so a single fetch
  // covers the whole tab. `showSpinner=false` is used for background
  // refreshes (WS tick / visibility) so the list doesn't flicker.
  const reloadInFlightRef = useRef(false);
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) return;
      reloadInFlightRef.current = true;
      if (showSpinner) setLoading(true);
      try {
        const [vs, obs] = await Promise.all([
          listRequestVariants(engagementKey),
          listRequestObservations(engagementKey).catch(() => [] as RequestObservation[]),
        ]);
        setVariants(vs);
        setObservations(obs);
        setLoadError(null);
      } catch (err) {
        if (showSpinner) {
          setVariants([]);
          setObservations([]);
        }
        setLoadError(err instanceof Error ? err.message : "Failed to load HTTP traffic");
      } finally {
        reloadInFlightRef.current = false;
        if (showSpinner) setLoading(false);
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

  // Background refresh on visibility regain so the tab stays live alongside
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

  // `/` focuses search, Esc blurs / closes the drawer.
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
        if (isTyping) searchRef.current?.blur();
        else if (selected) setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected]);

  const truncated = variants.length >= INITIAL_FETCH_LIMIT;

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
              placeholder="Search request variants — path, host, URL…"
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
            <span className="meta-text">
              {filtered.length} of {variants.length} variant
              {variants.length === 1 ? "" : "s"}
              {loading && " · loading…"}
              {truncated && " · list truncated"}
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
          <p className="empty" style={{ textAlign: "left" }}>
            {loadError}
          </p>
        </div>
      )}

      {/* Variants table */}
      <section className="panel">
        <div className="panel-header">
          <h2>Request variants</h2>
          <p className="meta-text">
            {filtered.length} variant{filtered.length === 1 ? "" : "s"}
            {observations.length ? ` · ${observations.length} observations` : ""}
          </p>
        </div>

        {loading ? (
          <TableSkeleton rows={8} showHeader={false} />
        ) : variants.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px", color: "var(--muted)" }}>
            No HTTP request traffic recorded yet.
          </p>
        ) : (
          <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
            <HttpGrid
              rows={filtered}
              observationCounts={observationCounts}
              selectedId={selected?.id ?? null}
              onRowOpen={(variant) => setSelected(variant)}
            />
          </Suspense>
        )}
      </section>

      {selected && (
        <HttpDrawer
          variant={selected}
          observations={observationsByVariant.get(selected.id) ?? []}
          toast={toast}
          onClose={() => setSelected(null)}
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
  toast,
  onClose,
}: {
  variant: RequestVariant;
  observations: RequestObservation[];
  toast: (message: string, type?: "success" | "error" | "info") => void;
  onClose: () => void;
}) {
  useBodyScrollLock();
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
        className="drawer-panel panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="http-detail-modal-title"
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
            {observations.length === 0 ? (
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
