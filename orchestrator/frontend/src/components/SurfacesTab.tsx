import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AssessmentFindingLink, AssessmentSurface, SurfacePatchPayload } from "../lib/api";
import {
  listAssessmentFindingLinks,
  listAssessmentSurfaces,
  patchAssessmentSurface,
} from "../lib/api";

type SurfacesTabProps = {
  engagementKey: string;
  surfaces: AssessmentSurface[];
  // Optional: parent refresh hook so a successful PATCH triggers a fresh
  // list fetch instead of waiting for the next polling tick.
  onSurfaceUpdated?: (surface: AssessmentSurface) => void;
};

type GroupedSurfaces = {
  type: string;
  items: AssessmentSurface[];
};

function groupSurfaces(surfaces: AssessmentSurface[]): GroupedSurfaces[] {
  const buckets = new Map<string, AssessmentSurface[]>();
  for (const surface of surfaces) {
    const key = surface.surface_type || "unknown";
    const list = buckets.get(key) ?? [];
    list.push(surface);
    buckets.set(key, list);
  }
  return Array.from(buckets.entries())
    .map(([type, items]) => ({ type, items }))
    .sort((a, b) => b.items.length - a.items.length || a.type.localeCompare(b.type));
}

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

export function SurfacesTab({ engagementKey, surfaces, onSurfaceUpdated }: SurfacesTabProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [findingLinks, setFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [linksError, setLinksError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AssessmentSurface | null>(null);
  // Track the in-flight PATCH so the inline button shows a busy state and
  // disables itself until the network round-trip resolves.
  const [pendingResolution, setPendingResolution] = useState<string | null>(null);
  const [resolutionError, setResolutionError] = useState<string | null>(null);
  const [resolutionRationale, setResolutionRationale] = useState<string>("");
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
      setResolutionError(null);
      setPendingResolution(status);
      const submittedRationale = resolutionRationale;
      try {
        const updated = await patchAssessmentSurface(engagementKey, selected.id, {
          status,
          rationale: submittedRationale || undefined,
        });
        setSelected(updated);
        mergeLocalSurface(updated);
        setResolutionRationale("");
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
          const fresh = await listAssessmentSurfaces(engagementKey);
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
    [engagementKey, mergeLocalSurface, onSurfaceUpdated, resolutionRationale, selected],
  );

  const [query, setQuery] = useState("");
  const [typeFilters, setTypeFilters] = useState<Set<string>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [sourceFilters, setSourceFilters] = useState<Set<string>>(new Set());

  const searchRef = useRef<HTMLInputElement | null>(null);

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
      if (typeFilters.size && !typeFilters.has(s.surface_type || "unknown")) return false;
      if (statusFilters.size && !statusFilters.has(s.status || "")) return false;
      if (sourceFilters.size && !sourceFilters.has(s.source_name || "")) return false;
      if (!matchesQuery(s, parsedQuery)) return false;
      return true;
    });
  }, [localSurfaces, typeFilters, statusFilters, sourceFilters, parsedQuery, matchesQuery]);

  const groups = useMemo(() => groupSurfaces(filteredSurfaces), [filteredSurfaces]);

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

  function toggle(type: string) {
    setExpanded((current) => ({ ...current, [type]: !current[type] }));
  }

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
            <span className="meta-text">
              {filteredSurfaces.length} of {localSurfaces.length} surface
              {localSurfaces.length === 1 ? "" : "s"}
              {linksError ? " · links unavailable" : ""}
            </span>
          </div>
        </div>
        <div className="filter-row">
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
                    onClick={() => toggleChip(typeFilters, setTypeFilters, t)}
                  >
                    {t}
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
                    onClick={() => toggleChip(statusFilters, setStatusFilters, s)}
                  >
                    {s.replace(/_/g, " ")}
                    <span className="filter-count">{statusCounts[s]}</span>
                  </button>
                ))}
            </div>
          )}
          {Object.keys(sourceCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Source</span>
              {Object.keys(sourceCounts)
                .sort((a, b) => sourceCounts[b] - sourceCounts[a] || a.localeCompare(b))
                .map((src) => (
                  <button
                    key={src}
                    type="button"
                    className={`filter-chip ${sourceFilters.has(src) ? "is-active" : ""}`}
                    onClick={() => toggleChip(sourceFilters, setSourceFilters, src)}
                  >
                    {src}
                    <span className="filter-count">{sourceCounts[src]}</span>
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

      {/* Surfaces table, grouped by type */}
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surfaces</h2>
          <p className="meta-text">
            {filteredSurfaces.length} surface{filteredSurfaces.length === 1 ? "" : "s"}
            {linksError ? " · links unavailable" : ""}
          </p>
        </div>

        {groups.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px" }}>
            {localSurfaces.length === 0
              ? "No surfaces discovered yet."
              : "No surfaces match the current filters."}
          </p>
        ) : (
          <div className="coverage-tree" style={{ marginTop: "14px" }}>
            {groups.map(({ type, items }) => {
              const isOpen = expanded[type] ?? true;
              return (
                <div key={type} className="coverage-tree-node">
                  <button
                    type="button"
                    className="coverage-tree-header"
                    onClick={() => toggle(type)}
                  >
                    <span>{isOpen ? "▾" : "▸"}</span>
                    <strong>{type}</strong>
                    <span className="meta-text">
                      {items.length} surface{items.length === 1 ? "" : "s"}
                    </span>
                  </button>
                  {isOpen && (
                    <div style={{ padding: "0 14px 14px" }}>
                      <div className="coverage-items-grid">
                        <div
                          className="coverage-items-header"
                          style={{ gridTemplateColumns: "1fr 120px 140px 2fr 80px" }}
                        >
                          <span>Target</span>
                          <span>Status</span>
                          <span>Source</span>
                          <span>Rationale</span>
                          <span>Findings</span>
                        </div>
                        {items.map((surface) => {
                          const links = linksBySurfaceId.get(surface.id) ?? [];
                          return (
                            <button
                              key={surface.id}
                              type="button"
                              className="finding-row"
                              onClick={() => setSelected(surface)}
                              style={{
                                display: "grid",
                                gridTemplateColumns: "1fr 120px 140px 2fr 80px",
                                gap: "8px",
                                textAlign: "left",
                              }}
                            >
                              <span className="mono-text" title={surface.target_descriptor}>
                                {surface.target_descriptor}
                              </span>
                              <span>
                                <span className={`badge status-${surface.status}`}>
                                  {surface.status}
                                </span>
                              </span>
                              <span className="meta-text">{surface.source_name || "—"}</span>
                              <span className="meta-text">{surface.rationale || "—"}</span>
                              <span>
                                {links.length > 0 ? (
                                  <span className="badge">{links.length}</span>
                                ) : (
                                  <span className="meta-text">—</span>
                                )}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Detail modal — styled to match Findings drawer */}
      {selected && (
        <div
          className="finding-overlay"
          role="presentation"
          onClick={() => setSelected(null)}
        >
          <article
            className="drawer-panel panel"
            role="dialog"
            aria-modal="true"
            onClick={(event) => event.stopPropagation()}
            style={{ maxWidth: "720px", width: "min(92vw, 720px)", maxHeight: "90vh", overflow: "auto" }}
          >
            <div className="drawer-hero">
              <div className="drawer-top">
                <div className="drawer-slug">
                  <span>{selected.surface_type}</span>
                </div>
                <div className="drawer-nav">
                  <button
                    type="button"
                    className="icon-btn"
                    onClick={() => setSelected(null)}
                    title="Close (Esc)"
                  >
                    <IconClose />
                  </button>
                </div>
              </div>
              <h2 className="drawer-title">{selected.target_descriptor}</h2>
              <div className="hero-meta">
                <span className={`pill pill-${selected.status}`}>{selected.status}</span>
                {selected.source_name && (
                  <span className="pill pill-unreviewed">{selected.source_name}</span>
                )}
              </div>
            </div>
            <div className="drawer-body">
              <div className="section">
                <p className="section-title">Metadata</p>
                <div className="kv-grid">
                  <div className="kv">
                    <p className="k">Surface type</p>
                    <p className="v">{selected.surface_type || "—"}</p>
                  </div>
                  <div className="kv">
                    <p className="k">Status</p>
                    <p className="v">{selected.status || "—"}</p>
                  </div>
                  <div className="kv">
                    <p className="k">Source</p>
                    <p className="v">{selected.source_name || "—"}</p>
                  </div>
                  <div className="kv">
                    <p className="k">Updated</p>
                    <p className="v">{selected.updated_at || "—"}</p>
                  </div>
                  {selected.evidence_ref && (
                    <div className="kv">
                      <p className="k">Evidence ref</p>
                      <p className="v mono">{selected.evidence_ref}</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="section">
                <p className="section-title">Resolve status</p>
                <p className="meta-text" style={{ margin: "0 0 8px" }}>
                  Resolve a discovered surface to covered, not_applicable, or deferred.
                  The rationale is appended to the existing audit trail.
                </p>
                <textarea
                  rows={2}
                  placeholder="Rationale (optional, appended to the audit trail)"
                  value={resolutionRationale}
                  onChange={(e) => setResolutionRationale(e.target.value)}
                  style={{
                    width: "100%",
                    boxSizing: "border-box",
                    fontSize: "0.85rem",
                    padding: "6px 8px",
                    marginBottom: "8px",
                  }}
                />
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {(["covered", "not_applicable", "deferred"] as const).map((s) => (
                    <button
                      key={s}
                      type="button"
                      className={`filter-chip ${pendingResolution === s ? "is-active" : ""}`}
                      disabled={pendingResolution != null}
                      onClick={() => void resolveSurfaceStatus(s)}
                    >
                      {pendingResolution === s ? "Saving…" : `Mark ${s}`}
                    </button>
                  ))}
                </div>
                {resolutionError && (
                  <p className="meta-text" style={{ color: "var(--c-error, #c33)", margin: "8px 0 0" }}>
                    {resolutionError}
                  </p>
                )}
              </div>

              {selected.rationale && (
                <div className="callout">
                  <p className="section-title">Rationale</p>
                  <p>{selected.rationale}</p>
                </div>
              )}

              <div className="section">
                <p className="section-title">
                  Linked findings <span className="count">{selectedLinks.length}</span>
                </p>
                {selectedLinks.length === 0 ? (
                  <p className="empty" style={{ padding: "12px 0" }}>
                    No findings linked to this surface yet.
                  </p>
                ) : (
                  <div style={{ display: "grid", gap: "6px" }}>
                    {selectedLinks.map((link) => (
                      <div key={link.id} className="callout" style={{ padding: "10px 12px" }}>
                        <p className="mono" style={{ margin: 0, fontWeight: 600 }}>
                          {link.finding_slug}
                        </p>
                        <p className="meta-text" style={{ margin: "4px 0 0" }}>
                          {link.link_kind}
                          {link.notes ? ` · ${link.notes}` : ""}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </article>
        </div>
      )}
    </div>
  );
}
