// ── OastTab ───────────────────────────────────────────────────────────
// Read-only view over the engagement's OAST (out-of-band) probes. One grid
// row per probe (assessment_oob_probes); the list endpoint embeds a derived
// interaction_count + last_interaction_at. The per-probe detail drawer
// fetches getOobProbe(nonce) to pull the full interactions[] history — the
// LIST endpoint only carries counts, so the DETAIL endpoint is the source
// for the per-interaction sub-list.
//
// Status filtering is done CLIENT-SIDE (a chip toggling a Set) rather than
// re-fetching with ?status= — the full list is small and already in memory,
// so a client filter is simpler and avoids a round-trip per chip click.
// The grid is lazy-loaded so ag-grid lands in the shared code-split chunk.

import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { OobInteraction, OobProbe, OobProbeDetail } from "../lib/api";
import { getOobProbe, listOobProbes } from "../lib/api";
import { useBodyScrollLock } from "../lib/modalScrollLock";
import { useToast } from "../contexts/ToastContext";
import { CodeBlock, RelTime } from "./formatting";
import { KV, ProseSection, UntrustedDataNotice } from "./drawer/DrawerKit";
import { Skeleton, TableSkeleton } from "./Skeletons";

const OastGrid = lazy(() => import("./OastGrid"));

// ── Status colors ─────────────────────────────────────────────────────
// fired = ok/green (a callback landed), pending = warn (minted, awaiting),
// unmatched = muted (stray callback w/ no probe), confirmed = ok,
// expired/ignored = muted. Drives the colored .oob-status-badge — see
// app.css "OAST status colors".
const OOB_STATUS_CLASSES: Record<string, string> = {
  fired: "oob-fired",
  confirmed: "oob-fired",
  pending: "oob-pending",
  unmatched: "oob-muted",
  expired: "oob-muted",
  ignored: "oob-muted",
};

export function oobStatusClass(status: string): string {
  return OOB_STATUS_CLASSES[(status || "").toLowerCase()] || "oob-muted";
}

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
function maybeDecode(raw: string): string {
  const text = (raw || "").trim();
  if (!text) return "";
  // Heuristic: base64 alphabet only, length a multiple of 4, reasonably long.
  if (text.length >= 8 && text.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    try {
      const decoded = atob(text);
      // Only swap in the decoded form if it's mostly printable — otherwise
      // the original was probably not base64 (or was binary).
      const printable = decoded.replace(/[^\x20-\x7e\r\n\t]/g, "");
      if (printable.length >= decoded.length * 0.85) return decoded;
    } catch {
      // fall through to raw
    }
  }
  return raw;
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

type OastTabProps = {
  engagementKey: string;
  // Bumped by EngagementPage after every successful page refresh (including
  // WebSocket-driven ones). A change triggers a silent background reload so
  // this tab stays live alongside the others without flickering to a spinner.
  refreshVersion?: number;
};

const STATUS_ORDER = ["fired", "pending", "unmatched", "confirmed", "expired", "ignored"] as const;

export function OastTab({ engagementKey, refreshVersion }: OastTabProps) {
  const { toast } = useToast();
  const [probes, setProbes] = useState<OobProbe[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<OobProbe | null>(null);

  // Detail cache keyed by nonce — full interactions[] pulled lazily when a
  // probe drawer opens.
  const [detailCache, setDetailCache] = useState<Map<string, OobProbeDetail>>(() => new Map());
  const [detailLoading, setDetailLoading] = useState<Set<string>>(() => new Set());

  const searchRef = useRef<HTMLInputElement | null>(null);

  const reloadInFlightRef = useRef(false);
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) return;
      reloadInFlightRef.current = true;
      if (showSpinner) setLoading(true);
      try {
        const items = await listOobProbes(engagementKey);
        setProbes(items);
        setLoadError(null);
      } catch (err) {
        if (showSpinner) setProbes([]);
        setLoadError(err instanceof Error ? err.message : "Failed to load OAST probes");
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

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void reload(false);
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [reload]);

  // Refetch a probe's detail (full interactions[]), bypassing the cache. Used
  // by the WS-driven refresh so an open drawer picks up freshly correlated
  // callbacks; ensureDetail (below) is the cache-first variant for first open.
  const refetchDetail = useCallback(
    (nonce: string) => {
      getOobProbe(engagementKey, nonce)
        .then((detail) => setDetailCache((m) => new Map(m).set(nonce, detail)))
        .catch(() => {
          // Swallow — keep the stale detail on a transient failure.
        });
    },
    [engagementKey],
  );

  const ensureDetail = useCallback(
    (nonce: string) => {
      if (detailCache.has(nonce) || detailLoading.has(nonce)) return;
      setDetailLoading((s) => new Set(s).add(nonce));
      getOobProbe(engagementKey, nonce)
        .then((detail) => {
          setDetailCache((m) => new Map(m).set(nonce, detail));
        })
        .catch(() => {
          // Swallow — the drawer keeps showing the list-row metadata.
        })
        .finally(() => {
          setDetailLoading((s) => {
            const next = new Set(s);
            next.delete(nonce);
            return next;
          });
        });
    },
    [detailCache, detailLoading, engagementKey],
  );

  // Silent background reload whenever the parent's refresh version bumps
  // (poll tick / WebSocket event). Skip the first render so it doesn't
  // double-fetch alongside the mount load. Also re-pull the open drawer's
  // detail so newly correlated callbacks show without re-opening it.
  const didInitialMountRef = useRef(false);
  const selectedNonceRef = useRef<string | null>(null);
  selectedNonceRef.current = selected?.nonce ?? null;
  useEffect(() => {
    if (!didInitialMountRef.current) {
      didInitialMountRef.current = true;
      return;
    }
    void reload(false);
    const openNonce = selectedNonceRef.current;
    if (openNonce) refetchDetail(openNonce);
  }, [refreshVersion, reload, refetchDetail]);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of probes) {
      const k = (p.status || "pending").toLowerCase();
      c[k] = (c[k] || 0) + 1;
    }
    return c;
  }, [probes]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return probes.filter((p) => {
      if (statusFilters.size && !statusFilters.has((p.status || "pending").toLowerCase()))
        return false;
      if (q) {
        const corpus = [p.target_url, p.technique, p.nonce, p.oob_domain, p.param, p.probe_kind]
          .filter(Boolean)
          .join(" \n ")
          .toLowerCase();
        if (!corpus.includes(q)) return false;
      }
      return true;
    });
  }, [probes, statusFilters, query]);

  useEffect(() => {
    if (selected && !probes.some((p) => p.nonce === selected.nonce)) {
      setSelected(null);
    }
  }, [probes, selected]);

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

  const activeFilterCount = statusFilters.size + (query ? 1 : 0);

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

  // Chip order: canonical buckets first, then any other present status.
  const statusChips = useMemo(() => {
    const present = new Set(Object.keys(statusCounts));
    const ordered: string[] = [];
    for (const s of STATUS_ORDER) {
      if (present.has(s) || statusFilters.has(s)) ordered.push(s);
    }
    for (const s of present) if (!ordered.includes(s)) ordered.push(s);
    return ordered;
  }, [statusCounts, statusFilters]);

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
              placeholder="Search OAST probes — target, technique, nonce…"
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
              {filtered.length} of {probes.length} probe{probes.length === 1 ? "" : "s"}
              {loading && " · loading…"}
            </span>
          </div>
        </div>
        <div className="filter-row">
          {statusChips.length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Status</span>
              {statusChips.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`filter-chip oob-status-chip ${oobStatusClass(s)} ${
                    statusFilters.has(s) ? "is-active" : ""
                  }`}
                  onClick={() => toggleStatus(s)}
                >
                  <span className={`sev-dot oob-status-dot ${oobStatusClass(s)}`} />
                  {s}
                  <span className="filter-count">{statusCounts[s] || 0}</span>
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

      {/* Probes table */}
      <section className="panel">
        <div className="panel-header">
          <h2>OAST probes</h2>
          <p className="meta-text">
            {filtered.length} probe{filtered.length === 1 ? "" : "s"}
          </p>
        </div>

        {loading ? (
          <TableSkeleton rows={8} showHeader={false} />
        ) : probes.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px", color: "var(--muted)" }}>
            No OAST probes minted yet.
          </p>
        ) : (
          <Suspense fallback={<TableSkeleton rows={8} showHeader={false} />}>
            <OastGrid
              rows={filtered}
              selectedNonce={selected?.nonce ?? null}
              onRowOpen={(probe) => {
                setSelected(probe);
                ensureDetail(probe.nonce);
              }}
            />
          </Suspense>
        )}
      </section>

      {selected && (
        <OastDrawer
          probe={selected}
          detail={detailCache.get(selected.nonce) ?? null}
          detailLoading={detailLoading.has(selected.nonce)}
          protocolClass={protocolClass}
          maybeDecode={maybeDecode}
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

// ── Probe detail drawer ───────────────────────────────────────────────
// Hero = technique + status badge; KV grid of probe metadata; notes; and an
// Interactions sub-list driven by the DETAIL fetch (getOobProbe(nonce)).
// Falls back to the list-row interaction_count while the detail is loading.
function OastDrawer({
  probe,
  detail,
  detailLoading,
  protocolClass,
  maybeDecode,
  toast,
  onClose,
}: {
  probe: OobProbe;
  detail: OobProbeDetail | null;
  detailLoading: boolean;
  protocolClass: (proto: string) => string;
  maybeDecode: (raw: string) => string;
  toast: (message: string, type?: "success" | "error" | "info") => void;
  onClose: () => void;
}) {
  useBodyScrollLock();
  const status = probe.status || "pending";
  const interactions: OobInteraction[] = detail?.interactions ?? [];
  const expectedCount = probe.interaction_count ?? 0;

  return (
    <div className="finding-overlay" role="presentation" onClick={onClose}>
      <article
        className="drawer-panel panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="oast-detail-modal-title"
        onClick={(event) => event.stopPropagation()}
        style={{ maxWidth: "760px", width: "min(94vw, 760px)", maxHeight: "90vh", overflow: "auto" }}
      >
        <div className="drawer-hero">
          <div className="drawer-top">
            <div className="drawer-slug">
              <span className={`oob-status-badge ${oobStatusClass(status)}`}>{status}</span>
            </div>
            <div className="drawer-nav">
              <button type="button" className="icon-btn" onClick={onClose} title="Close (Esc)">
                <IconClose />
              </button>
            </div>
          </div>
          <h2 id="oast-detail-modal-title" className="drawer-title">
            {probe.technique || "OAST probe"}
          </h2>
          <div className="hero-meta">
            {probe.probe_kind && <span className="tag">{probe.probe_kind}</span>}
            {probe.param && <span className="tag">{probe.param}</span>}
          </div>
        </div>

        <div className="drawer-body">
          <UntrustedDataNotice />
          <div className="section">
            <p className="section-title">Metadata</p>
            <div className="kv-grid">
              <KV k="Nonce" v={probe.nonce} mono toast={probe.nonce ? toast : undefined} />
              <KV
                k="OOB domain"
                v={probe.oob_domain}
                mono
                toast={probe.oob_domain ? toast : undefined}
              />
              <KV
                k="Target URL"
                v={probe.target_url}
                mono
                toast={probe.target_url ? toast : undefined}
              />
              <KV k="Param" v={probe.param} mono />
              <KV k="Technique" v={probe.technique} />
              <KV k="Probe kind" v={probe.probe_kind} />
              <KV
                k="Request hash"
                v={probe.request_hash}
                mono
                toast={probe.request_hash ? toast : undefined}
              />
              <KV k="Status" v={status} />
              <div className="kv">
                <p className="k">Created</p>
                <p className="v">{probe.created_at ? <RelTime iso={probe.created_at} /> : "—"}</p>
              </div>
              <div className="kv">
                <p className="k">Updated</p>
                <p className="v">{probe.updated_at ? <RelTime iso={probe.updated_at} /> : "—"}</p>
              </div>
            </div>
          </div>

          {probe.notes && probe.notes.trim() && (
            <ProseSection title="Notes" text={probe.notes} mode="rendered" toast={toast} kind="callout" />
          )}

          <div className="section">
            <p className="section-title">
              Interactions{" "}
              <span className="count">{detail ? interactions.length : expectedCount}</span>
            </p>
            {detailLoading && !detail ? (
              <div style={{ display: "grid", gap: 8, padding: "8px 0" }}>
                <Skeleton height={48} />
                <Skeleton height={48} />
              </div>
            ) : interactions.length === 0 ? (
              <p className="empty" style={{ padding: "12px 0" }}>
                No callbacks observed for this probe yet.
              </p>
            ) : (
              <div className="oob-interaction-list">
                {interactions.map((it) => (
                  <div key={it.id} className="oob-interaction-card">
                    <div className="oob-interaction-head">
                      <span className={`oob-proto-badge ${protocolClass(it.protocol)}`}>
                        {it.protocol || "—"}
                      </span>
                      {it.remote_address && (
                        <span className="oob-remote mono">{it.remote_address}</span>
                      )}
                      {it.query_type && <span className="tag">{it.query_type}</span>}
                      <RelTime iso={it.observed_at || it.created_at} />
                    </div>
                    {it.raw_request && (
                      <CodeBlock
                        label="Raw request"
                        text={maybeDecode(it.raw_request)}
                        onCopied={() => toast("Copied", "success")}
                      />
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </article>
    </div>
  );
}
