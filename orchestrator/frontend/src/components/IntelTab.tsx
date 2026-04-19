import { useEffect, useMemo, useState } from "react";
import type {
  IntelByUrlResponse,
  IntelEntityType,
  IntelRecord,
  IntelSearchHit,
  IntelSummary,
  ListIntelResponse,
} from "../lib/api";
import {
  intelByUrl,
  listIntel,
  listIntelCredentials,
  searchIntel,
} from "../lib/api";

type IntelTabProps = {
  engagementKey: string;
  summary: IntelSummary | null;
};

type EntityFilter = IntelEntityType | "credentials";

type FilterSpec = {
  key: EntityFilter;
  label: string;
};

// Order mirrors §3a: Tech stack / People / Emails / Domains / Credentials /
// CVEs / DNS / Social / Breach / Org / Notes.
const ENTITY_FILTERS: FilterSpec[] = [
  { key: "tech_component", label: "Tech stack" },
  { key: "person", label: "People" },
  { key: "email", label: "Emails" },
  { key: "domain", label: "Domains" },
  { key: "credentials", label: "Credentials" },
  { key: "cve", label: "CVEs" },
  { key: "dns_record", label: "DNS" },
  { key: "social_profile", label: "Social" },
  { key: "breach_record", label: "Breach" },
  { key: "org_fact", label: "Org" },
  { key: "note", label: "Notes" },
];

const PAGE_SIZE = 50;

function summaryKey(filter: EntityFilter): string {
  // The backend summary keys (when it lands) will match the entity_type;
  // credentials is handled as a separate list.
  return filter;
}

type SortDir = "asc" | "desc";

export function IntelTab({ engagementKey, summary }: IntelTabProps) {
  const [filter, setFilter] = useState<EntityFilter>("tech_component");
  const [items, setItems] = useState<IntelRecord[] | Record<string, unknown>[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [rowFilter, setRowFilter] = useState("");

  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<IntelSearchHit[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  const [urlQuery, setUrlQuery] = useState("");
  const [urlResults, setUrlResults] = useState<IntelByUrlResponse | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);

  const [selected, setSelected] = useState<IntelRecord | Record<string, unknown> | null>(null);

  // Fetch per-filter table data whenever the chosen entity chip changes.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setPage(0);
    setSortColumn(null);

    const fetcher: Promise<{ items: (IntelRecord | Record<string, unknown>)[]; total: number }> =
      filter === "credentials"
        ? listIntelCredentials(engagementKey).then((rows) => ({
            items: rows,
            total: rows.length,
          }))
        : listIntel(engagementKey, filter).then((payload: ListIntelResponse) => ({
            items: payload.items,
            total: payload.total,
          }));

    fetcher
      .then((result) => {
        if (cancelled) return;
        setItems(result.items);
        setTotal(result.total);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // 501 / 404 are expected while B1 is mid-flight — degrade to empty.
        setItems([]);
        setTotal(0);
        setError(err instanceof Error ? err.message : "Failed to load intel");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [engagementKey, filter]);

  // Columns are derived from whichever rows came back. Keeps the table
  // honest against whatever payload Phase B1 finally emits.
  const columns = useMemo(() => {
    if (items.length === 0) return [] as string[];
    const seen = new Set<string>();
    const ordered: string[] = [];
    for (const row of items.slice(0, 20)) {
      if (row && typeof row === "object") {
        for (const key of Object.keys(row)) {
          if (key === "provenance" || key === "notes") continue;
          if (!seen.has(key)) {
            seen.add(key);
            ordered.push(key);
          }
        }
      }
    }
    // Push timestamps to the end, ids to the front.
    const priority = (k: string) => {
      if (k === "id") return -2;
      if (k === "created_at" || k === "updated_at") return 2;
      return 0;
    };
    ordered.sort((a, b) => priority(a) - priority(b));
    return ordered;
  }, [items]);

  const filteredItems = useMemo(() => {
    const needle = rowFilter.trim().toLowerCase();
    let rows: (IntelRecord | Record<string, unknown>)[] = items;
    if (needle) {
      rows = rows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle));
    }
    if (sortColumn) {
      rows = [...rows].sort((a, b) => {
        const av = fmtCell((a as Record<string, unknown>)[sortColumn]);
        const bv = fmtCell((b as Record<string, unknown>)[sortColumn]);
        const cmp = av.localeCompare(bv, undefined, { numeric: true });
        return sortDir === "asc" ? cmp : -cmp;
      });
    }
    return rows;
  }, [items, rowFilter, sortColumn, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE));
  const pageItems = filteredItems.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  useEffect(() => {
    setPage((current) => Math.min(current, totalPages - 1));
  }, [totalPages]);

  function toggleSort(column: string) {
    if (sortColumn === column) {
      setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    } else {
      setSortColumn(column);
      setSortDir("asc");
    }
  }

  function runSearch() {
    const q = searchQuery.trim();
    if (!q) {
      setSearchResults(null);
      setSearchError(null);
      return;
    }
    setSearching(true);
    setSearchError(null);
    const entity_type = filter === "credentials" ? "" : filter;
    searchIntel(engagementKey, { q, entity_type })
      .then((rows) => setSearchResults(rows))
      .catch((err: unknown) => {
        setSearchResults([]);
        setSearchError(err instanceof Error ? err.message : "Search failed");
      })
      .finally(() => setSearching(false));
  }

  function runUrlSearch() {
    const u = urlQuery.trim();
    if (!u) {
      setUrlResults(null);
      setUrlError(null);
      return;
    }
    setUrlLoading(true);
    setUrlError(null);
    intelByUrl(engagementKey, u)
      .then((resp) => setUrlResults(resp))
      .catch((err: unknown) => {
        setUrlResults(null);
        setUrlError(err instanceof Error ? err.message : "By-URL lookup failed");
      })
      .finally(() => setUrlLoading(false));
  }

  // Close drawer on Escape.
  useEffect(() => {
    if (!selected) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selected]);

  const activeSpec = ENTITY_FILTERS.find((s) => s.key === filter);
  const counts = summary?.counts ?? {};

  return (
    <>
      <section className="panel filter-bar-panel">
        <div className="filter-bar" style={{ flexDirection: "column", alignItems: "stretch", gap: "12px" }}>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <input
              type="search"
              className="filter-select"
              placeholder="Search intel (FTS)…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runSearch();
              }}
              style={{ flex: "1 1 260px", minWidth: "200px" }}
            />
            <button type="button" className="ghost-button" onClick={runSearch} disabled={searching}>
              {searching ? "Searching…" : "Search"}
            </button>
            {(searchResults !== null || searchError) && (
              <button
                type="button"
                className="ghost-button"
                onClick={() => {
                  setSearchQuery("");
                  setSearchResults(null);
                  setSearchError(null);
                }}
              >
                Clear
              </button>
            )}
          </div>

          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <input
              type="search"
              className="filter-select"
              placeholder="By URL: anything from this URL…"
              value={urlQuery}
              onChange={(e) => setUrlQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runUrlSearch();
              }}
              style={{ flex: "1 1 260px", minWidth: "200px" }}
            />
            <button type="button" className="ghost-button" onClick={runUrlSearch} disabled={urlLoading}>
              {urlLoading ? "Looking up…" : "By URL"}
            </button>
            {(urlResults || urlError) && (
              <button
                type="button"
                className="ghost-button"
                onClick={() => {
                  setUrlQuery("");
                  setUrlResults(null);
                  setUrlError(null);
                }}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </section>

      <section
        className="findings-layout"
        style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: "16px", alignItems: "start" }}
      >
        <aside className="panel" style={{ padding: "14px" }}>
          <p className="eyebrow" style={{ marginTop: 0 }}>Entity type</p>
          <div className="filter-group" style={{ flexDirection: "column", alignItems: "stretch", gap: "4px" }}>
            {ENTITY_FILTERS.map((spec) => {
              const count = counts[summaryKey(spec.key)];
              return (
                <button
                  key={spec.key}
                  type="button"
                  className={`filter-chip ${filter === spec.key ? "filter-active" : ""}`}
                  onClick={() => setFilter(spec.key)}
                  style={{ justifyContent: "space-between" }}
                >
                  <span>{spec.label}</span>
                  {count != null && count > 0 && <span className="filter-count">{count}</span>}
                </button>
              );
            })}
          </div>
        </aside>

        <div style={{ display: "grid", gap: "16px" }}>
          {searchResults !== null && (
            <section className="panel">
              <div className="panel-header">
                <h2>Search results</h2>
                <p className="meta-text">{searchResults.length} hit{searchResults.length === 1 ? "" : "s"}</p>
              </div>
              {searchError && <p className="error-text">{searchError}</p>}
              {searchResults.length === 0 && !searchError && (
                <p className="empty-state">No hits.</p>
              )}
              {searchResults.length > 0 && (
                <div className="coverage-items-grid">
                  <div className="coverage-items-header" style={{ gridTemplateColumns: "140px 160px 1fr 120px" }}>
                    <span>Entity</span>
                    <span>Key</span>
                    <span>Body</span>
                    <span>Source</span>
                  </div>
                  {searchResults.map((hit, index) => (
                    <button
                      key={`${hit.entity_type}:${hit.source_id}:${index}`}
                      type="button"
                      className="finding-row"
                      onClick={() => setSelected(hit.record)}
                      style={{ display: "grid", gridTemplateColumns: "140px 160px 1fr 120px", gap: "8px", textAlign: "left" }}
                    >
                      <span className="badge">{hit.entity_type}</span>
                      <span className="mono-text">{hit.key}</span>
                      <span>{truncate(hit.body, 200)}</span>
                      <span className="meta-text">{hit.source_name}</span>
                    </button>
                  ))}
                </div>
              )}
            </section>
          )}

          {urlResults !== null && (
            <section className="panel">
              <div className="panel-header">
                <h2>By-URL results</h2>
                <p className="meta-text">{urlQuery}</p>
              </div>
              {urlError && <p className="error-text">{urlError}</p>}
              <UrlResultBlock label="Domains" rows={urlResults.domains as unknown as Record<string, unknown>[]} onSelect={setSelected} />
              <UrlResultBlock label="Services" rows={urlResults.services} onSelect={setSelected} />
              <UrlResultBlock label="Surfaces" rows={urlResults.surfaces} onSelect={setSelected} />
              <UrlResultBlock label="Request variants" rows={urlResults.request_variants} onSelect={setSelected} />
            </section>
          )}

          <section className="panel">
            <div className="panel-header">
              <h2>{activeSpec?.label ?? filter}</h2>
              <p className="meta-text">
                {loading ? "Loading…" : `${filteredItems.length}${rowFilter ? ` of ${total}` : ""} row${filteredItems.length === 1 ? "" : "s"}`}
              </p>
            </div>

            {items.length > 0 && (
              <div style={{ padding: "0 14px 10px" }}>
                <input
                  type="search"
                  className="filter-select"
                  placeholder="Filter rows…"
                  value={rowFilter}
                  onChange={(e) => setRowFilter(e.target.value)}
                  style={{ width: "100%" }}
                />
              </div>
            )}

            {error && <p className="error-text" style={{ padding: "0 14px" }}>{error}</p>}

            {!loading && items.length === 0 && !error && (
              <p className="empty-state" style={{ padding: "20px" }}>No {activeSpec?.label ?? filter} recorded yet.</p>
            )}

            {pageItems.length > 0 && columns.length > 0 && (
              <div className="coverage-items-grid" style={{ overflowX: "auto" }}>
                <div
                  className="coverage-items-header"
                  style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(100px, 1fr))` }}
                >
                  {columns.map((col) => (
                    <button
                      key={col}
                      type="button"
                      className="filter-chip"
                      onClick={() => toggleSort(col)}
                      style={{ justifyContent: "flex-start" }}
                    >
                      {col}
                      {sortColumn === col && <span>{sortDir === "asc" ? " ▲" : " ▼"}</span>}
                    </button>
                  ))}
                </div>
                {pageItems.map((row, index) => (
                  <button
                    key={((row as Record<string, unknown>).id as number) ?? index}
                    type="button"
                    className="finding-row"
                    onClick={() => setSelected(row as IntelRecord | Record<string, unknown>)}
                    style={{ display: "grid", gridTemplateColumns: `repeat(${columns.length}, minmax(100px, 1fr))`, gap: "8px", textAlign: "left" }}
                  >
                    {columns.map((col) => (
                      <span key={col} className="mono-text" title={fmtCell((row as Record<string, unknown>)[col])}>
                        {truncate(fmtCell((row as Record<string, unknown>)[col]), 80) || "—"}
                      </span>
                    ))}
                  </button>
                ))}
              </div>
            )}

            {totalPages > 1 && (
              <div className="pager">
                <button type="button" className="pager-button" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
                <span className="meta-text">Page {page + 1} of {totalPages}</span>
                <button type="button" className="pager-button" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>Next</button>
              </div>
            )}
          </section>
        </div>
      </section>

      {selected && (
        <div className="finding-overlay" role="presentation" onClick={() => setSelected(null)}>
          <article
            className="finding-modal panel"
            role="dialog"
            aria-modal="true"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="finding-modal-header">
              <div className="finding-modal-heading">
                <h2>Intel record</h2>
                <p className="meta-text">{activeSpec?.label ?? filter}</p>
              </div>
              <div className="finding-modal-actions">
                <button type="button" className="ghost-button" onClick={() => setSelected(null)}>Close</button>
              </div>
            </div>
            <div className="finding-modal-content">
              <IntelRecordDetail record={selected as Record<string, unknown>} />
            </div>
          </article>
        </div>
      )}
    </>
  );
}

function UrlResultBlock({
  label,
  rows,
  onSelect,
}: {
  label: string;
  rows: Record<string, unknown>[];
  onSelect: (row: Record<string, unknown>) => void;
}) {
  if (!rows || rows.length === 0) return null;
  return (
    <div style={{ padding: "0 14px 10px" }}>
      <p className="eyebrow">{label} · {rows.length}</p>
      <div style={{ display: "grid", gap: "4px" }}>
        {rows.map((row, index) => (
          <button
            key={index}
            type="button"
            className="finding-row"
            onClick={() => onSelect(row)}
            style={{ textAlign: "left" }}
          >
            <span className="mono-text">{truncate(summarizeRow(row), 200)}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function IntelRecordDetail({ record }: { record: Record<string, unknown> }) {
  const provenance = (record.provenance ?? {}) as Record<string, unknown>;
  const body = record.body_markdown as string | undefined;
  const skip = new Set(["provenance", "body_markdown"]);
  const fields = Object.entries(record).filter(([k]) => !skip.has(k));

  return (
    <>
      <div className="finding-meta-grid">
        {fields.map(([key, value]) => (
          <div key={key}>
            <p className="eyebrow">{key}</p>
            <p className="meta-text finding-mono" style={{ whiteSpace: "pre-wrap" }}>{fmtCell(value) || "—"}</p>
          </div>
        ))}
      </div>

      {typeof body === "string" && body.trim() && (
        <div>
          <p className="eyebrow">Body</p>
          <pre className="finding-notes" style={{ whiteSpace: "pre-wrap" }}>{body}</pre>
        </div>
      )}

      <div>
        <p className="eyebrow">Provenance</p>
        {Object.keys(provenance).length === 0 ? (
          <p className="meta-text">No provenance recorded.</p>
        ) : (
          <div className="finding-meta-grid">
            {Object.entries(provenance).map(([k, v]) => (
              <div key={k}>
                <p className="eyebrow">{k}</p>
                <p className="meta-text finding-mono">{fmtCell(v) || "—"}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function fmtCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function truncate(text: string, max: number): string {
  if (!text) return "";
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

function summarizeRow(row: Record<string, unknown>): string {
  for (const key of ["identity", "endpoint", "target_descriptor", "host", "name", "address", "url"]) {
    const v = row[key];
    if (typeof v === "string" && v) return v;
  }
  return fmtCell(row);
}
