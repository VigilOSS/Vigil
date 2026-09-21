import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AssessmentCoverageItem,
  AssessmentService,
  AssessmentSummary,
  AssessmentTarget,
} from "../lib/api";

type CoverageTabProps = {
  summary: AssessmentSummary | null;
  targets: AssessmentTarget[];
  services: AssessmentService[];
  coverageItems: AssessmentCoverageItem[];
};

const PAGE_SIZE = 50;

function extractHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

type HostGroup = {
  host: string;
  items: AssessmentCoverageItem[];
  serviceCount: number;
};

// ── Tokenized search ─────────────────────────────────────

const SCOPES = [
  "status",
  "host",
  "surface",
  "method",
  "family",
  "slot",
  "auth",
  "endpoint",
  "service",
] as const;
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

// ── Icons (inline SVG) ───────────────────────────────────

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

export function CoverageTab({
  summary,
  targets,
  services,
  coverageItems,
}: CoverageTabProps) {
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [pages, setPages] = useState<Record<string, number>>({});

  // Chip filters (multi-select sets)
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [familyFilters, setFamilyFilters] = useState<Set<string>>(new Set());
  const [authFilters, setAuthFilters] = useState<Set<string>>(new Set());

  // Tokenized search
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement | null>(null);

  const coverageStatuses = summary?.coverage_statuses ?? {};
  const totalCoverage = Object.values(coverageStatuses).reduce((a, b) => a + b, 0);
  const loadedCoverage = coverageItems.length;
  const coverageIsPartial = totalCoverage > loadedCoverage;
  const statusKeys = useMemo(() => Object.keys(coverageStatuses), [coverageStatuses]);

  // Build lookup: service_id → target host / surface name
  const serviceHostMap = useMemo(() => {
    const targetHostById = new Map<number, string>();
    for (const t of targets) targetHostById.set(t.id, t.host || t.hostname || t.identity);

    const map = new Map<number, string>();
    for (const svc of services) {
      const targetHost = targetHostById.get(svc.target_id);
      map.set(svc.id, targetHost || extractHost(svc.endpoint));
    }
    return map;
  }, [targets, services]);

  const serviceNameMap = useMemo(() => {
    const m = new Map<number, string>();
    for (const svc of services) m.set(svc.id, svc.service || "");
    return m;
  }, [services]);

  // Services count per host
  const serviceCountByHost = useMemo(() => {
    const counts = new Map<string, number>();
    for (const svc of services) {
      const host = serviceHostMap.get(svc.id) ?? "unknown";
      counts.set(host, (counts.get(host) ?? 0) + 1);
    }
    return counts;
  }, [services, serviceHostMap]);

  // Resolve a row's host once so we can use it for both filtering & grouping
  const hostOf = useCallback(
    (item: AssessmentCoverageItem): string => {
      if (item.service_id != null) {
        return serviceHostMap.get(item.service_id) ?? "unknown";
      }
      if (item.canonical_url) return extractHost(item.canonical_url);
      if (item.service_endpoint) return extractHost(item.service_endpoint);
      return "unknown";
    },
    [serviceHostMap],
  );

  const surfaceOf = useCallback(
    (item: AssessmentCoverageItem): string => {
      if (item.service_name) return item.service_name;
      if (item.service_id != null) return serviceNameMap.get(item.service_id) || "";
      return "";
    },
    [serviceNameMap],
  );

  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (item: AssessmentCoverageItem, parsed: ParsedQuery): boolean => {
      const host = hostOf(item);
      const surface = surfaceOf(item);
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "status":
            if ((item.status || "").toLowerCase() !== v) return false;
            break;
          case "host":
            if (!host.toLowerCase().includes(v)) return false;
            break;
          case "surface":
          case "service":
            if (!surface.toLowerCase().includes(v)) return false;
            break;
          case "method":
            if ((item.method || "").toLowerCase() !== v) return false;
            break;
          case "family":
            if (!(item.attack_family || "").toLowerCase().includes(v)) return false;
            break;
          case "slot":
            if (!(item.input_slot || "").toLowerCase().includes(v)) return false;
            break;
          case "auth":
            if (!(item.auth_context || "").toLowerCase().includes(v)) return false;
            break;
          case "endpoint": {
            const hay = `${item.canonical_url || ""} ${item.service_endpoint || ""}`;
            if (!hay.toLowerCase().includes(v)) return false;
            break;
          }
        }
      }
      if (parsed.freeTerms.length) {
        const corpus = [
          item.status,
          item.method,
          item.attack_family,
          item.input_slot,
          item.auth_context,
          item.canonical_url,
          item.service_endpoint,
          item.service_name,
          item.notes,
          host,
          surface,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        for (const t of parsed.freeTerms) if (!corpus.includes(t)) return false;
      }
      return true;
    },
    [hostOf, surfaceOf],
  );

  // Apply chip + search filters
  const filteredItems = useMemo(() => {
    return coverageItems.filter((item) => {
      if (statusFilters.size && !statusFilters.has(item.status)) return false;
      if (familyFilters.size && !familyFilters.has(item.attack_family)) return false;
      if (authFilters.size && !authFilters.has(item.auth_context)) return false;
      if (!matchesQuery(item, parsedQuery)) return false;
      return true;
    });
  }, [coverageItems, statusFilters, familyFilters, authFilters, parsedQuery, matchesQuery]);

  // Group filtered items by host (preserves tree structure)
  const hostGroups = useMemo(() => {
    const map = new Map<string, AssessmentCoverageItem[]>();

    for (const item of filteredItems) {
      const host = hostOf(item);
      const list = map.get(host) ?? [];
      list.push(item);
      map.set(host, list);
    }

    // Also include target hosts with zero coverage items
    for (const t of targets) {
      const host = t.host || t.hostname || t.identity;
      if (!map.has(host)) map.set(host, []);
    }

    const groups: HostGroup[] = [];
    for (const [host, items] of map) {
      groups.push({ host, items, serviceCount: serviceCountByHost.get(host) ?? 0 });
    }
    groups.sort((a, b) => b.items.length - a.items.length || a.host.localeCompare(b.host));
    return groups;
  }, [filteredItems, hostOf, serviceCountByHost, targets]);

  // Counts per chip dimension (independent of that dimension's own active filter)
  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const item of coverageItems) {
      if (familyFilters.size && !familyFilters.has(item.attack_family)) continue;
      if (authFilters.size && !authFilters.has(item.auth_context)) continue;
      if (!matchesQuery(item, parsedQuery)) continue;
      const key = item.status || "—";
      c[key] = (c[key] || 0) + 1;
    }
    return c;
  }, [coverageItems, familyFilters, authFilters, parsedQuery, matchesQuery]);

  const familyCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const item of coverageItems) {
      if (statusFilters.size && !statusFilters.has(item.status)) continue;
      if (authFilters.size && !authFilters.has(item.auth_context)) continue;
      if (!matchesQuery(item, parsedQuery)) continue;
      const key = item.attack_family || "—";
      c[key] = (c[key] || 0) + 1;
    }
    return c;
  }, [coverageItems, statusFilters, authFilters, parsedQuery, matchesQuery]);

  const authCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const item of coverageItems) {
      if (statusFilters.size && !statusFilters.has(item.status)) continue;
      if (familyFilters.size && !familyFilters.has(item.attack_family)) continue;
      if (!matchesQuery(item, parsedQuery)) continue;
      const key = item.auth_context || "—";
      c[key] = (c[key] || 0) + 1;
    }
    return c;
  }, [coverageItems, statusFilters, familyFilters, parsedQuery, matchesQuery]);

  const statusOrder = useMemo(
    () => Object.keys(statusCounts).sort((a, b) => a.localeCompare(b)),
    [statusCounts],
  );
  const familyOrder = useMemo(
    () => Object.keys(familyCounts).sort((a, b) => a.localeCompare(b)),
    [familyCounts],
  );
  const authOrder = useMemo(
    () => Object.keys(authCounts).sort((a, b) => a.localeCompare(b)),
    [authCounts],
  );

  const activeFilterCount =
    statusFilters.size + familyFilters.size + authFilters.size + (query ? 1 : 0);
  const hasAnyFilter = activeFilterCount > 0;

  const toggle = useCallback(
    (
      current: Set<string>,
      setter: (next: Set<string>) => void,
      value: string,
    ) => {
      const next = new Set(current);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      setter(next);
    },
    [],
  );

  const clearAll = useCallback(() => {
    setStatusFilters(new Set());
    setFamilyFilters(new Set());
    setAuthFilters(new Set());
    setQuery("");
  }, []);

  function getPage(host: string) {
    return pages[host] ?? 0;
  }
  function setPage(host: string, page: number) {
    setPages((p) => ({ ...p, [host]: page }));
  }

  useEffect(() => {
    setPages((current) => {
      const next: Record<string, number> = {};
      let changed = false;
      for (const { host, items } of hostGroups) {
        const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
        const currentPage = current[host] ?? 0;
        const clampedPage = Math.min(currentPage, totalPages - 1);
        next[host] = clampedPage;
        if (clampedPage !== currentPage) {
          changed = true;
        }
      }
      if (Object.keys(current).length !== Object.keys(next).length) {
        changed = true;
      }
      return changed ? next : current;
    });
  }, [hostGroups]);

  // `/` focuses search, Esc blurs
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
      if (e.key === "Escape" && isTyping && target === searchRef.current) {
        searchRef.current?.blur();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function splitEndpoint(item: AssessmentCoverageItem): { method: string; endpoint: string } {
    const method = item.method ?? "";
    if (item.canonical_url) {
      try {
        const url = new URL(item.canonical_url);
        return { method, endpoint: url.pathname + url.search };
      } catch {
        return { method, endpoint: item.canonical_url };
      }
    }
    return { method, endpoint: item.service_endpoint || "—" };
  }

  return (
    <>
      {/* Coverage status breakdown */}
      <section className="panel">
        <div className="panel-header">
          <h2>Test coverage</h2>
          <p className="meta-text">{totalCoverage} total items</p>
        </div>
        {totalCoverage > 0 ? (
          <div className="coverage-bar-container">
            <div className="coverage-bar">
              {statusKeys.map((status) => {
                const count = coverageStatuses[status];
                const pct = totalCoverage > 0 ? (count / totalCoverage) * 100 : 0;
                if (pct === 0) return null;
                return (
                  <div
                    key={status}
                    className={`coverage-segment coverage-segment-${status}`}
                    style={{ width: `${pct}%` }}
                    title={`${status}: ${count}`}
                  />
                );
              })}
            </div>
            <div className="coverage-legend">
              {statusKeys.map((status) => (
                <span key={status} className="coverage-legend-item">
                  <span className={`coverage-dot coverage-dot-${status}`} />
                  {status}: {coverageStatuses[status]}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <p className="meta-text">No coverage data recorded yet.</p>
        )}
        {coverageIsPartial && (
          <p className="data-boundary-note" role="status">
            Showing the first {loadedCoverage.toLocaleString()} of {totalCoverage.toLocaleString()} items.
            Filters below apply only to the loaded rows.
          </p>
        )}
      </section>

      {/* Unified attack surface */}
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surface</h2>
          <p className="meta-text">
            {targets.length} host{targets.length !== 1 ? "s" : ""}, {filteredItems.length}
            {hasAnyFilter ? ` of ${coverageItems.length}` : ""} item
            {filteredItems.length !== 1 ? "s" : ""}
            {coverageIsPartial ? " loaded" : ""}
          </p>
        </div>

        {/* Toolbar + filter chips (inherits .findings-redesign styles) */}
        {coverageItems.length > 0 && (
          <div className="findings-redesign">
            <div className="panel findings-toolbar-panel">
              <div className="toolbar">
                <div className="search-wrap">
                  <IconSearch />
                  <input
                    ref={searchRef}
                    className="search-input"
                    placeholder="Search any field — host, endpoint, family, payload… (try status:covered host:api method:GET)"
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
              </div>
              <div className="filter-row">
                {statusOrder.length > 0 && (
                  <div className="filter-group">
                    <span className="filter-label">Status</span>
                    {statusOrder.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={`filter-chip ${statusFilters.has(s) ? "is-active" : ""}`}
                        onClick={() => toggle(statusFilters, setStatusFilters, s)}
                      >
                        {s.replace(/_/g, " ")}
                        <span className="filter-count">{statusCounts[s]}</span>
                      </button>
                    ))}
                  </div>
                )}
                {familyOrder.length > 0 && (
                  <div className="filter-group">
                    <span className="filter-label">Attack family</span>
                    {familyOrder.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={`filter-chip ${familyFilters.has(s) ? "is-active" : ""}`}
                        onClick={() => toggle(familyFilters, setFamilyFilters, s)}
                      >
                        {s.replace(/_/g, " ")}
                        <span className="filter-count">{familyCounts[s]}</span>
                      </button>
                    ))}
                  </div>
                )}
                {authOrder.length > 0 && (
                  <div className="filter-group">
                    <span className="filter-label">Auth</span>
                    {authOrder.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={`filter-chip ${authFilters.has(s) ? "is-active" : ""}`}
                        onClick={() => toggle(authFilters, setAuthFilters, s)}
                      >
                        {s.replace(/_/g, " ")}
                        <span className="filter-count">{authCounts[s]}</span>
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
          </div>
        )}

        {/* Host groups */}
        {hostGroups.length > 0 ? (
          <div className="coverage-tree" style={{ marginTop: "14px" }}>
            {hostGroups.map(({ host, items, serviceCount }) => {
              const isExpanded = expandedHost === host;
              const page = getPage(host);
              const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
              const pageItems = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

              return (
                <div key={host} className="coverage-tree-node">
                  <button
                    type="button"
                    className="coverage-tree-header"
                    onClick={() => {
                      setExpandedHost(isExpanded ? null : host);
                    }}
                  >
                    <span>{isExpanded ? "▾" : "▸"}</span>
                    <strong>{host}</strong>
                    <span className="meta-text">
                      {items.length} item{items.length !== 1 ? "s" : ""}
                      {serviceCount > 0
                        ? `, ${serviceCount} service${serviceCount !== 1 ? "s" : ""}`
                        : ""}
                    </span>
                  </button>
                  {isExpanded && (
                    <div style={{ padding: "0 14px 14px" }}>
                      {items.length > 0 ? (
                        <>
                          <div className="coverage-items-grid">
                            <div className="coverage-items-header coverage-items-6col">
                              <span>Method</span>
                              <span>Endpoint</span>
                              <span>Attack family</span>
                              <span>Input slot</span>
                              <span>Auth</span>
                              <span>Status</span>
                            </div>
                            {pageItems.map((item) => {
                              const { method, endpoint } = splitEndpoint(item);
                              return (
                                <div
                                  key={item.id}
                                  className="coverage-items-row coverage-items-6col"
                                >
                                  <span className="mono-text">{method || "—"}</span>
                                  <span
                                    className="mono-text"
                                    title={item.canonical_url || item.service_endpoint || ""}
                                  >
                                    {endpoint}
                                  </span>
                                  <span>{item.attack_family}</span>
                                  <span>{item.input_slot}</span>
                                  <span>{item.auth_context}</span>
                                  <span className={`badge coverage-badge-${item.status}`}>
                                    {item.status}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                          {totalPages > 1 && (
                            <div className="pager">
                              <button
                                type="button"
                                className="pager-button"
                                disabled={page === 0}
                                onClick={() => setPage(host, page - 1)}
                              >
                                Prev
                              </button>
                              <span className="meta-text">
                                Page {page + 1} of {totalPages}
                              </span>
                              <button
                                type="button"
                                className="pager-button"
                                disabled={page >= totalPages - 1}
                                onClick={() => setPage(host, page + 1)}
                              >
                                Next
                              </button>
                            </div>
                          )}
                        </>
                      ) : (
                        <p className="meta-text" style={{ padding: "8px 0" }}>
                          No coverage items for this host.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="meta-text" style={{ marginTop: "8px" }}>
            No targets discovered yet.
          </p>
        )}
      </section>
    </>
  );
}
