import { useMemo, useState } from "react";
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

function uniqueSorted(values: (string | null | undefined)[]): string[] {
  const set = new Set<string>();
  for (const v of values) {
    if (v) set.add(v);
  }
  return Array.from(set).sort();
}

type HostGroup = {
  host: string;
  items: AssessmentCoverageItem[];
  serviceCount: number;
};

export function CoverageTab({
  summary,
  targets,
  services,
  coverageItems,
}: CoverageTabProps) {
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [pages, setPages] = useState<Record<string, number>>({});

  // Column filters
  const [methodFilter, setMethodFilter] = useState<string | null>(null);
  const [attackFamilyFilter, setAttackFamilyFilter] = useState<string | null>(null);
  const [inputSlotFilter, setInputSlotFilter] = useState<string | null>(null);
  const [authFilter, setAuthFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);

  const coverageStatuses = summary?.coverage_statuses ?? {};
  const totalCoverage = Object.values(coverageStatuses).reduce((a, b) => a + b, 0);
  const statusKeys = useMemo(() => Object.keys(coverageStatuses), [coverageStatuses]);

  // Build lookup: service_id → target host
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

  // Services count per host
  const serviceCountByHost = useMemo(() => {
    const counts = new Map<string, number>();
    for (const svc of services) {
      const host = serviceHostMap.get(svc.id) ?? "unknown";
      counts.set(host, (counts.get(host) ?? 0) + 1);
    }
    return counts;
  }, [services, serviceHostMap]);

  // Apply column filters
  const filteredItems = useMemo(() => {
    return coverageItems.filter((item) => {
      if (methodFilter && (item.method ?? "") !== methodFilter) return false;
      if (attackFamilyFilter && item.attack_family !== attackFamilyFilter) return false;
      if (inputSlotFilter && item.input_slot !== inputSlotFilter) return false;
      if (authFilter && item.auth_context !== authFilter) return false;
      if (statusFilter && item.status !== statusFilter) return false;
      return true;
    });
  }, [coverageItems, methodFilter, attackFamilyFilter, inputSlotFilter, authFilter, statusFilter]);

  // Group filtered items by host
  const hostGroups = useMemo(() => {
    const map = new Map<string, AssessmentCoverageItem[]>();

    for (const item of filteredItems) {
      let host = "unknown";
      if (item.service_id != null) {
        host = serviceHostMap.get(item.service_id) ?? "unknown";
      } else if (item.canonical_url) {
        host = extractHost(item.canonical_url);
      } else if (item.service_endpoint) {
        host = extractHost(item.service_endpoint);
      }
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
  }, [filteredItems, serviceHostMap, serviceCountByHost, targets]);

  // Unique values for filter dropdowns
  const allMethods = useMemo(() => uniqueSorted(coverageItems.map((i) => i.method)), [coverageItems]);
  const allAttackFamilies = useMemo(() => uniqueSorted(coverageItems.map((i) => i.attack_family)), [coverageItems]);
  const allInputSlots = useMemo(() => uniqueSorted(coverageItems.map((i) => i.input_slot)), [coverageItems]);
  const allAuthContexts = useMemo(() => uniqueSorted(coverageItems.map((i) => i.auth_context)), [coverageItems]);
  const allStatuses = useMemo(() => uniqueSorted(coverageItems.map((i) => i.status)), [coverageItems]);

  const hasAnyFilter = methodFilter || attackFamilyFilter || inputSlotFilter || authFilter || statusFilter;

  function getPage(host: string) { return pages[host] ?? 0; }
  function setPage(host: string, page: number) { setPages((p) => ({ ...p, [host]: page })); }

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
      </section>

      {/* Unified attack surface */}
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surface</h2>
          <p className="meta-text">
            {targets.length} host{targets.length !== 1 ? "s" : ""}, {filteredItems.length}{hasAnyFilter ? ` of ${coverageItems.length}` : ""} item{filteredItems.length !== 1 ? "s" : ""}
          </p>
        </div>

        {/* Column filters */}
        {coverageItems.length > 0 && (
          <div className="coverage-filters">
            <FilterSelect label="Method" value={methodFilter} options={allMethods} onChange={setMethodFilter} />
            <FilterSelect label="Attack family" value={attackFamilyFilter} options={allAttackFamilies} onChange={setAttackFamilyFilter} />
            <FilterSelect label="Input slot" value={inputSlotFilter} options={allInputSlots} onChange={setInputSlotFilter} />
            <FilterSelect label="Auth" value={authFilter} options={allAuthContexts} onChange={setAuthFilter} />
            <FilterSelect label="Status" value={statusFilter} options={allStatuses} onChange={setStatusFilter} />
            {hasAnyFilter && (
              <button
                type="button"
                className="filter-chip filter-active"
                onClick={() => { setMethodFilter(null); setAttackFamilyFilter(null); setInputSlotFilter(null); setAuthFilter(null); setStatusFilter(null); }}
              >
                Clear all
              </button>
            )}
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
                    onClick={() => { setExpandedHost(isExpanded ? null : host); }}
                  >
                    <span>{isExpanded ? "▾" : "▸"}</span>
                    <strong>{host}</strong>
                    <span className="meta-text">
                      {items.length} item{items.length !== 1 ? "s" : ""}
                      {serviceCount > 0 ? `, ${serviceCount} service${serviceCount !== 1 ? "s" : ""}` : ""}
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
                                <div key={item.id} className="coverage-items-row coverage-items-6col">
                                  <span className="mono-text">{method || "—"}</span>
                                  <span className="mono-text" title={item.canonical_url || item.service_endpoint || ""}>{endpoint}</span>
                                  <span>{item.attack_family}</span>
                                  <span>{item.input_slot}</span>
                                  <span>{item.auth_context}</span>
                                  <span className={`badge coverage-badge-${item.status}`}>{item.status}</span>
                                </div>
                              );
                            })}
                          </div>
                          {totalPages > 1 && (
                            <div className="pager">
                              <button type="button" className="pager-button" disabled={page === 0} onClick={() => setPage(host, page - 1)}>Prev</button>
                              <span className="meta-text">Page {page + 1} of {totalPages}</span>
                              <button type="button" className="pager-button" disabled={page >= totalPages - 1} onClick={() => setPage(host, page + 1)}>Next</button>
                            </div>
                          )}
                        </>
                      ) : (
                        <p className="meta-text" style={{ padding: "8px 0" }}>No coverage items for this host.</p>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="meta-text" style={{ marginTop: "8px" }}>No targets discovered yet.</p>
        )}
      </section>
    </>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string | null;
  options: string[];
  onChange: (value: string | null) => void;
}) {
  if (options.length === 0) return null;
  return (
    <div className="filter-select-group">
      <label className="filter-label">{label}</label>
      <select
        className="filter-select"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || null)}
      >
        <option value="">All</option>
        {options.map((opt) => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
    </div>
  );
}
