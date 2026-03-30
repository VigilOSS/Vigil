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

export function CoverageTab({ summary, targets, services, coverageItems }: CoverageTabProps) {
  const [expandedTarget, setExpandedTarget] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);

  const coverageStatuses = summary?.coverage_statuses ?? {};
  const totalCoverage = Object.values(coverageStatuses).reduce((a, b) => a + b, 0);

  const servicesByTarget = useMemo(() => {
    const map = new Map<number, typeof services>();
    services.forEach((svc) => {
      const list = map.get(svc.target_id) ?? [];
      list.push(svc);
      map.set(svc.target_id, list);
    });
    return map;
  }, [services]);

  const filteredCoverage = useMemo(() => {
    if (!statusFilter) return coverageItems;
    return coverageItems.filter((item) => item.status === statusFilter);
  }, [coverageItems, statusFilter]);

  const statusKeys = useMemo(() => Object.keys(coverageStatuses), [coverageStatuses]);

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

      {/* Targets & services */}
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surface</h2>
          <p className="meta-text">{targets.length} target{targets.length !== 1 ? "s" : ""}, {services.length} service{services.length !== 1 ? "s" : ""}</p>
        </div>
        {targets.length > 0 ? (
          <div className="coverage-tree">
            {targets.map((target) => {
              const targetServices = servicesByTarget.get(target.id) ?? [];
              const isExpanded = expandedTarget === target.id;
              return (
                <div key={target.id} className="coverage-tree-node">
                  <button
                    type="button"
                    className="coverage-tree-header"
                    onClick={() => setExpandedTarget(isExpanded ? null : target.id)}
                  >
                    <span>{isExpanded ? "▾" : "▸"}</span>
                    <strong>{target.identity}</strong>
                    <span className="badge">{target.kind}</span>
                    {target.hostname && <span className="meta-text">{target.hostname}</span>}
                    {target.ip_address && <span className="meta-text">{target.ip_address}</span>}
                    <span className="meta-text" style={{ marginLeft: "auto" }}>
                      {targetServices.length} service{targetServices.length !== 1 ? "s" : ""}
                    </span>
                  </button>
                  {isExpanded && (
                    <div className="coverage-tree-children">
                      {targetServices.map((svc) => (
                        <div key={svc.id} className="service-row">
                          <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                            <strong>{svc.endpoint || `${svc.protocol}/${svc.port}`}</strong>
                            <span className={`badge coverage-badge-${svc.coverage_status}`}>{svc.coverage_status}</span>
                            {svc.service && <span className="meta-text">{svc.service}</span>}
                          </div>
                          {svc.banner && <p className="meta-text">{svc.banner}</p>}
                        </div>
                      ))}
                      {targetServices.length === 0 && (
                        <p className="meta-text" style={{ padding: "8px 0" }}>No services discovered for this target.</p>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="meta-text">No targets discovered yet.</p>
        )}
      </section>

      {/* Coverage items */}
      {coverageItems.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Coverage items</h2>
            <div className="filter-group" style={{ gap: "4px" }}>
              <button
                type="button"
                className={`filter-chip ${statusFilter === null ? "filter-active" : ""}`}
                onClick={() => setStatusFilter(null)}
              >
                All
              </button>
              {statusKeys.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`filter-chip ${statusFilter === s ? "filter-active" : ""}`}
                  onClick={() => setStatusFilter(statusFilter === s ? null : s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="coverage-items-grid">
            <div className="coverage-items-header">
              <span>Endpoint</span>
              <span>Attack family</span>
              <span>Input slot</span>
              <span>Auth</span>
              <span>Status</span>
            </div>
            {filteredCoverage.slice(0, 100).map((item) => (
              <div key={item.id} className="coverage-items-row">
                <span className="mono-text">
                  {item.method && item.canonical_url
                    ? `${item.method} ${item.canonical_url}`
                    : item.service_endpoint || "—"}
                </span>
                <span>{item.attack_family}</span>
                <span>{item.input_slot}</span>
                <span>{item.auth_context}</span>
                <span className={`badge coverage-badge-${item.status}`}>{item.status}</span>
              </div>
            ))}
            {filteredCoverage.length > 100 && (
              <p className="meta-text" style={{ padding: "8px" }}>
                Showing 100 of {filteredCoverage.length} items.
              </p>
            )}
          </div>
        </section>
      )}
    </>
  );
}
