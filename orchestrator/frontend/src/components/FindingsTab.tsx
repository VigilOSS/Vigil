import { useMemo, useState } from "react";
import type { AssessmentFinding, AssessmentFindingDetail, AssessmentSummary, FindingDetails } from "../lib/api";

type FindingsTabProps = {
  findings: AssessmentFindingDetail[];
  fallbackFindings: AssessmentFinding[];
  summary: AssessmentSummary | null;
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function isDetail(f: AssessmentFinding | AssessmentFindingDetail): f is AssessmentFindingDetail {
  return "id" in f;
}

function parseDetails(f: AssessmentFindingDetail): FindingDetails {
  try {
    return JSON.parse(f.details_json || "{}");
  } catch {
    return {};
  }
}

export function FindingsTab({ findings, fallbackFindings, summary }: FindingsTabProps) {
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const allFindings = findings.length > 0 ? findings : fallbackFindings;

  const severities = useMemo(() => {
    const set = new Set(allFindings.map((f) => f.severity));
    return SEVERITY_ORDER.filter((s) => set.has(s));
  }, [allFindings]);

  const statuses = useMemo(() => {
    const set = new Set<string>();
    allFindings.forEach((f) => set.add(f.status));
    return Array.from(set);
  }, [allFindings]);

  const filtered = useMemo(() => {
    return allFindings.filter((f) => {
      if (severityFilter && f.severity !== severityFilter) return false;
      if (statusFilter && f.status !== statusFilter) return false;
      return true;
    });
  }, [allFindings, severityFilter, statusFilter]);

  const selectedFinding = useMemo(
    () => allFindings.find((f) => f.slug === selected) ?? null,
    [allFindings, selected],
  );

  const statusCounts = summary?.finding_statuses ?? {};

  return (
    <>
      {/* Filter bar */}
      <section className="panel filter-bar-panel">
        <div className="filter-bar">
          <div className="filter-group">
            <span className="filter-label">Severity</span>
            {severities.map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip severity-${s} ${severityFilter === s ? "filter-active" : ""}`}
                onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
              >
                {s}
              </button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-label">Status</span>
            {statuses.map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip ${statusFilter === s ? "filter-active" : ""}`}
                onClick={() => setStatusFilter(statusFilter === s ? null : s)}
              >
                {s}
                {statusCounts[s] != null && <span className="filter-count">{statusCounts[s]}</span>}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Findings list + detail */}
      <section className="findings-layout">
        <div className="findings-list">
          {filtered.map((f) => (
            <button
              key={f.slug}
              type="button"
              className={`finding-row ${selected === f.slug ? "finding-row-active" : ""}`}
              onClick={() => setSelected(selected === f.slug ? null : f.slug)}
            >
              <span className={`badge severity-${f.severity}`}>{f.severity}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <strong>{f.title}</strong>
                <p className="meta-text">{f.status}{f.source_name ? ` · ${f.source_name}` : ""}</p>
              </div>
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="empty-state" style={{ padding: "20px" }}>
              {allFindings.length === 0 ? "No findings recorded yet." : "No findings match the current filters."}
            </p>
          )}
        </div>

        <div className="finding-detail panel">
          {selectedFinding ? (
            <div style={{ display: "grid", gap: "16px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap", marginBottom: "8px" }}>
                  <span className={`badge severity-${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                  <span className={`badge status-${selectedFinding.status}`}>{selectedFinding.status}</span>
                </div>
                <h2 style={{ margin: 0 }}>{selectedFinding.title}</h2>
              </div>

              {selectedFinding.summary && (
                <div>
                  <p className="eyebrow">Summary</p>
                  <p>{selectedFinding.summary}</p>
                </div>
              )}

              {selectedFinding.canonical_location && (
                <div>
                  <p className="eyebrow">Location</p>
                  <p className="meta-text" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                    {selectedFinding.canonical_location}
                  </p>
                </div>
              )}

              <div className="finding-meta-grid">
                {isDetail(selectedFinding) && selectedFinding.defect_family && (
                  <div>
                    <p className="eyebrow">Defect family</p>
                    <p>{selectedFinding.defect_family}</p>
                  </div>
                )}
                {isDetail(selectedFinding) && selectedFinding.auth_context && (
                  <div>
                    <p className="eyebrow">Auth context</p>
                    <p>{selectedFinding.auth_context}</p>
                  </div>
                )}
                {isDetail(selectedFinding) && selectedFinding.root_cause_key && (
                  <div>
                    <p className="eyebrow">Root cause</p>
                    <p style={{ fontFamily: "'IBM Plex Mono', monospace" }}>{selectedFinding.root_cause_key}</p>
                  </div>
                )}
                {selectedFinding.source_name && (
                  <div>
                    <p className="eyebrow">Source</p>
                    <p>{selectedFinding.source_name}</p>
                  </div>
                )}
                {isDetail(selectedFinding) && (() => {
                  const d = parseDetails(selectedFinding);
                  return (
                    <>
                      {d.owasp_category && (
                        <div>
                          <p className="eyebrow">OWASP</p>
                          <p>{d.owasp_category}</p>
                        </div>
                      )}
                      {d.cwe_id && (
                        <div>
                          <p className="eyebrow">CWE</p>
                          <p>{d.cwe_id}</p>
                        </div>
                      )}
                      {d.request_method && (
                        <div>
                          <p className="eyebrow">Method</p>
                          <p>{d.request_method}</p>
                        </div>
                      )}
                      {d.cvss_vector && (
                        <div>
                          <p className="eyebrow">CVSS</p>
                          <p style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                            {d.cvss_vector}{d.cvss_score != null ? ` (${d.cvss_score})` : ""}
                          </p>
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>

              {isDetail(selectedFinding) && (() => {
                const d = parseDetails(selectedFinding);
                return (
                  <>
                    {d.impact && (
                      <div>
                        <p className="eyebrow">Impact</p>
                        <p>{d.impact}</p>
                      </div>
                    )}
                    {d.remediation && (
                      <div>
                        <p className="eyebrow">Remediation</p>
                        <p>{d.remediation}</p>
                      </div>
                    )}
                    {d.steps_to_reproduce && d.steps_to_reproduce.length > 0 && (
                      <div>
                        <p className="eyebrow">Steps to reproduce</p>
                        <ol style={{ margin: 0, paddingLeft: "20px" }}>
                          {d.steps_to_reproduce.map((step, i) => (
                            <li key={i} style={{ marginBottom: "4px" }}>{step}</li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </>
                );
              })()}

              {isDetail(selectedFinding) && selectedFinding.notes && (
                <div>
                  <p className="eyebrow">Notes</p>
                  <pre className="finding-notes">{selectedFinding.notes}</pre>
                </div>
              )}

              {isDetail(selectedFinding) && selectedFinding.evidence_ref && (
                <div>
                  <p className="eyebrow">Evidence</p>
                  <p className="meta-text" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                    {selectedFinding.evidence_ref}
                  </p>
                </div>
              )}
            </div>
          ) : (
            <p className="empty-state">Select a finding to view details.</p>
          )}
        </div>
      </section>
    </>
  );
}
