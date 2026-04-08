import { useEffect, useMemo, useState } from "react";
import type {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentFindingTransition,
  FindingDetails,
} from "../lib/api";
import { listAssessmentFindingTransitions } from "../lib/api";

type FindingsTabProps = {
  engagementKey: string;
  findings: (AssessmentFindingDetail | AssessmentFinding)[];
  fallbackFindings: AssessmentFinding[];
  chains: AssessmentAttackChainDetail[];
  chainLinks: AssessmentAttackChainLink[];
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function isDetail(finding: AssessmentFinding | AssessmentFindingDetail): finding is AssessmentFindingDetail {
  return "id" in finding;
}

function parseDetails(finding: AssessmentFinding | AssessmentFindingDetail): FindingDetails {
  if (!isDetail(finding)) return {};
  try {
    return JSON.parse(finding.details_json || "{}");
  } catch {
    return {};
  }
}

function sortFindings(findings: (AssessmentFindingDetail | AssessmentFinding)[]) {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

function workflowLabel(finding: AssessmentFinding | AssessmentFindingDetail) {
  switch (finding.workflow_status) {
    case "reported":
      return "Included in report";
    case "merged":
      return isDetail(finding) && finding.merged_into_slug ? `Merged into ${finding.merged_into_slug}` : "Merged duplicate";
    case "active":
      return "Active";
    case "exploited":
      return "Exploited";
    case "blocked":
      return "Blocked";
    case "false_positive":
      return "Suppressed";
    default:
      return finding.workflow_status;
  }
}

function verificationKey(finding: AssessmentFinding | AssessmentFindingDetail) {
  if (finding.verification_state === "disputed") return "disputed";
  if (finding.verification_disposition !== "none") return finding.verification_disposition;
  return finding.verification_state;
}

function verificationLabel(finding: AssessmentFinding | AssessmentFindingDetail) {
  switch (verificationKey(finding)) {
    case "confirmed":
      return "Verified";
    case "downgraded":
      return "Downgraded";
    case "false_positive":
      return "False positive";
    case "disputed":
      return "Disputed";
    default:
      return "Unreviewed";
  }
}

function rowMeta(finding: AssessmentFinding | AssessmentFindingDetail) {
  const parts = [];
  if (finding.source_name) {
    parts.push(finding.source_name);
  }
  parts.push(verificationLabel(finding));
  if (finding.workflow_status !== "active") {
    parts.push(workflowLabel(finding));
  }
  return parts.join(" · ");
}

const FINDINGS_PAGE_SIZE = 50;

export function FindingsTab({
  engagementKey,
  findings,
  fallbackFindings,
  chains,
  chainLinks,
}: FindingsTabProps) {
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [workflowFilter, setWorkflowFilter] = useState<string | null>(null);
  const [verificationFilter, setVerificationFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [transitions, setTransitions] = useState<AssessmentFindingTransition[]>([]);
  const [transitionsLoading, setTransitionsLoading] = useState(false);
  const [transitionsError, setTransitionsError] = useState<string | null>(null);

  const allFindings = findings.length > 0 ? findings : fallbackFindings;

  useEffect(() => {
    if (!selected) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelected(null);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selected]);

  useEffect(() => {
    if (!selected) {
      setTransitions([]);
      setTransitionsLoading(false);
      setTransitionsError(null);
      return;
    }

    let cancelled = false;
    setTransitionsLoading(true);
    setTransitionsError(null);
    listAssessmentFindingTransitions(engagementKey, selected)
      .then((rows) => {
        if (cancelled) return;
        setTransitions(rows);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setTransitions([]);
        setTransitionsError(error instanceof Error ? error.message : "Failed to load transition history");
      })
      .finally(() => {
        if (!cancelled) setTransitionsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [engagementKey, selected]);

  const severities = useMemo(() => {
    const set = new Set(allFindings.map((finding) => finding.severity));
    return SEVERITY_ORDER.filter((severity) => set.has(severity));
  }, [allFindings]);

  const workflowStatuses = useMemo(() => {
    const set = new Set<string>();
    allFindings.forEach((finding) => set.add(finding.workflow_status));
    return Array.from(set);
  }, [allFindings]);

  const verificationStatuses = useMemo(() => {
    const set = new Set<string>();
    allFindings.forEach((finding) => set.add(verificationKey(finding)));
    return Array.from(set);
  }, [allFindings]);

  const workflowCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of allFindings) {
      counts[finding.workflow_status] = (counts[finding.workflow_status] ?? 0) + 1;
    }
    return counts;
  }, [allFindings]);

  const verificationCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of allFindings) {
      const key = verificationKey(finding);
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return counts;
  }, [allFindings]);

  const filtered = useMemo(() => {
    setPage(0);
    const visible = allFindings.filter((finding) => {
      if (severityFilter && finding.severity !== severityFilter) return false;
      if (workflowFilter && finding.workflow_status !== workflowFilter) return false;
      if (verificationFilter && verificationKey(finding) !== verificationFilter) return false;
      return true;
    });
    return sortFindings(visible);
  }, [allFindings, severityFilter, workflowFilter, verificationFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / FINDINGS_PAGE_SIZE));
  const pageFindings = filtered.slice(page * FINDINGS_PAGE_SIZE, (page + 1) * FINDINGS_PAGE_SIZE);

  const selectedFinding = useMemo(
    () => allFindings.find((finding) => finding.slug === selected) ?? null,
    [allFindings, selected],
  );

  const details = selectedFinding ? parseDetails(selectedFinding) : {};

  const findingLinkMatches = useMemo(() => {
    const findingIdToSlug = new Map<number, string>();
    for (const f of allFindings) {
      if (isDetail(f)) findingIdToSlug.set(f.id, f.slug);
    }
    return (link: { entity_kind: string; entity_ref: string; entity_id: number | null }) => {
      if (link.entity_kind !== "finding") return null;
      if (link.entity_ref) return link.entity_ref;
      if (link.entity_id != null) return findingIdToSlug.get(link.entity_id) ?? null;
      return null;
    };
  }, [allFindings]);

  const selectedChains = useMemo(() => {
    if (!selectedFinding) return [];
    const linkedChainKeys = chainLinks
      .filter((link) => findingLinkMatches(link) === selectedFinding.slug)
      .map((link) => link.chain_key);
    return chains.filter((chain) => linkedChainKeys.includes(chain.chain_key));
  }, [selectedFinding, chains, chainLinks, findingLinkMatches]);

  const findingChainCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const link of chainLinks) {
      const slug = findingLinkMatches(link);
      if (slug) counts[slug] = (counts[slug] ?? 0) + 1;
    }
    return counts;
  }, [chainLinks, findingLinkMatches]);

  return (
    <>
      <section className="panel filter-bar-panel">
        <div className="filter-bar">
          <div className="filter-group">
            <span className="filter-label">Severity</span>
            {severities.map((severity) => (
              <button
                key={severity}
                type="button"
                className={`filter-chip severity-${severity} ${severityFilter === severity ? "filter-active" : ""}`}
                onClick={() => setSeverityFilter(severityFilter === severity ? null : severity)}
              >
                {severity}
              </button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-label">Workflow</span>
            {workflowStatuses.map((status) => (
              <button
                key={status}
                type="button"
                className={`filter-chip ${workflowFilter === status ? "filter-active" : ""}`}
                onClick={() => setWorkflowFilter(workflowFilter === status ? null : status)}
              >
                {status}
                <span className="filter-count">{workflowCounts[status] ?? 0}</span>
              </button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-label">Verification</span>
            {verificationStatuses.map((status) => (
              <button
                key={status}
                type="button"
                className={`filter-chip ${verificationFilter === status ? "filter-active" : ""}`}
                onClick={() => setVerificationFilter(verificationFilter === status ? null : status)}
              >
                {status}
                <span className="filter-count">{verificationCounts[status] ?? 0}</span>
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="findings-layout">
        <div className="findings-list">
          {pageFindings.map((finding) => (
            <button
              key={finding.slug}
              type="button"
              className={`finding-row ${finding.workflow_status === "false_positive" ? "finding-row-suppressed" : ""} ${selected === finding.slug ? "finding-row-active" : ""}`}
              onClick={() => setSelected(finding.slug)}
            >
              <div className="finding-row-main">
                <strong className="finding-row-title">{finding.title}</strong>
                <p className="meta-text">{rowMeta(finding) || finding.slug}</p>
              </div>
              <div className="finding-row-aside">
                {(findingChainCounts[finding.slug] ?? 0) > 0 && (
                  <span className="badge" title="Attack chains">{findingChainCounts[finding.slug]} chain{findingChainCounts[finding.slug] !== 1 ? "s" : ""}</span>
                )}
                <span className={`badge severity-${finding.severity}`}>{finding.severity}</span>
                <span className={`badge status-${finding.workflow_status}`}>{finding.workflow_status}</span>
                <span className={`badge status-${verificationKey(finding)}`}>{verificationLabel(finding)}</span>
              </div>
            </button>
          ))}
          {filtered.length === 0 && (
            <p className="empty-state" style={{ padding: "20px" }}>
              {allFindings.length === 0 ? "No findings recorded yet." : "No findings match the current filters."}
            </p>
          )}
        </div>
        {totalPages > 1 && (
          <div className="pager">
            <button type="button" className="pager-button" disabled={page === 0} onClick={() => setPage(page - 1)}>Prev</button>
            <span className="meta-text">Page {page + 1} of {totalPages} ({filtered.length} findings)</span>
            <button type="button" className="pager-button" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        )}
      </section>

      {selectedFinding && (
        <div className="finding-overlay" role="presentation" onClick={() => setSelected(null)}>
          <article className="finding-modal panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="finding-modal-header">
              <div className="finding-modal-heading">
                <h2>{selectedFinding.title}</h2>
                <p className="meta-text">{selectedFinding.slug}</p>
              </div>
              <div className="finding-modal-actions">
                <span className={`badge severity-${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                <span className={`badge status-${selectedFinding.workflow_status}`}>{selectedFinding.workflow_status}</span>
                <span className={`badge status-${verificationKey(selectedFinding)}`}>{verificationLabel(selectedFinding)}</span>
                <button type="button" className="ghost-button" onClick={() => setSelected(null)}>Close</button>
              </div>
            </div>

            <div className="finding-modal-content">
              {selectedFinding.summary && (
                <div>
                  <p className="eyebrow">Summary</p>
                  <p>{selectedFinding.summary}</p>
                </div>
              )}

              {selectedFinding.canonical_location && (
                <div>
                  <p className="eyebrow">Location</p>
                  <p className="meta-text finding-mono">{selectedFinding.canonical_location}</p>
                </div>
              )}

              <div className="finding-meta-grid">
                <div>
                  <p className="eyebrow">Workflow</p>
                  <p>{workflowLabel(selectedFinding)}</p>
                </div>
                <div>
                  <p className="eyebrow">Verification</p>
                  <p>{verificationLabel(selectedFinding)}</p>
                </div>
                {selectedFinding.source_name && (
                  <div>
                    <p className="eyebrow">Source</p>
                    <p>{selectedFinding.source_name}</p>
                  </div>
                )}
                {details.discovered_by && (
                  <div>
                    <p className="eyebrow">Discovered by</p>
                    <p>{details.discovered_by}</p>
                  </div>
                )}
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
                    <p className="finding-mono">{selectedFinding.root_cause_key}</p>
                  </div>
                )}
                {details.parameter && (
                  <div>
                    <p className="eyebrow">Parameter</p>
                    <p>{details.parameter}</p>
                  </div>
                )}
                {details.owasp_category && (
                  <div>
                    <p className="eyebrow">OWASP</p>
                    <p>{details.owasp_category}</p>
                  </div>
                )}
                {details.cwe_id && (
                  <div>
                    <p className="eyebrow">CWE</p>
                    <p>{details.cwe_id}</p>
                  </div>
                )}
                {details.request_method && (
                  <div>
                    <p className="eyebrow">Method</p>
                    <p>{details.request_method}</p>
                  </div>
                )}
                {details.cvss_vector && (
                  <div>
                    <p className="eyebrow">CVSS</p>
                    <p className="finding-mono">
                      {details.cvss_vector}
                      {details.cvss_score != null ? ` (${details.cvss_score})` : ""}
                    </p>
                  </div>
                )}
                {isDetail(selectedFinding) && selectedFinding.merged_into_slug && (
                  <div>
                    <p className="eyebrow">Merged into</p>
                    <p className="finding-mono">{selectedFinding.merged_into_slug}</p>
                  </div>
                )}
              </div>

              {details.impact && (
                <div>
                  <p className="eyebrow">Impact</p>
                  <p>{details.impact}</p>
                </div>
              )}

              {details.kill_reason && (
                <div>
                  <p className="eyebrow">Kill reason</p>
                  <p>
                    {details.kill_check != null ? `Check ${details.kill_check}: ` : ""}
                    {details.kill_reason}
                  </p>
                </div>
              )}

              {details.remediation && (
                <div>
                  <p className="eyebrow">Remediation</p>
                  <p>{details.remediation}</p>
                </div>
              )}

              {details.evidence && (
                <div>
                  <p className="eyebrow">Evidence detail</p>
                  <p>{details.evidence}</p>
                </div>
              )}

              {details.steps_to_reproduce && details.steps_to_reproduce.length > 0 && (
                <div>
                  <p className="eyebrow">Steps to reproduce</p>
                  <ol className="finding-steps">
                    {details.steps_to_reproduce.map((step, index) => (
                      <li key={index}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}

              <div>
                <p className="eyebrow">Transition history</p>
                {transitionsLoading && <p className="meta-text">Loading transition history…</p>}
                {transitionsError && <p className="meta-text">{transitionsError}</p>}
                {!transitionsLoading && !transitionsError && transitions.length === 0 && (
                  <p className="meta-text">No transition history recorded yet.</p>
                )}
                {!transitionsLoading && !transitionsError && transitions.length > 0 && (
                  <div className="finding-transitions">
                    {transitions.map((transition) => (
                      <div key={transition.id} className="finding-transition-row">
                        <div className="finding-transition-header">
                          <strong>{transition.action}</strong>
                          <span className="meta-text">{transition.actor || "system"}</span>
                          <span className="meta-text">{transition.created_at}</span>
                        </div>
                        <p className="meta-text">
                          Workflow: {transition.from_workflow_status ?? "none"} → {transition.to_workflow_status}
                          {" · "}
                          Verification: {transition.from_verification_state ?? "none"} / {transition.from_verification_disposition ?? "none"}
                          {" → "}
                          {transition.to_verification_state} / {transition.to_verification_disposition}
                        </p>
                        {(transition.from_severity || transition.to_severity) && (
                          <p className="meta-text">
                            Severity: {transition.from_severity ?? "none"} → {transition.to_severity}
                          </p>
                        )}
                        {transition.reason_text && <p>{transition.reason_text}</p>}
                        {transition.artifact_ref && (
                          <p className="meta-text finding-mono">{transition.artifact_ref}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {selectedChains.length > 0 && (
                <div>
                  <p className="eyebrow">Attack chains</p>
                  <div style={{ display: "grid", gap: "8px", marginTop: "4px" }}>
                    {selectedChains.map((chain) => (
                      <div key={chain.chain_key} style={{ display: "grid", gap: "2px" }}>
                        <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                          <span className={`badge severity-${chain.severity}`}>{chain.severity}</span>
                          <strong>{chain.title}</strong>
                          <span className="meta-text">{chain.status}</span>
                        </div>
                        {chain.narrative && <p className="meta-text">{chain.narrative}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {isDetail(selectedFinding) && selectedFinding.notes && (
                <div>
                  <p className="eyebrow">Notes</p>
                  <pre className="finding-notes">{selectedFinding.notes}</pre>
                </div>
              )}

              {isDetail(selectedFinding) && selectedFinding.evidence_ref && (
                <div>
                  <p className="eyebrow">Evidence reference</p>
                  <p className="meta-text finding-mono">{selectedFinding.evidence_ref}</p>
                </div>
              )}
            </div>
          </article>
        </div>
      )}
    </>
  );
}
