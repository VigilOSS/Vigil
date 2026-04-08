import { useMemo, useState } from "react";

import type {
  CodeAnalysisResult,
  CodeCoverage,
  CodeModule,
  CodeQueueStats,
  CodeRepo,
} from "../lib/api";

// ── Phase pipeline ──────────────────────────────────────

const CODE_PHASES = [
  { key: "ingest", label: "Ingest + Index" },
  { key: "classify", label: "Classify + Map" },
  { key: "hunt", label: "Hunt" },
  { key: "verify", label: "Verify + Variant" },
] as const;

type PhaseKey = (typeof CODE_PHASES)[number]["key"];

const STATUS_TO_PHASE: Record<string, PhaseKey> = {
  ingested: "ingest",
  classified: "classify",
  context_built: "classify",
  queued: "hunt",
  in_progress: "hunt",
  analyzed: "verify",
  variant_done: "verify",
  verified: "verify",
  complete: "verify",
};

function resolvePhase(repos: CodeRepo[], queueStats: CodeQueueStats | null, coverage: CodeCoverage | null): PhaseKey {
  if (repos.length === 0) return "ingest";
  // Use the most advanced repo status
  let best: PhaseKey = "ingest";
  const order: PhaseKey[] = ["ingest", "classify", "hunt", "verify"];
  for (const repo of repos) {
    const phase = STATUS_TO_PHASE[repo.analysis_status] ?? "ingest";
    if (order.indexOf(phase) > order.indexOf(best)) best = phase;
  }
  // If queue has active items, we're in hunt
  if (queueStats && (queueStats.processing > 0 || queueStats.pending > 0) && order.indexOf(best) < order.indexOf("hunt")) {
    best = "hunt";
  }
  // If coverage gate is failing, stay in hunt (Phase 2B) rather than
  // advancing to verify — effort thresholds may still need re-dispatch.
  if (coverage && !coverage.gate.passed && order.indexOf(best) >= order.indexOf("verify")) {
    best = "hunt";
  }
  return best;
}

function phaseState(phase: PhaseKey, current: PhaseKey): "completed" | "active" | "pending" {
  const order: PhaseKey[] = ["ingest", "classify", "hunt", "verify"];
  const pi = order.indexOf(phase);
  const ci = order.indexOf(current);
  if (pi < ci) return "completed";
  if (pi === ci) return "active";
  return "pending";
}

// ── Main component ──────────────────────────────────────

type CodeAnalysisTabProps = {
  repos: CodeRepo[];
  modules: CodeModule[];
  queueStats: CodeQueueStats | null;
  coverage: CodeCoverage | null;
  results: CodeAnalysisResult[];
};

const DISPOSITION_ORDER = ["finding", "suspicious", "needs_context", "clean"];

export function CodeAnalysisTab({
  repos,
  modules,
  queueStats,
  coverage,
  results,
}: CodeAnalysisTabProps) {
  const currentPhase = resolvePhase(repos, queueStats, coverage);
  const [expandedModules, setExpandedModules] = useState<Set<number>>(new Set());
  const [resultFilter, setResultFilter] = useState<string>("all");
  const [resultPage, setResultPage] = useState(0);

  const filteredResults = useMemo(() => {
    const sorted = [...results].sort((a, b) => {
      const ai = DISPOSITION_ORDER.indexOf(a.disposition);
      const bi = DISPOSITION_ORDER.indexOf(b.disposition);
      // Unknown dispositions sort after all known ones
      const da = ai === -1 ? DISPOSITION_ORDER.length : ai;
      const db = bi === -1 ? DISPOSITION_ORDER.length : bi;
      if (da !== db) return da - db;
      return b.id - a.id;
    });
    if (resultFilter === "all") return sorted;
    return sorted.filter((r) => r.disposition === resultFilter);
  }, [results, resultFilter]);

  const PAGE_SIZE = 25;
  const totalResultPages = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const pageResults = filteredResults.slice(resultPage * PAGE_SIZE, (resultPage + 1) * PAGE_SIZE);

  const dispositionCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const r of results) {
      counts[r.disposition] = (counts[r.disposition] ?? 0) + 1;
    }
    return counts;
  }, [results]);

  const hasData = repos.length > 0;

  if (!hasData) {
    return (
      <section className="panel">
        <p className="meta-text">
          No code repositories ingested yet. Run <code>assess.py code-ingest</code> to start code analysis.
        </p>
      </section>
    );
  }

  return (
    <>
      {/* Phase pipeline */}
      <section className="panel">
        <div className="panel-header">
          <h2>Code Analysis Pipeline</h2>
        </div>
        <div className="code-phase-pipeline">
          {CODE_PHASES.map((phase) => {
            const state = phaseState(phase.key, currentPhase);
            return (
              <div key={phase.key} className={`code-phase-step code-phase-${state}`}>
                <div className="code-phase-indicator">
                  {state === "completed" ? "\u2713" : state === "active" ? "\u25CF" : "\u25CB"}
                </div>
                <span className="code-phase-label">{phase.label}</span>
              </div>
            );
          })}
        </div>
      </section>

      {/* Repository overview */}
      <section className="panel">
        <div className="panel-header">
          <h2>Repositories</h2>
        </div>
        <div className="code-repos-grid">
          {repos.map((repo) => (
            <article key={repo.id} className="code-repo-card">
              <div className="code-repo-header">
                <strong>{repo.name}</strong>
                <span className={`badge code-status-${repo.analysis_status}`}>
                  {repo.analysis_status.replace(/_/g, " ")}
                </span>
              </div>
              <div className="code-repo-stats">
                <div className="code-repo-stat">
                  <span className="code-repo-stat-value">{repo.analyzable_files.toLocaleString()}</span>
                  <span className="meta-text">files</span>
                </div>
                <div className="code-repo-stat">
                  <span className="code-repo-stat-value">{repo.total_loc.toLocaleString()}</span>
                  <span className="meta-text">LOC</span>
                </div>
                <div className="code-repo-stat">
                  <span className="code-repo-stat-value">{repo.language || "mixed"}</span>
                  <span className="meta-text">language</span>
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* Queue + coverage stats */}
      <section className="panel">
        <div className="panel-header">
          <h2>Analysis Progress</h2>
        </div>
        <div className="stats-grid code-stats-grid">
          <article className="stat-card">
            <span className="stat-value">{queueStats?.total ?? 0}</span>
            <span className="meta-text">Queue items</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{queueStats?.done ?? 0}</span>
            <span className="meta-text">Completed</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{queueStats?.processing ?? 0}</span>
            <span className="meta-text">Processing</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{queueStats?.pending ?? 0}</span>
            <span className="meta-text">Pending</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{queueStats?.needs_context ?? 0}</span>
            <span className="meta-text">Needs context</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{queueStats?.error ?? 0}</span>
            <span className="meta-text">Errors</span>
          </article>
        </div>

        {/* Queue progress bar */}
        {queueStats && queueStats.total > 0 && (
          <div className="code-queue-bar-wrap">
            <div className="coverage-bar">
              <div
                className="coverage-segment code-segment-done"
                style={{ width: `${(queueStats.done / queueStats.total) * 100}%` }}
              />
              <div
                className="coverage-segment code-segment-processing"
                style={{ width: `${(queueStats.processing / queueStats.total) * 100}%` }}
              />
              <div
                className="coverage-segment code-segment-needs-context"
                style={{ width: `${(queueStats.needs_context / queueStats.total) * 100}%` }}
              />
              <div
                className="coverage-segment code-segment-error"
                style={{ width: `${(queueStats.error / queueStats.total) * 100}%` }}
              />
            </div>
            <div className="coverage-legend">
              <span className="coverage-legend-item"><span className="coverage-dot code-dot-done" /> Done</span>
              <span className="coverage-legend-item"><span className="coverage-dot code-dot-processing" /> Processing</span>
              <span className="coverage-legend-item"><span className="coverage-dot code-dot-needs-context" /> Needs ctx</span>
              <span className="coverage-legend-item"><span className="coverage-dot code-dot-error" /> Error</span>
              <span className="coverage-legend-item"><span className="coverage-dot code-dot-pending" /> Pending</span>
            </div>
          </div>
        )}
      </section>

      {/* File classification + coverage */}
      {coverage && (
        <section className="engagement-grid">
          <article className="panel">
            <p className="eyebrow">File Classification</p>
            <div className="code-classification-grid">
              {["critical", "high", "medium", "low", "skip"].map((cls) => {
                const data = coverage.by_classification[cls];
                if (!data) return null;
                return (
                  <div key={cls} className="code-classification-row">
                    <span className={`badge severity-${cls === "skip" ? "info" : cls}`}>{cls}</span>
                    <span className="code-classification-count">{data.count}</span>
                    <span className="meta-text">
                      {data.analyzed}/{data.count} analyzed
                    </span>
                  </div>
                );
              })}
              {coverage.by_status.unclassified > 0 && (
                <div className="code-classification-row">
                  <span className="badge">unclassified</span>
                  <span className="code-classification-count">{coverage.by_status.unclassified}</span>
                  <span className="meta-text">awaiting Phase 1</span>
                </div>
              )}
            </div>

          </article>

          <article className="panel">
            <p className="eyebrow">Coverage Gate</p>
            <div className="code-gate-status">
              <span className={`code-gate-badge ${coverage.gate.passed ? "code-gate-pass" : "code-gate-fail"}`}>
                {coverage.gate.passed ? "PASS" : "FAIL"}
              </span>
              {coverage.gate.reasons.length > 0 && (
                <ul className="code-gate-reasons">
                  {coverage.gate.reasons.map((reason, i) => (
                    <li key={i} className="meta-text">{reason}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Confidence metrics */}
            <div className="code-confidence">
              <p className="eyebrow" style={{ marginTop: "16px" }}>Confidence</p>
              <div className="code-fn-stats">
                <span>Critical: {coverage.confidence.critical_coverage_pct.toFixed(0)}%</span>
                <span>High: {coverage.confidence.high_coverage_pct.toFixed(0)}%</span>
                <span>LOC analyzed: {coverage.confidence.overall_loc_analyzed.toLocaleString()}</span>
              </div>
            </div>

            {/* Findings summary */}
            {coverage.findings_summary.total_code_findings > 0 && (
              <div className="code-findings-summary">
                <p className="eyebrow" style={{ marginTop: "16px" }}>Code Findings</p>
                <div className="code-fn-stats">
                  <span>{coverage.findings_summary.total_code_findings} total</span>
                  {Object.entries(coverage.findings_summary.by_severity)
                    .filter(([, count]) => count > 0)
                    .map(([sev, count]) => (
                      <span key={sev} className={`badge severity-${sev}`}>{count} {sev}</span>
                    ))}
                  {coverage.findings_summary.variant_count > 0 && (
                    <span>{coverage.findings_summary.variant_count} variants</span>
                  )}
                </div>
              </div>
            )}
          </article>
        </section>
      )}

      {/* Modules */}
      {modules.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Modules</h2>
            <span className="meta-text">{modules.length} modules</span>
          </div>
          <div className="coverage-tree">
            {modules.map((mod) => {
              const isExpanded = expandedModules.has(mod.id);
              return (
                <div key={mod.id} className="coverage-tree-node">
                  <button
                    className="coverage-tree-header"
                    onClick={() => {
                      setExpandedModules((prev) => {
                        const next = new Set(prev);
                        if (next.has(mod.id)) next.delete(mod.id);
                        else next.add(mod.id);
                        return next;
                      });
                    }}
                  >
                    <span>{isExpanded ? "\u25BE" : "\u25B8"}</span>
                    <strong>{mod.name}</strong>
                    <span className="meta-text">{mod.file_count} files</span>
                    {mod.critical_file_count > 0 && (
                      <span className="badge severity-critical">{mod.critical_file_count} critical</span>
                    )}
                    <span className={`badge code-status-${mod.analysis_status}`}>
                      {mod.analysis_status}
                    </span>
                  </button>
                  {isExpanded && (
                    <div className="coverage-tree-children">
                      {mod.trust_boundary && (
                        <div className="code-module-detail">
                          <span className="meta-text">Trust boundary:</span> {mod.trust_boundary}
                        </div>
                      )}
                      {mod.description && (
                        <div className="code-module-detail">
                          <span className="meta-text">Description:</span> {mod.description}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Analysis results */}
      {results.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Analysis Results</h2>
            <span className="meta-text">{results.length} results</span>
          </div>

          {/* Filter chips */}
          <div className="filter-bar" style={{ marginBottom: "12px" }}>
            <span className="filter-label">Disposition</span>
            <div className="filter-group">
              <button
                className={`filter-chip ${resultFilter === "all" ? "filter-active" : ""}`}
                onClick={() => { setResultFilter("all"); setResultPage(0); }}
              >
                All <span className="filter-count">{results.length}</span>
              </button>
              {DISPOSITION_ORDER.map((disp) => {
                const count = dispositionCounts[disp] ?? 0;
                if (count === 0) return null;
                return (
                  <button
                    key={disp}
                    className={`filter-chip ${resultFilter === disp ? "filter-active" : ""}`}
                    onClick={() => { setResultFilter(disp); setResultPage(0); }}
                  >
                    {disp} <span className="filter-count">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Results list */}
          <div className="code-results-list">
            {pageResults.map((r) => (
              <article key={r.id} className={`code-result-row ${r.finding_status === "false_positive" ? "code-result-row-suppressed" : ""}`}>
                <div className="code-result-header">
                  <span className={`badge code-disposition-${r.disposition}`}>{r.disposition}</span>
                  <strong className="mono-text">{r.function_name || `file #${r.file_id}`}</strong>
                  {r.cwe_id && <span className="badge">{r.cwe_id}</span>}
                  <span className={`badge code-confidence-${r.confidence}`}>{r.confidence}</span>
                  <span className="meta-text">{r.agent_name}</span>
                </div>
                {r.hypothesis && (
                  <div className="code-result-detail">
                    <span className="code-result-label">Hypothesis:</span>
                    <span>{r.hypothesis.length > 200 ? `${r.hypothesis.slice(0, 200)}...` : r.hypothesis}</span>
                  </div>
                )}
                {r.evidence && (
                  <div className="code-result-detail">
                    <span className="code-result-label">Evidence:</span>
                    <span>{r.evidence.length > 200 ? `${r.evidence.slice(0, 200)}...` : r.evidence}</span>
                  </div>
                )}
                {r.finding_slug && (
                  <div className="code-result-detail">
                    <span className="code-result-label">Finding:</span>
                    <span className="mono-text">{r.finding_slug}</span>
                    {r.finding_status && <span className={`badge status-${r.finding_status}`}>{r.finding_status}</span>}
                  </div>
                )}
              </article>
            ))}
          </div>

          {/* Pagination */}
          {totalResultPages > 1 && (
            <div className="pager">
              <button
                className="pager-button"
                disabled={resultPage === 0}
                onClick={() => setResultPage((p) => p - 1)}
              >
                Prev
              </button>
              <span className="meta-text">
                {resultPage + 1} / {totalResultPages}
              </span>
              <button
                className="pager-button"
                disabled={resultPage >= totalResultPages - 1}
                onClick={() => setResultPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </section>
      )}
    </>
  );
}
