import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  CodeAnalysisResult,
  CodeCoverage,
  CodeModule,
  CodeQueueStats,
  CodeReadiness,
  CodeRepo,
} from "../lib/api";

// ── Phase pipeline ──────────────────────────────────────

const CODE_PHASES = [
  { key: "ingest", label: "Ingest + Index" },
  { key: "classify-map", label: "Classify + Map" },
  { key: "hunt", label: "Hunt" },
  { key: "verify-variant", label: "Verify + Variant" },
  { key: "fuzz", label: "Fuzz" },
] as const;

type PhaseKey = (typeof CODE_PHASES)[number]["key"];

function phaseState(phase: PhaseKey, persistedPhase: string): "completed" | "active" | "pending" {
  const order = CODE_PHASES.map((entry) => entry.key);
  const pi = order.indexOf(phase);
  if (persistedPhase === "complete") return "completed";
  const ci = order.indexOf(persistedPhase as PhaseKey);
  if (ci < 0) return "pending";
  if (pi < ci) return "completed";
  if (pi === ci) return "active";
  return "pending";
}

function reviewQuality(coverage: CodeCoverage | null): { passed: boolean; warnings: string[] } | null {
  const effortWarnings = coverage?.gate.effort_warnings;
  const integrity = coverage?.gate.coverage_integrity;
  if (!Array.isArray(effortWarnings) || !Array.isArray(integrity)) return null;

  const warnings = [...effortWarnings];
  for (const item of integrity) {
    for (const warning of item.warnings ?? []) {
      warnings.push(`${item.file_path ?? "unknown file"}: ${warning}`);
    }
  }
  return { passed: warnings.length === 0, warnings: [...new Set(warnings)] };
}

// ── Search tokenizer ────────────────────────────────────

const SCOPES = [
  "disposition",
  "confidence",
  "status",
  "workflow",
  "cwe",
  "agent",
  "slot",
  "file",
  "function",
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

function buildCorpus(r: CodeAnalysisResult): string {
  return [
    r.function_name,
    r.file_path ?? "",
    r.hypothesis,
    r.evidence,
    r.notes,
    r.agent_name,
    r.finding_slug,
    r.cwe_id,
    r.slot_type,
    r.disposition,
    r.confidence,
    r.finding_workflow_status ?? "",
    r.finding_verification_state ?? "",
    r.finding_verification_disposition ?? "",
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
}

// ── Icons ───────────────────────────────────────────────

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

// ── Main component ──────────────────────────────────────

type CodeAnalysisTabProps = {
  persistedPhase: string;
  loadError: string | null;
  repos: CodeRepo[];
  modules: CodeModule[];
  queueStats: CodeQueueStats | null;
  coverage: CodeCoverage | null;
  readiness: CodeReadiness | null;
  results: CodeAnalysisResult[];
};

// C50 added `skipped` (with `skip_reason`) to the code-analysis queue
// dispositions. Keep this list in sync with `_VALID_DISPOSITIONS` in
// `orchestrator/backend/app/services/code_analysis.py` — UI drift here
// means operators who skipped a result (test fixture, generated code,
// minified, vendored dep) see an unstyled badge and the disposition
// filter chip is missing from the chip row.
const DISPOSITION_ORDER = ["finding", "suspicious", "needs_context", "clean", "skipped"];
const CONFIDENCE_ORDER = ["high", "medium", "low"];

export function CodeAnalysisTab({
  persistedPhase,
  loadError,
  repos,
  modules,
  queueStats,
  coverage,
  readiness,
  results,
}: CodeAnalysisTabProps) {
  const fallbackQuality = reviewQuality(coverage);
  const [expandedModules, setExpandedModules] = useState<Set<number>>(new Set());
  const [expandedResults, setExpandedResults] = useState<Set<number>>(new Set());
  const [resultPage, setResultPage] = useState(0);
  const [query, setQuery] = useState("");
  const [dispositionFilters, setDispositionFilters] = useState<Set<string>>(new Set());
  const [confidenceFilters, setConfidenceFilters] = useState<Set<string>>(new Set());
  const [workflowFilters, setWorkflowFilters] = useState<Set<string>>(new Set());
  const searchRef = useRef<HTMLInputElement | null>(null);

  // Pre-compute per-result corpus once
  const corpora = useMemo(() => {
    const map = new Map<number, string>();
    for (const r of results) map.set(r.id, buildCorpus(r));
    return map;
  }, [results]);

  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (r: CodeAnalysisResult, parsed: ParsedQuery): boolean => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "disposition":
            if ((r.disposition || "").toLowerCase() !== v) return false;
            break;
          case "confidence":
            if ((r.confidence || "").toLowerCase() !== v) return false;
            break;
          case "status":
          case "workflow":
            if ((r.finding_workflow_status || "").toLowerCase() !== v) return false;
            break;
          case "cwe":
            if (!(r.cwe_id || "").toLowerCase().includes(v)) return false;
            break;
          case "agent":
            if (!(r.agent_name || "").toLowerCase().includes(v)) return false;
            break;
          case "slot":
            if (!(r.slot_type || "").toLowerCase().includes(v)) return false;
            break;
          case "file":
            if (!(r.file_path || "").toLowerCase().includes(v)) return false;
            break;
          case "function":
            if (!(r.function_name || "").toLowerCase().includes(v)) return false;
            break;
        }
      }
      if (parsed.freeTerms.length) {
        const hay = corpora.get(r.id) || "";
        for (const t of parsed.freeTerms) if (!hay.includes(t)) return false;
      }
      return true;
    },
    [corpora],
  );

  // Counts computed from the full results set (stable chip labels)
  const dispositionCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of results) c[r.disposition] = (c[r.disposition] ?? 0) + 1;
    return c;
  }, [results]);

  const confidenceCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of results) {
      if (r.confidence) c[r.confidence] = (c[r.confidence] ?? 0) + 1;
    }
    return c;
  }, [results]);

  const workflowCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of results) {
      const w = r.finding_workflow_status;
      if (w) c[w] = (c[w] ?? 0) + 1;
    }
    return c;
  }, [results]);

  const filteredResults = useMemo(() => {
    const list = results.filter((r) => {
      if (dispositionFilters.size && !dispositionFilters.has(r.disposition)) return false;
      if (confidenceFilters.size && !confidenceFilters.has(r.confidence)) return false;
      if (workflowFilters.size) {
        const w = r.finding_workflow_status || "";
        if (!workflowFilters.has(w)) return false;
      }
      if (!matchesQuery(r, parsedQuery)) return false;
      return true;
    });
    list.sort((a, b) => {
      const ai = DISPOSITION_ORDER.indexOf(a.disposition);
      const bi = DISPOSITION_ORDER.indexOf(b.disposition);
      const da = ai === -1 ? DISPOSITION_ORDER.length : ai;
      const db = bi === -1 ? DISPOSITION_ORDER.length : bi;
      if (da !== db) return da - db;
      return b.id - a.id;
    });
    return list;
  }, [results, dispositionFilters, confidenceFilters, workflowFilters, parsedQuery, matchesQuery]);

  const PAGE_SIZE = 25;
  const totalResultPages = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const pageResults = filteredResults.slice(resultPage * PAGE_SIZE, (resultPage + 1) * PAGE_SIZE);

  useEffect(() => {
    setResultPage(0);
  }, [dispositionFilters, confidenceFilters, workflowFilters, query]);

  useEffect(() => {
    setResultPage((current) => Math.min(current, totalResultPages - 1));
  }, [totalResultPages]);

  // Keyboard: "/" to focus, "Esc" to blur
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
      if (e.key === "Escape" && isTyping && document.activeElement === searchRef.current) {
        searchRef.current?.blur();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const toggle = (set: Set<string>, setter: (s: Set<string>) => void, val: string) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
  };

  const clearAll = () => {
    setDispositionFilters(new Set());
    setConfidenceFilters(new Set());
    setWorkflowFilters(new Set());
    setQuery("");
  };

  const activeFilterCount =
    dispositionFilters.size +
    confidenceFilters.size +
    workflowFilters.size +
    (query ? 1 : 0);

  return (
    <>
      {/* Phase pipeline */}
      <section className="panel">
        <div className="panel-header">
          <h2>Code Analysis Pipeline</h2>
        </div>
        <div className="code-phase-pipeline">
          {CODE_PHASES.map((phase) => {
            const state = phaseState(phase.key, persistedPhase);
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
        <p className="meta-text">Persisted phase: {persistedPhase.replace(/-/g, " ")}</p>
      </section>

      {/* Repository overview */}
      <section className="panel">
        <div className="panel-header">
          <h2>Repositories</h2>
        </div>
        {loadError && (
          <p className="error-text" role="alert">
            {loadError}
          </p>
        )}
        <div className="code-repos-grid">
          {repos.length === 0 && !loadError && (
            <p className="meta-text">
              No code repositories ingested yet. Run <code>vigil assess code-ingest</code> to start code analysis.
            </p>
          )}
          {repos.map((repo) => {
            const degraded = repo.structural_analysis_status_counts.degraded ?? 0;
            const unsupported = repo.structural_analysis_status_counts.unsupported ?? 0;
            const truncated = repo.structural_artifact_truncated_files;
            const hasStructuralDebt = degraded > 0 || unsupported > 0 || truncated > 0;
            const degradedOrTruncatedPaths = [
              ...new Set([
                ...repo.structural_degraded_file_paths,
                ...repo.structural_artifact_truncated_file_paths,
              ]),
            ].sort();
            return (
            <article
              key={repo.id}
              className={`code-repo-card${hasStructuralDebt ? " code-repo-has-debt" : ""}`}
            >
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
              <p className="meta-text">
                Generation {repo.active_generation} · snapshot {repo.source_snapshot_quality}
                {repo.source_manifest_digest ? ` · ${repo.source_manifest_digest.slice(0, 12)}` : ""}
              </p>
              {hasStructuralDebt && (
                <div className="code-structural-debt" role="status">
                  <strong>Structural coverage debt</strong>
                  <span>
                    {degraded} degraded · {unsupported} unsupported · {truncated} truncated
                  </span>
                  <p>
                    {readiness?.transition_ready
                      ? "Completion readiness is READY; structural limitations remain recorded for auditability."
                      : readiness
                        ? "Check Completion readiness blockers for any outstanding direct-review requirement."
                        : "Completion readiness is unavailable; inspect the file inventory before treating debt as reviewed."}
                  </p>
                  {unsupported > 0 && (
                    <p>Unsupported paths are not included below; inspect the code file inventory/API.</p>
                  )}
                  {degradedOrTruncatedPaths.length > 0 && (
                    <details>
                      <summary>
                        {degradedOrTruncatedPaths.length} degraded/truncated affected path
                        {degradedOrTruncatedPaths.length === 1 ? "" : "s"}
                      </summary>
                      <ul>
                        {degradedOrTruncatedPaths.slice(0, 20).map((path) => <li key={path}><code>{path}</code></li>)}
                        {degradedOrTruncatedPaths.length > 20 && (
                          <li>+ {degradedOrTruncatedPaths.length - 20} more degraded/truncated paths</li>
                        )}
                      </ul>
                    </details>
                  )}
                </div>
              )}
            </article>
            );
          })}
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
      {(coverage || readiness) && (
        <section className="engagement-grid">
          {coverage && (
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
                {(coverage.by_status.unclassified ?? 0) > 0 && (
                  <div className="code-classification-row">
                    <span className="badge">unclassified</span>
                    <span className="code-classification-count">{coverage.by_status.unclassified}</span>
                    <span className="meta-text">awaiting Phase 1</span>
                  </div>
                )}
              </div>
            </article>
          )}

          <article className="panel">
            <p className="eyebrow">Analysis Gates</p>
            <div className="code-gate-status">
              <p className="meta-text">Completion readiness</p>
              <span className={`code-gate-badge ${readiness ? (readiness.transition_ready ? "code-gate-pass" : "code-gate-fail") : ""}`}>
                {readiness ? (readiness.transition_ready ? "READY" : "BLOCKED") : "UNKNOWN"}
              </span>
              {readiness && readiness.blockers.length > 0 && (
                <ul className="code-gate-reasons">
                  {readiness.blockers.map((blocker, i) => (
                    <li key={`${blocker.code}-${i}`} className="meta-text">
                      [{blocker.code}] {blocker.message}
                      {!blocker.overrideable ? " (integrity; non-overrideable)" : ""}
                    </li>
                  ))}
                </ul>
              )}

              <p className="meta-text" style={{ marginTop: "16px" }}>Review quality</p>
              {(() => {
                const quality = readiness?.quality_gate ?? fallbackQuality;
                const warnings = quality?.warnings ?? [];
                return (
                  <>
                    <span className={`code-gate-badge ${quality ? (quality.passed ? "code-gate-pass" : "code-gate-fail") : ""}`}>
                      {quality ? (quality.passed ? "PASS" : "NEEDS ATTENTION") : "UNKNOWN"}
                    </span>
                    {warnings.length > 0 && (
                      <ul className="code-gate-reasons">
                        {warnings.map((warning, i) => (
                          <li key={i} className="meta-text">{warning}</li>
                        ))}
                      </ul>
                    )}
                  </>
                );
              })()}
            </div>

            {/* Confidence metrics */}
            {coverage && <div className="code-confidence">
              <p className="eyebrow" style={{ marginTop: "16px" }}>Confidence</p>
              <div className="code-fn-stats">
                <span>Critical: {coverage.confidence.critical_coverage_pct.toFixed(0)}%</span>
                <span>High: {coverage.confidence.high_coverage_pct.toFixed(0)}%</span>
                <span>LOC analyzed: {coverage.confidence.overall_loc_analyzed.toLocaleString()}</span>
              </div>
            </div>}

            {/* Findings summary */}
            {coverage && coverage.findings_summary.total_code_findings > 0 && (
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
            <span className="meta-text">
              {filteredResults.length} of {results.length} results
            </span>
          </div>

          {/* Toolbar + filter chips (reuses FindingsTab redesign styles) */}
          <div className="findings-redesign">
            <div className="panel findings-toolbar-panel">
              <div className="toolbar">
                <div className="search-wrap">
                  <IconSearch />
                  <input
                    ref={searchRef}
                    className="search-input"
                    placeholder="Search function, file, evidence… (try disposition:finding confidence:high cwe:79)"
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
                <div className="filter-group">
                  <span className="filter-label">Disposition</span>
                  {DISPOSITION_ORDER.filter((d) => (dispositionCounts[d] ?? 0) > 0).map((d) => (
                    <button
                      key={d}
                      type="button"
                      className={`filter-chip ${dispositionFilters.has(d) ? "is-active" : ""}`}
                      onClick={() => toggle(dispositionFilters, setDispositionFilters, d)}
                    >
                      {d.replace(/_/g, " ")}
                      <span className="filter-count">{dispositionCounts[d]}</span>
                    </button>
                  ))}
                </div>
                {Object.keys(confidenceCounts).length > 0 && (
                  <div className="filter-group">
                    <span className="filter-label">Confidence</span>
                    {CONFIDENCE_ORDER.filter((c) => (confidenceCounts[c] ?? 0) > 0).map((c) => (
                      <button
                        key={c}
                        type="button"
                        className={`filter-chip ${confidenceFilters.has(c) ? "is-active" : ""}`}
                        onClick={() => toggle(confidenceFilters, setConfidenceFilters, c)}
                      >
                        {c}
                        <span className="filter-count">{confidenceCounts[c]}</span>
                      </button>
                    ))}
                    {/* Any non-standard confidence values */}
                    {Object.keys(confidenceCounts)
                      .filter((c) => !CONFIDENCE_ORDER.includes(c))
                      .map((c) => (
                        <button
                          key={c}
                          type="button"
                          className={`filter-chip ${confidenceFilters.has(c) ? "is-active" : ""}`}
                          onClick={() => toggle(confidenceFilters, setConfidenceFilters, c)}
                        >
                          {c}
                          <span className="filter-count">{confidenceCounts[c]}</span>
                        </button>
                      ))}
                  </div>
                )}
                {Object.keys(workflowCounts).length > 0 && (
                  <div className="filter-group">
                    <span className="filter-label">Status</span>
                    {Object.keys(workflowCounts).map((s) => (
                      <button
                        key={s}
                        type="button"
                        className={`filter-chip ${workflowFilters.has(s) ? "is-active" : ""}`}
                        onClick={() => toggle(workflowFilters, setWorkflowFilters, s)}
                      >
                        {s.replace(/_/g, " ")}
                        <span className="filter-count">{workflowCounts[s]}</span>
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

          {/* Results list */}
          <div className="code-results-list">
            {pageResults.length === 0 ? (
              <p className="meta-text">No results match the current filters.</p>
            ) : (
              pageResults.map((r) => {
                const isExpanded = expandedResults.has(r.id);
                const truncateAt = 200;
                const needsTruncation =
                  (r.evidence?.length ?? 0) > truncateAt || (r.hypothesis?.length ?? 0) > truncateAt;
                return (
                  <article
                    key={r.id}
                    className={`code-result-row ${r.finding_workflow_status === "false_positive" ? "code-result-row-suppressed" : ""}`}
                    style={needsTruncation ? { cursor: "pointer" } : undefined}
                    onClick={needsTruncation ? () => {
                      setExpandedResults((prev) => {
                        const next = new Set(prev);
                        if (next.has(r.id)) next.delete(r.id);
                        else next.add(r.id);
                        return next;
                      });
                    } : undefined}
                  >
                    <div className="code-result-header">
                      <span className={`badge code-disposition-${r.disposition}`}>{r.disposition}</span>
                      <strong className="mono-text">{r.function_name || (r.file_path ? r.file_path.split("/").pop() : `file #${r.file_id}`)}</strong>
                      {r.cwe_id && <span className="badge">{r.cwe_id}</span>}
                      {r.slot_type && <span className="badge">{r.slot_type}</span>}
                      <span className={`badge code-confidence-${r.confidence}`}>{r.confidence} conf.</span>
                      <span className="meta-text">{r.agent_name}</span>
                    </div>
                    {r.file_path && (
                      <div className="code-result-detail">
                        <span className="code-result-label">File:</span>
                        <span className="mono-text">{r.file_path}</span>
                      </div>
                    )}
                    {r.hypothesis && (
                      <div className={`code-result-detail ${isExpanded ? "is-expanded" : ""}`}>
                        <span className="code-result-label">Hypothesis:</span>
                        <span>{!isExpanded && r.hypothesis.length > truncateAt ? `${r.hypothesis.slice(0, truncateAt)}...` : r.hypothesis}</span>
                      </div>
                    )}
                    {r.evidence && (
                      <div className={`code-result-detail ${isExpanded ? "is-expanded" : ""}`}>
                        <span className="code-result-label">Evidence:</span>
                        <span>{!isExpanded && r.evidence.length > truncateAt ? `${r.evidence.slice(0, truncateAt)}...` : r.evidence}</span>
                      </div>
                    )}
                    {r.finding_slug && (
                      <div className="code-result-detail">
                        <span className="code-result-label">Finding:</span>
                        <span className="mono-text">{r.finding_slug}</span>
                        {r.finding_workflow_status && (
                          <span className={`badge status-${r.finding_workflow_status}`}>{r.finding_workflow_status}</span>
                        )}
                        {r.finding_verification_disposition && r.finding_verification_disposition !== "none" && (
                          <span className={`badge status-${r.finding_verification_disposition}`}>{r.finding_verification_disposition}</span>
                        )}
                        {r.finding_verification_state === "disputed" && (
                          <span className="badge status-disputed">disputed</span>
                        )}
                      </div>
                    )}
                  </article>
                );
              })
            )}
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
