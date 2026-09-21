import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";

import type {
  AssessmentRun,
  AssessmentRunChild,
  AuditBlocker,
  RunAuditSection,
  RunComparison,
} from "../lib/api";
import {
  getAssessmentRun,
  getAssessmentRunComparison,
  listAssessmentRunChildren,
  listAssessmentRuns,
} from "../lib/api";
import {
  appendAuditPage,
  auditUiReducer,
  blockerDestination,
  chooseRunSelection,
  collectBarePages,
  dispatchProvenance,
  elapsedLabel,
  initialAuditUiState,
  lifecyclePresentation,
  normalizedComparison,
} from "../lib/runAudit";
import { TableSkeleton } from "./Skeletons";

const RUN_PAGE_SIZE = 200;
const CHILD_PAGE_SIZE = 50;
const SECTIONS: { key: RunAuditSection; label: string }[] = [
  { key: "sources", label: "Sources" },
  { key: "source-reads", label: "Source reads" },
  { key: "dispatches", label: "Dispatches" },
  { key: "commands", label: "Command evidence" },
  { key: "observed-events", label: "Observed events" },
  { key: "decision-history", label: "Decision history" },
  { key: "proof-receipts", label: "Proof and events" },
  { key: "obligations", label: "Obligations" },
  { key: "candidates", label: "Candidates" },
  { key: "tool-signals", label: "Tool signals" },
  { key: "discovery-passes", label: "Discovery passes" },
  { key: "code-receipts", label: "Code receipts" },
  { key: "comparisons", label: "Comparison records" },
];

const PROOF_SECTION_KEYS = new Set<RunAuditSection>([
  "dispatches",
  "commands",
  "observed-events",
  "decision-history",
  "proof-receipts",
]);

const OVERVIEW_COUNT_KEYS: Record<"proof" | "scan", Set<string>> = {
  proof: new Set(["findings", "proof_receipts"]),
  scan: new Set([
    "inventory_total",
    "source_reads",
    "obligations",
    "candidates",
    "findings",
    "proof_receipts",
  ]),
};

type ChildState = {
  items: AssessmentRunChild[];
  total: number;
  nextOffset: number;
  hasMore: boolean;
};

const EMPTY_CHILD_STATE: ChildState = {
  items: [],
  total: 0,
  nextOffset: 0,
  hasMore: false,
};

type RunsTabProps = {
  engagementKey: string;
  refreshVersion?: number;
  initialRunId?: number;
  initialSection?: string;
  initialObject?: string;
};

function validSection(value: string | undefined): RunAuditSection | null {
  return SECTIONS.some((section) => section.key === value)
    ? (value as RunAuditSection)
    : null;
}

function statusLabel(value: string | undefined): string {
  return (value || "unknown").replace(/_/g, " ");
}

function formatDate(value?: string | null): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

function titleForChild(row: AssessmentRunChild, section: RunAuditSection): string {
  const candidates = section === "sources"
    ? [row.path, row.target_key, row.content_sha256]
    : section === "source-reads"
      ? [row.path, row.source_path, row.source_sha256]
      : section === "dispatches"
        ? [row.agent_id, row.agent_role, row.client_name]
      : section === "commands"
        ? [(row.command as Record<string, unknown> | undefined)?.command, row.observed_result]
      : section === "observed-events"
        ? [row.evidence_kind, row.artifact_relative_path, row.observed_result]
      : section === "decision-history"
        ? [row.detail, row.object_type, row.to_status]
      : section === "proof-receipts"
        ? [row.evidence_kind, row.artifact_relative_path, row.observed_result]
      : section === "obligations"
        ? [row.object_key, row.identity_key, row.obligation_kind]
        : section === "candidates"
          ? [row.identity_key, row.source_anchor, row.vulnerability_family]
          : section === "tool-signals"
            ? [row.observed_signature, row.signal_kind, row.source_anchor]
            : section === "discovery-passes"
              ? [row.identity_key, row.terminal_reason, row.frontier_identity_sha256]
              : section === "code-receipts"
                ? [row.receipt_kind, row.target_key, row.obligation_status]
          : [row.selection, row.baseline_run_id, row.comparison_sha256];
  const title = candidates.find((value) => typeof value === "string" && value.trim());
  return typeof title === "string" ? title : `${statusLabel(section)} record`;
}

function rowDomId(section: RunAuditSection, id: number | string | undefined): string | undefined {
  return id === undefined ? undefined : `run-audit-${section}-${String(id).replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

function AuditJson({ value }: { value: unknown }) {
  return (
    <pre className="run-audit-json">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function RunComparisonPanel({
  baseline,
  comparison,
  comparisonError,
  comparisonGroups,
  comparisonLoading,
  detail,
  runs,
  setBaseline,
}: {
  baseline: string;
  comparison: RunComparison | null;
  comparisonError: string | null;
  comparisonGroups: ReturnType<typeof normalizedComparison>;
  comparisonLoading: boolean;
  detail: AssessmentRun;
  runs: AssessmentRun[];
  setBaseline: (value: string) => void;
}) {
  const compatibility = comparison
    ? comparison.target_compatible === true && comparison.source_compatible === true
      ? "compatible"
      : comparison.target_compatible === null || comparison.source_compatible === null
        ? "unknown"
        : "drift"
    : null;

  return (
    <section className="run-audit-comparison">
      <div className="run-comparison-heading">
        <div><h2>Deterministic comparison</h2><p className="meta-text">Latest compatible baseline by default; no model call.</p></div>
        <label>
          Baseline
          <select value={baseline} onChange={(event) => setBaseline(event.target.value)}>
            <option value="">Latest compatible</option>
            {runs.filter((run) => run.id !== detail.id).map((run) => (
              <option key={run.id} value={run.id}>{run.run_uuid} · {statusLabel(run.status)}</option>
            ))}
          </select>
        </label>
      </div>
      {comparisonLoading && <p className="meta-text">Comparing recorded identities…</p>}
      {comparisonError && <p className="error-text">{comparisonError}</p>}
      {comparison && (
        <>
          <p className={`run-compatibility ${compatibility === "compatible" ? "is-compatible" : compatibility === "unknown" ? "is-unknown" : "has-drift"}`}>
            {compatibility === "compatible"
              ? `Target and source compatible with run ${comparison.baseline_run_id}`
              : compatibility === "unknown"
                ? `Compatibility with run ${comparison.baseline_run_id} is unknown because target or source identity was not recorded`
                : `Target or source drift from run ${comparison.baseline_run_id}; unresolved prior records remain unknown`}
          </p>
          <div className="run-comparison-grid">
            {comparisonGroups.map((group) => (
              <section key={group.key} className={`comparison-${group.key}`}>
                <header><h3>{statusLabel(group.key)}</h3><span>{group.items.length}</span></header>
                {group.items.length === 0 ? <p>None</p> : (
                  <ul>{group.items.map((item) => <li key={item}>{item}</li>)}</ul>
                )}
              </section>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

export function RunsTab({
  engagementKey,
  refreshVersion,
  initialRunId,
  initialSection,
  initialObject,
}: RunsTabProps) {
  const [runs, setRuns] = useState<AssessmentRun[]>([]);
  const [runsLoading, setRunsLoading] = useState(true);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(initialRunId ?? null);
  const [detail, setDetail] = useState<AssessmentRun | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [ui, dispatchUi] = useReducer(auditUiReducer, {
    ...initialAuditUiState,
    section: validSection(initialSection) ?? initialAuditUiState.section,
  });
  const [children, setChildren] = useState<ChildState>(EMPTY_CHILD_STATE);
  const [childrenLoading, setChildrenLoading] = useState(false);
  const [childrenError, setChildrenError] = useState<string | null>(null);
  const [baseline, setBaseline] = useState("");
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const childrenRequestRef = useRef(0);
  const runsRequestRef = useRef(0);

  const loadRuns = useCallback(async (showSpinner: boolean) => {
    const requestId = ++runsRequestRef.current;
    if (showSpinner) setRunsLoading(true);
    try {
      const accumulated = await collectBarePages(
        (offset, limit) => listAssessmentRuns(engagementKey, { limit, offset }),
        RUN_PAGE_SIZE,
      );
      if (requestId !== runsRequestRef.current) return;
      setRuns(accumulated);
      setSelectedRunId((current) => chooseRunSelection(
        accumulated.map((run) => run.id),
        current,
        initialRunId,
      ));
      setRunsError(null);
    } catch (error) {
      if (requestId !== runsRequestRef.current) return;
      setRunsError(error instanceof Error ? error.message : "Failed to load assessment runs");
      if (showSpinner) setRuns([]);
    } finally {
      if (requestId === runsRequestRef.current) setRunsLoading(false);
    }
  }, [engagementKey, initialRunId]);

  useEffect(() => {
    void loadRuns(true);
  }, [loadRuns]);

  const didRefreshRef = useRef(false);
  useEffect(() => {
    if (!didRefreshRef.current) {
      didRefreshRef.current = true;
      return;
    }
    void loadRuns(false);
  }, [refreshVersion, loadRuns]);

  useEffect(() => {
    if (initialRunId) {
      setSelectedRunId(initialRunId);
      setBaseline("");
      setAdvancedOpen(false);
    }
  }, [initialRunId]);

  useEffect(() => {
    const section = validSection(initialSection);
    if (section) dispatchUi({ type: "select-section", section });
  }, [initialSection]);

  useEffect(() => {
    if (selectedRunId === null) {
      setDetail(null);
      return;
    }
    let active = true;
    setDetailLoading(true);
    setDetail((current) => current?.id === selectedRunId ? current : null);
    setDetailError(null);
    getAssessmentRun(engagementKey, selectedRunId)
      .then((next) => {
        if (active) setDetail(next);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setDetail(null);
        setDetailError(error instanceof Error ? error.message : "Failed to load run detail");
      })
      .finally(() => {
        if (active) setDetailLoading(false);
      });
    return () => {
      active = false;
    };
  }, [engagementKey, selectedRunId, refreshVersion]);

  const loadChildren = useCallback(async (offset: number, replace: boolean) => {
    if (selectedRunId === null) return;
    const requestId = ++childrenRequestRef.current;
    setChildrenLoading(true);
    setChildrenError(null);
    try {
      const page = await listAssessmentRunChildren(
        engagementKey,
        selectedRunId,
        ui.section,
        { limit: CHILD_PAGE_SIZE, offset },
      );
      if (requestId !== childrenRequestRef.current) return;
      setChildren((current) => {
        const merged = appendAuditPage(replace ? [] : current.items, page);
        return {
          items: merged.items,
          total: page.total,
          nextOffset: merged.nextOffset,
          hasMore: merged.hasMore,
        };
      });
    } catch (error) {
      if (requestId !== childrenRequestRef.current) return;
      if (replace) setChildren(EMPTY_CHILD_STATE);
      setChildrenError(error instanceof Error ? error.message : "Failed to load run records");
    } finally {
      if (requestId === childrenRequestRef.current) setChildrenLoading(false);
    }
  }, [engagementKey, selectedRunId, ui.section]);

  useEffect(() => {
    setChildren(EMPTY_CHILD_STATE);
    if (selectedRunId !== null) void loadChildren(0, true);
  }, [selectedRunId, ui.section, refreshVersion, loadChildren]);

  const focusedObject = (
    initialObject
    && selectedRunId === initialRunId
    && ui.section === validSection(initialSection)
  ) ? initialObject : undefined;

  useEffect(() => {
    if (!focusedObject || childrenLoading) return;
    const target = rowDomId(ui.section, focusedObject);
    const element = target ? document.getElementById(target) : null;
    if (element) {
      element.scrollIntoView({ block: "center", behavior: "smooth" });
      return;
    }
    if (children.hasMore) void loadChildren(children.nextOffset, false);
  }, [children, childrenLoading, focusedObject, loadChildren, ui.section]);

  useEffect(() => {
    if (selectedRunId === null) {
      setComparison(null);
      return;
    }
    let active = true;
    setComparisonLoading(true);
    setComparison(null);
    setComparisonError(null);
    const baselineId = baseline ? Number(baseline) : undefined;
    getAssessmentRunComparison(engagementKey, selectedRunId, baselineId)
      .then((next) => {
        if (active) setComparison(next);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setComparison(null);
        setComparisonError(
          error instanceof Error ? error.message : "No compatible baseline is available",
        );
      })
      .finally(() => {
        if (active) setComparisonLoading(false);
      });
    return () => {
      active = false;
    };
  }, [baseline, engagementKey, selectedRunId, refreshVersion]);

  const blockers = useMemo(() => {
    if (!detail) return [];
    if (detail.blockers?.length) return detail.blockers;
    return detail.seal?.blockers ?? [];
  }, [detail]);

  const comparisonGroups = comparison ? normalizedComparison(comparison) : [];
  const lifecycleRows = lifecyclePresentation(detail?.lifecycle_history ?? []);
  const proofHealth = Object.entries(detail?.proof_health ?? {});
  const counts = Object.entries(detail?.counts ?? {});
  const provenance = detail ? dispatchProvenance(detail) : {};
  const purpose = detail?.run_purpose === "scan" ? "scan" : "proof";
  const overviewCounts = counts.filter(([name]) => OVERVIEW_COUNT_KEYS[purpose].has(name));
  const visibleSections = purpose === "proof" && !advancedOpen
    ? SECTIONS.filter((section) => PROOF_SECTION_KEYS.has(section.key))
    : SECTIONS;
  const targetIdentity = detail?.target_identity ?? {};
  const hasTargetIdentity = Object.keys(targetIdentity).length > 0;

  useEffect(() => {
    if (
      detail?.run_purpose === "proof"
      && !advancedOpen
      && !PROOF_SECTION_KEYS.has(ui.section)
    ) {
      dispatchUi({ type: "select-section", section: "proof-receipts" });
    }
  }, [advancedOpen, detail?.run_purpose, ui.section]);

  return (
    <div className="runs-audit">
      <section className="panel run-audit-toolbar">
        <p className="eyebrow">Shared audit</p>
        <h2>Assessment runs</h2>
        <p className="meta-text">
          Code, web, blue, and shared work use the same durable evidence trail.
        </p>
      </section>
      <div className="run-audit-layout">
        <aside className="panel run-audit-rail" aria-label="Assessment runs">
          <div className="run-rail-heading">
            <strong>Run history</strong>
            <span className="tab-count">{runs.length}</span>
          </div>
          {runsLoading && <TableSkeleton rows={5} />}
          {runsError && <p className="error-text">{runsError}</p>}
          {!runsLoading && !runsError && runs.length === 0 && (
            <p className="empty-state">No assessment runs have been recorded.</p>
          )}
          <div className="run-rail-list">
            {runs.map((run) => (
              <button
                type="button"
                key={run.id}
                className={`run-rail-row ${run.id === selectedRunId ? "is-selected" : ""}`}
                onClick={() => {
                  setSelectedRunId(run.id);
                  setBaseline("");
                }}
              >
                <span className={`run-status-mark status-${run.status}`} aria-hidden="true" />
                <span>
                  <strong>{run.run_uuid}</strong>
                  <small>{statusLabel(run.run_kind)} · {statusLabel(run.run_purpose)}</small>
                </span>
                <span className={`status-pill status-${run.status}`}>{statusLabel(run.status)}</span>
              </button>
            ))}
          </div>
        </aside>

        <div className="run-audit-workspace">
          {detailLoading && !detail && (
            <section className="panel"><TableSkeleton rows={6} /></section>
          )}
          {detailError && <section className="panel"><p className="error-text">{detailError}</p></section>}
          {!detailLoading && !detailError && !detail && runs.length > 0 && (
            <section className="panel"><p className="empty-state">Select a run to inspect it.</p></section>
          )}

          {detail && (
            <>
              <section className="panel run-audit-summary">
                <header className="run-detail-header">
                  <div>
                    <p className="eyebrow">{statusLabel(detail.run_kind)} · {statusLabel(detail.run_purpose)}</p>
                    <h2>{detail.run_uuid}</h2>
                  </div>
                  <span className={`status-pill status-${detail.status}`}>{statusLabel(detail.status)}</span>
                </header>

                <dl className="run-identity-strip">
                  <div><dt>Started</dt><dd>{formatDate(detail.started_at ?? detail.created_at)}</dd></div>
                  <div><dt>Finished</dt><dd>{formatDate(detail.finished_at)}</dd></div>
                  <div><dt>Elapsed</dt><dd>{elapsedLabel(detail.started_at ?? detail.created_at, detail.finished_at)}</dd></div>
                  <div>
                    <dt>Observed cost</dt>
                    <dd>{detail.observed_cost == null ? "Not recorded" : `$${detail.observed_cost.toFixed(4)}`}</dd>
                  </div>
                </dl>

                {overviewCounts.length > 0 && (
                  <div className="run-metric-strip" aria-label="Run counts">
                    {overviewCounts.map(([name, value]) => (
                      <div key={name}><strong>{value}</strong><span>{statusLabel(name)}</span></div>
                    ))}
                  </div>
                )}

                {(hasTargetIdentity || proofHealth.length > 0) && (
                  <div className="run-detail-columns">
                  {hasTargetIdentity && <div>
                    <h3>Target identity</h3>
                    <AuditJson value={targetIdentity} />
                  </div>}
                  {proofHealth.length > 0 && <div>
                    <h3>Proof health</h3>
                    <dl className="run-proof-health">
                      {proofHealth.map(([name, value]) => (
                        <div key={name}><dt>{statusLabel(name)}</dt><dd>{String(value)}</dd></div>
                      ))}
                    </dl>
                  </div>}
                </div>)}
                {detail.finding_slugs && detail.finding_slugs.length > 0 && (
                  <div className="run-finding-links">
                    <h3>Linked findings</h3>
                    <div>
                      {detail.finding_slugs.map((slug) => (
                        <a
                          key={slug}
                          href={`#/engagements/${encodeURIComponent(engagementKey)}?tab=findings&finding=${encodeURIComponent(slug)}`}
                        >
                          {slug}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                {detail.resumed_from_run_id && (
                  <p className="run-resume-line">
                    Continued from <a href={`#/engagements/${encodeURIComponent(engagementKey)}?tab=runs&run=${detail.resumed_from_run_id}`}>run #{detail.resumed_from_run_id}</a>
                  </p>
                )}
              </section>

              <section className="panel run-audit-blockers">
                <div className="panel-header">
                  <div><h2>Blockers</h2><p className="meta-text">Each item names the object and corrective action.</p></div>
                  <span className="tab-count">{blockers.length}</span>
                </div>
                {blockers.length === 0 ? (
                  <p className="run-clear-state">No recorded blockers.</p>
                ) : (
                  <div className="run-blocker-list">
                    {blockers.map((blocker: AuditBlocker, index) => (
                      <article key={`${String(blocker.object_type)}-${String(blocker.object_id)}-${index}`}>
                        <span className="badge badge-warn">{statusLabel(blocker.code)}</span>
                        <div>
                          <code className="run-blocker-object">{statusLabel(blocker.object_type)}{blocker.object_id == null ? "" : ` #${blocker.object_id}`}</code>
                          <strong>{blocker.message || `${statusLabel(blocker.object_type)} ${String(blocker.object_id ?? "")}`}</strong>
                          <p>{blocker.action || "Inspect and settle this recorded blocker."}</p>
                        </div>
                        <a href={blockerDestination(engagementKey, detail.id, blocker)}>Open object →</a>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="panel run-audit-advanced">
                <button
                  type="button"
                  className="run-advanced-toggle"
                  aria-expanded={advancedOpen}
                  onClick={() => setAdvancedOpen((open) => !open)}
                >
                  <span><strong>Advanced audit</strong><small>Complete accounting, provenance, lifecycle, and comparison data</small></span>
                  <span aria-hidden="true">{advancedOpen ? "−" : "+"}</span>
                </button>
                {advancedOpen && <div className="run-advanced-content">
                  <section>
                    <h2>Complete accounting</h2>
                    <div className="run-metric-strip" aria-label="Complete run counts">
                      {counts.map(([name, value]) => (
                        <div key={name}><strong>{value}</strong><span>{statusLabel(name)}</span></div>
                      ))}
                    </div>
                  </section>
                  <section>
                    <div className="panel-header">
                      <div><h2>Identity and provenance</h2><p className="meta-text">Observed dispatch and immutable source boundaries.</p></div>
                    </div>
                    <div className="run-detail-columns">
                      <div><h3>Target identity</h3><AuditJson value={targetIdentity} /></div>
                      <div><h3>Dispatch</h3><AuditJson value={provenance} /></div>
                      <div><h3>Source generations</h3><AuditJson value={detail.source_generations ?? []} /></div>
                      <div><h3>Exclusions</h3><AuditJson value={detail.exclusions ?? []} /></div>
                      <div><h3>Terminal seal</h3><AuditJson value={detail.seal ?? { seal_sha256: detail.seal_sha256 }} /></div>
                    </div>
                    {detail.warnings && detail.warnings.length > 0 && (
                      <ul className="run-provenance-warnings">
                        {detail.warnings.map((warning) => <li key={warning}>{warning}</li>)}
                      </ul>
                    )}
                  </section>
                  <section className="run-audit-history">
                    <div className="panel-header"><div><h2>Lifecycle history</h2><p className="meta-text">Recorded transitions remain distinct from current status.</p></div></div>
                    {lifecycleRows.length === 0 ? (
                      <p className="empty-state">No lifecycle events recorded.</p>
                    ) : (
                      <ol>
                        {lifecycleRows.map(({ key, transition, event }) => (
                          <li key={key}>
                            <span className="run-history-dot" aria-hidden="true" />
                            <div>
                              <strong>{transition.split(" → ").map(statusLabel).join(" → ")}</strong>
                              <p>{formatDate(event.created_at)}{event.actor ? ` · ${event.actor}` : ""}</p>
                              {event.reason && <p>{event.reason}</p>}
                            </div>
                          </li>
                        ))}
                      </ol>
                    )}
                  </section>
                  {purpose === "proof" && <RunComparisonPanel
                    baseline={baseline}
                    comparison={comparison}
                    comparisonError={comparisonError}
                    comparisonGroups={comparisonGroups}
                    comparisonLoading={comparisonLoading}
                    detail={detail}
                    runs={runs}
                    setBaseline={setBaseline}
                  />}
                </div>}
              </section>

              {purpose === "scan" && <RunComparisonPanel
                baseline={baseline}
                comparison={comparison}
                comparisonError={comparisonError}
                comparisonGroups={comparisonGroups}
                comparisonLoading={comparisonLoading}
                detail={detail}
                runs={runs}
                setBaseline={setBaseline}
              />}

              <section className="panel run-audit-drilldown">
                <div className="panel-header">
                  <div><h2>Recorded work</h2><p className="meta-text">Bounded pages from the selected run.</p></div>
                  <span className="tab-count">{children.total}</span>
                </div>
                <div className="run-section-tabs" role="tablist" aria-label="Run records">
                  {visibleSections.map((section) => (
                    <button
                      type="button"
                      role="tab"
                      aria-selected={ui.section === section.key}
                      key={section.key}
                      onClick={() => dispatchUi({ type: "select-section", section: section.key })}
                    >
                      {section.label}
                    </button>
                  ))}
                </div>
                {childrenError && <p className="error-text">{childrenError}</p>}
                {childrenLoading && children.items.length === 0 && <TableSkeleton rows={4} />}
                {!childrenLoading && !childrenError && children.items.length === 0 && (
                  <p className="empty-state">No {statusLabel(ui.section)} recorded for this run.</p>
                )}
                <div className="run-record-list">
                  {children.items.map((row, index) => {
                    const id = rowDomId(ui.section, row.id);
                    const focused = focusedObject != null && String(row.id) === focusedObject;
                    return (
                      <article id={id} key={row.id ?? `${ui.section}-${index}`} className={focused ? "is-focused" : ""}>
                        <header>
                          <strong>{titleForChild(row, ui.section)}</strong>
                          {row.id !== undefined && <span>#{String(row.id)}</span>}
                        </header>
                        <AuditJson value={row} />
                      </article>
                    );
                  })}
                </div>
                {children.hasMore && (
                  <button
                    type="button"
                    className="ghost-button run-load-more"
                    disabled={childrenLoading}
                    onClick={() => void loadChildren(children.nextOffset, false)}
                  >
                    {childrenLoading ? "Loading…" : `Load more · ${Math.max(0, children.total - children.items.length)} remaining`}
                  </button>
                )}
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
