import { useRef, type KeyboardEvent } from "react";

import "../styles/code.css";
import type { CodeReadinessTarget } from "../lib/api";
import { useLiveRefreshToken } from "../lib/useLiveRefreshToken";
import { engagementHref } from "../lib/workspaceRoutes";
import { CardSkeleton, SlowLoadHint } from "./Skeletons";
import { EmptyState, PageHeader } from "./ui";
import { PHASE_STATE_LABELS, VIEW_LABELS, type CodeView } from "./code/codeLabels";
import {
  awaitingVerdictFiles,
  classReviewTotals,
  debtUnknownRepoIds,
  fileReviewTotals,
  finishedNotReviewed,
  groupBlockers,
  pendingLeads,
  type ReviewTotals,
} from "./code/codeModel";
import { CodeFiles } from "./code/CodeFiles";
import { CodeModules } from "./code/CodeModules";
import { CodeOverview } from "./code/CodeOverview";
import { CodeQuality, qualityWarnings } from "./code/CodeQuality";
import { CodeQueue } from "./code/CodeQueue";
import { CodeRepositories } from "./code/CodeRepositories";
import { CodeResults } from "./code/CodeResults";
import { useCodeData } from "./code/useCodeData";
import { CODE_VIEWS, codeViewHref, useCodeRoute } from "./code/useCodeRoute";

// Readiness checks on large repositories take seconds; a burst of live
// updates refreshes the view at most this often (with a trailing refresh).
const LIVE_REFRESH_MIN_MS = 5000;

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

/** The transition the persisted phase is working toward. */
export function nextReadinessTarget(persistedPhase: string): CodeReadinessTarget {
  const order = CODE_PHASES.map((entry) => entry.key) as string[];
  const index = order.indexOf(persistedPhase);
  if (index < 0 || index === order.length - 1) return "complete";
  return order[index + 1] as CodeReadinessTarget;
}

function phaseLabel(phase: string): string {
  if (phase === "complete") return "Completion";
  return CODE_PHASES.find((entry) => entry.key === phase)?.label ?? phase.replace(/-/g, " ");
}

// ── Main component ──────────────────────────────────────

type CodeAnalysisTabProps = {
  engagementKey: string;
  persistedPhase: string;
  /** Bumped by the workspace on each live refresh. */
  refreshVersion?: number;
};

export function CodeAnalysisTab({ engagementKey, persistedPhase, refreshVersion = 0 }: CodeAnalysisTabProps) {
  const route = useCodeRoute(engagementKey);
  const target = nextReadinessTarget(persistedPhase);
  // Live updates, throttled; every section reloads on this token.
  const liveVersion = useLiveRefreshToken(refreshVersion, LIVE_REFRESH_MIN_MS);
  const { data, errors, errorBySource, pending, reload } = useCodeData({
    engagementKey,
    target,
    view: route.view,
    refreshVersion: liveVersion,
  });
  const firstLoad = data.repos === null && data.readiness === null && errors.length === 0;
  // A web or blue engagement with no repository owes no code review.
  const trackDisabled = (data.readiness ?? data.completion)?.track_enabled === false && (data.repos?.length ?? 0) === 0;
  // An open analysis result replaces the page, like every other record.
  const recordOpen = route.view === "results" && route.result != null;

  const knownPhase = CODE_PHASES.some((phase) => phase.key === persistedPhase) || persistedPhase === "complete";
  const nextLabel = phaseLabel(target);
  const groups = groupBlockers(data.readiness?.blockers ?? []);
  const requiredCount = groups.filter((group) => group.required).length;
  const warnings = qualityWarnings(data.readiness, data.coverage);
  const unknownDebt = debtUnknownRepoIds(data.readiness);
  const queueOpen = data.queueStats
    ? data.queueStats.pending + data.queueStats.processing + data.queueStats.error + data.queueStats.needs_context
    : null;
  const awaiting = awaitingVerdictFiles(data.completion);

  // Each badge counts what needs the operator in that section.
  const viewCounts: Partial<Record<CodeView, number | null>> = {
    overview: data.readiness ? groups.length : null,
    repositories: data.repos?.length ?? null,
    queue: queueOpen,
    files: data.readiness && unknownDebt.size === 0 ? data.readiness.structural_debt_count ?? null : null,
    results: awaiting,
    quality: data.readiness || data.coverage ? warnings.length : null,
    modules: data.modules?.length ?? null,
  };
  const viewCountTitles: Partial<Record<CodeView, string>> = {
    overview: `Things that block ${nextLabel}`,
    queue: "Review jobs queued, running, waiting on context or failed",
    files: "Files needing a direct read",
    results: "Files whose suspicious review awaits a verdict",
    quality: "Review-quality warnings",
  };

  const tabRefs = useRef<Partial<Record<CodeView, HTMLButtonElement | null>>>({});
  const select = (view: CodeView, focus = false) => {
    route.navigate({ view });
    if (focus) tabRefs.current[view]?.focus();
  };
  const onTabKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    const index = CODE_VIEWS.indexOf(route.view);
    const next =
      event.key === "ArrowRight" ? CODE_VIEWS[(index + 1) % CODE_VIEWS.length]
      : event.key === "ArrowLeft" ? CODE_VIEWS[(index - 1 + CODE_VIEWS.length) % CODE_VIEWS.length]
      : event.key === "Home" ? CODE_VIEWS[0]
      : event.key === "End" ? CODE_VIEWS[CODE_VIEWS.length - 1]
      : null;
    if (!next) return;
    event.preventDefault();
    select(next, true);
  };

  const header = (
    <PageHeader
      className="cv-head"
      title="Code"
      titleId="cv-title"
      purpose="Source review of the ingested repositories: how far it has got, what still blocks the next phase, and what it found."
      hidden={recordOpen}
      stats={trackDisabled ? [] : [
        { value: queueOpen, label: "open review jobs", title: "Review jobs queued, running, waiting on context or failed" },
        { value: awaiting, label: "awaiting a verdict", tone: awaiting ? "warning" : undefined, title: "Files whose suspicious review awaits a verdict" },
      ]}
      status={pending.size > 0 && !firstLoad ? "Updating…" : null}
    >
      {trackDisabled ? null : (
        <div className="cv-head-body">
          {knownPhase ? (
            <ol className="cv-stepper" aria-label="Code phases">
              {CODE_PHASES.map((phase) => {
                const state = phaseState(phase.key, persistedPhase);
                return (
                  <li key={phase.key} className={`cv-step cv-step-${state}`} aria-current={state === "active" ? "step" : undefined}>
                    <span className="cv-step-mark" aria-hidden="true">
                      {state === "completed" ? "✓" : state === "active" ? "●" : "○"}
                    </span>
                    <span>{phase.label}</span>
                    <span className="sr-only">
                      {state === "completed" ? " (done)" : state === "active" ? " (current)" : " (not started)"}
                    </span>
                  </li>
                );
              })}
            </ol>
          ) : (
            <p className="meta-text">
              No code phase recorded for this engagement (track state: <code>{persistedPhase}</code>); readiness is shown against completion.
            </p>
          )}

          <p className="cv-state" role="status">
            <strong>
              {knownPhase
                ? PHASE_STATE_LABELS[persistedPhase]
                : persistedPhase === "unknown" ? "Code track not started" : `Phase ${persistedPhase}`}
            </strong>
            {" · "}
            {data.readiness ? (
              data.readiness.transition_ready ? (
                <>Ready for {nextLabel}</>
              ) : (
                <>
                  {groups.length} {groups.length === 1 ? "thing blocks" : "things block"} {nextLabel}
                  {requiredCount > 0 && ` (${requiredCount} required)`}
                </>
              )
            ) : errors.some((error) => error.startsWith("next-transition")) ? (
              <>Readiness unavailable</>
            ) : (
              <>Checking readiness for {nextLabel}…</>
            )}
          </p>

          <KeyNumbers engagementKey={engagementKey} data={data} unknownDebtRepos={unknownDebt.size} />
        </div>
      )}
      {errors.length > 0 && (
        <p className="error-text" role="alert">
          Some code-review data is unavailable: {errors.join("; ")}{" "}
          <button type="button" className="ui-clear-filters" onClick={reload} disabled={pending.size > 0}>
            Try again
          </button>
        </p>
      )}
      <SlowLoadHint
        active={firstLoad}
        what="code review"
        detail="Readiness checks on large repositories can take several seconds."
      />
    </PageHeader>
  );

  if (trackDisabled) {
    return (
      <div className="cv">
        {header}
        <section className="panel">
          <EmptyState variant="empty" title="This engagement has no code track.">
            <p>
              No source repository has been ingested, and the engagement is not set up for code review, so nothing here
              is owed. Code review starts when a repository is ingested with <code>vigil assess code-ingest</code>.
            </p>
          </EmptyState>
        </section>
      </div>
    );
  }

  return (
    <div className="cv">
      {header}

      <div className="cv-tabs" role="tablist" aria-label="Code review sections" hidden={recordOpen}>
        {CODE_VIEWS.map((view) => {
          const selected = route.view === view;
          const count = viewCounts[view];
          return (
            <button
              key={view}
              ref={(node) => {
                tabRefs.current[view] = node;
              }}
              type="button"
              role="tab"
              id={`cv-tab-${view}`}
              aria-selected={selected}
              aria-controls="cv-panel"
              tabIndex={selected ? 0 : -1}
              className={`cv-tab${selected ? " is-active" : ""}`}
              onClick={() => select(view)}
              onKeyDown={onTabKey}
            >
              {VIEW_LABELS[view]}
              {count != null && (
                <span className="cv-count" title={viewCountTitles[view]}>
                  {count.toLocaleString()}
                  {viewCountTitles[view] ? <span className="sr-only"> {viewCountTitles[view].toLowerCase()}</span> : null}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <section
        className={`cv-panel${pending.size > 0 && !firstLoad ? " is-refreshing" : ""}`}
        id="cv-panel"
        role={recordOpen ? undefined : "tabpanel"}
        aria-labelledby={recordOpen ? undefined : `cv-tab-${route.view}`}
      >
        {firstLoad ? (
          <div className="panel">
            <CardSkeleton lines={5} />
          </div>
        ) : (
          <>
            {route.view === "overview" && (
              <CodeOverview
                engagementKey={engagementKey}
                data={data}
                groups={groups}
                nextLabel={nextLabel}
                targetIsCompletion={target === "complete"}
              />
            )}
            {route.view === "repositories" && (
              <CodeRepositories engagementKey={engagementKey} data={data} focusRepoId={route.repo} />
            )}
            {route.view === "queue" && (
              <CodeQueue
                engagementKey={engagementKey}
                data={data}
                errors={errorBySource}
                pending={pending}
                refreshVersion={liveVersion}
              />
            )}
            {route.view === "files" && (
              <CodeFiles engagementKey={engagementKey} data={data} repoFilter={route.repo} focus={route.focus} />
            )}
            {route.view === "results" && (
              <CodeResults engagementKey={engagementKey} refreshVersion={liveVersion} route={route} />
            )}
            {route.view === "quality" && <CodeQuality engagementKey={engagementKey} warnings={warnings} />}
            {route.view === "modules" && <CodeModules modules={data.modules} loading={pending.has("modules")} />}
          </>
        )}
      </section>
    </div>
  );
}

function KeyNumbers({
  engagementKey,
  data,
  unknownDebtRepos,
}: {
  engagementKey: string;
  data: ReturnType<typeof useCodeData>["data"];
  unknownDebtRepos: number;
}) {
  const files = fileReviewTotals(data.coverage);
  const gap = finishedNotReviewed(data.progress);
  const critical = classReviewTotals(data.coverage, "critical");
  const high = classReviewTotals(data.coverage, "high");
  const findings = data.coverage?.findings_summary;
  const leads = pendingLeads(data.coverage);
  const debt = data.readiness?.structural_debt_count;
  const severities = ["critical", "high", "medium", "low", "info"].filter(
    (severity) => (findings?.by_severity[severity] ?? 0) > 0,
  );
  const ratio = (totals: ReviewTotals | null) =>
    totals ? `${totals.reviewed.toLocaleString()} / ${totals.total.toLocaleString()}` : "—";

  const items: Array<{ label: string; value: string; detail?: string; href: string }> = [
    {
      label: "Files reviewed",
      value: ratio(files),
      // Done jobs that do not count yet explain a low number (the queue view says why).
      detail: gap ? `${gap.finished.toLocaleString()} finished · ${gap.reviewed.toLocaleString()} count as reviewed` : undefined,
      href: codeViewHref(engagementKey, gap ? { view: "queue" } : { view: "files", focus: "risk" }),
    },
    { label: "Critical reviewed", value: ratio(critical), href: codeViewHref(engagementKey, { view: "files", focus: "risk" }) },
    { label: "High reviewed", value: ratio(high), href: codeViewHref(engagementKey, { view: "files", focus: "risk" }) },
    {
      label: "Code findings",
      value: findings ? findings.total_code_findings.toLocaleString() : "—",
      detail: severities.map((severity) => `${findings!.by_severity[severity]} ${severity}`).join(" · ") || undefined,
      // Code findings are the ones located in a source file (Findings search grammar).
      href: engagementHref(engagementKey, { tab: "findings", q: "location:file:" }),
    },
    {
      label: "Need a direct read",
      value: debt == null ? "—" : unknownDebtRepos > 0 && debt === 0 ? "Unknown" : debt.toLocaleString(),
      detail: unknownDebtRepos > 0
        ? `${debt ? "+ unknown: " : ""}code index out of date in ${unknownDebtRepos} ${unknownDebtRepos === 1 ? "repository" : "repositories"}`
        : undefined,
      href: codeViewHref(engagementKey, { view: "files", focus: "direct" }),
    },
    {
      label: "Leads to follow",
      value: leads == null ? "—" : leads.toLocaleString(),
      href: codeViewHref(engagementKey, { view: "queue" }),
    },
  ];

  return (
    <ul className="cv-numbers" aria-label="Key numbers">
      {items.map((item) => (
        <li key={item.label}>
          <a className="cv-number" href={item.href}>
            <span className="cv-number-label">{item.label}</span>
            <span className="cv-number-value">{item.value}</span>
            {item.detail && <span className="cv-number-detail">{item.detail}</span>}
          </a>
        </li>
      ))}
    </ul>
  );
}
