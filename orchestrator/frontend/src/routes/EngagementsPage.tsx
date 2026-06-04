import { useEffect, useMemo, useState } from "react";
import {
  deleteEngagement,
  getDashboardSummary,
  type DashboardSummary,
  type Engagement,
} from "../lib/api";
import { ThemeToggle } from "../components/ThemeToggle";
import { CardSkeleton, ChartSkeleton } from "../components/Skeletons";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { SeverityMiniBar } from "../components/charts/SeverityMiniBar";
import { SummaryStatBar } from "../components/charts/SummaryStatBar";
import type { SummaryStatBarItem } from "../components/charts/SummaryStatBar";

type EngagementsPageProps = {
  engagements: Engagement[];
  loading?: boolean;
  onOpenEngagement: (engagementKey: string) => void;
  onEngagementDeleted?: (engagementKey: string) => void;
};

// Landing sort. Each option encodes its own direction (no separate asc/desc
// toggle) so a single select fully describes the order — the cleaner UX for a
// short, fixed option set. Persisted to localStorage (mirrors FindingsTab's
// readFindingsView idiom) so the choice survives reload. Default = "activity"
// (updated_at desc → newest activity first), matching the brief.
type EngagementSort = "activity" | "created" | "findings" | "target" | "status";
const ENGAGEMENT_SORT_KEY = "engagements.sort";
const ENGAGEMENT_SORT_OPTIONS: { value: EngagementSort; label: string }[] = [
  { value: "activity", label: "Latest activity" },
  { value: "created", label: "Recently created" },
  { value: "findings", label: "Findings" },
  { value: "target", label: "Target (A–Z)" },
  { value: "status", label: "Status" },
];
function isEngagementSort(value: string | null): value is EngagementSort {
  return value != null && ENGAGEMENT_SORT_OPTIONS.some((o) => o.value === value);
}
function readEngagementSort(): EngagementSort {
  try {
    const raw = window.localStorage.getItem(ENGAGEMENT_SORT_KEY);
    return isEngagementSort(raw) ? raw : "activity";
  } catch {
    return "activity";
  }
}

// Status breakdown bars are sorted so the most-common status reads first.
function sortedStatusBreakdown(byStatus: Record<string, number>): [string, number][] {
  return Object.entries(byStatus).sort((a, b) => b[1] - a[1]);
}

// Newest-first comparator over ISO timestamps; unparseable / missing values
// sort last so live engagements stay above malformed rows.
function descByIso(a: string | undefined, b: string | undefined): number {
  const ta = a ? new Date(a).getTime() : NaN;
  const tb = b ? new Date(b).getTime() : NaN;
  const va = Number.isNaN(ta) ? -Infinity : ta;
  const vb = Number.isNaN(tb) ? -Infinity : tb;
  return vb - va;
}

export function EngagementsPage({ engagements, loading = false, onOpenEngagement, onEngagementDeleted }: EngagementsPageProps) {
  const [pendingDelete, setPendingDelete] = useState<Engagement | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [sort, setSort] = useState<EngagementSort>(() => readEngagementSort());

  // Persist the chosen sort so it survives reload (FindingsTab persistence idiom).
  useEffect(() => {
    try {
      window.localStorage.setItem(ENGAGEMENT_SORT_KEY, sort);
    } catch {
      // ignore
    }
  }, [sort]);

  // Cross-engagement dashboard summary. Fetched here (not via App) with its own
  // state. `summary === null` while loading; `summaryUnavailable` is set when
  // the endpoint fails (e.g. an older backend without /dashboard/summary), in
  // which case the dashboard sections hide and the plain list still renders.
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [summaryUnavailable, setSummaryUnavailable] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function refreshSummary() {
      try {
        const next = await getDashboardSummary();
        if (!cancelled) {
          setSummary(next);
          setSummaryUnavailable(false);
        }
      } catch {
        // Tolerate the endpoint failing: hide the dashboard sections, keep the
        // engagement list working.
        if (!cancelled) {
          setSummaryUnavailable(true);
        }
      }
    }

    void refreshSummary();
    // Light polling keeps the cross-engagement rollup fresh while the operator
    // lingers on the landing page, matching App's engagement-list cadence.
    const interval = window.setInterval(() => {
      if (document.hidden) {
        return;
      }
      void refreshSummary();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  // Per-engagement finding rollup keyed by engagement key, so the existing
  // cards can show a severity mini-bar + finding-count badge.
  const findingByKey = useMemo(() => {
    const map = new Map<string, { count: number; severities: Record<string, number> }>();
    for (const row of summary?.engagements ?? []) {
      map.set(row.key, { count: row.finding_count, severities: row.finding_severities });
    }
    return map;
  }, [summary]);

  // Render a SORTED COPY — never mutate the `engagements` prop. The dashboard
  // aggregate sections above are order-independent totals and stay untouched.
  // "Findings" joins the per-engagement count from the dashboard summary by key
  // (engagements with no summary row count as -1 so they sort last, desc).
  const sortedEngagements = useMemo(() => {
    const copy = [...engagements];
    copy.sort((a, b) => {
      switch (sort) {
        case "created":
          return descByIso(a.created_at, b.created_at);
        case "findings": {
          const ca = findingByKey.get(a.key)?.count ?? -1;
          const cb = findingByKey.get(b.key)?.count ?? -1;
          if (cb !== ca) return cb - ca;
          return (a.target || a.key).localeCompare(b.target || b.key);
        }
        case "target":
          return (a.target || a.key).localeCompare(b.target || b.key);
        case "status": {
          const cmp = (a.status || "").localeCompare(b.status || "");
          if (cmp !== 0) return cmp;
          return (a.target || a.key).localeCompare(b.target || b.key);
        }
        case "activity":
        default:
          return descByIso(a.updated_at, b.updated_at);
      }
    });
    return copy;
  }, [engagements, sort, findingByKey]);

  const statBarItems: SummaryStatBarItem[] = useMemo(() => {
    const counts = summary?.engagement_counts;
    const totals = summary?.finding_totals;
    const inProgress = counts?.by_status?.in_progress ?? 0;
    const critHigh = (totals?.by_severity?.critical ?? 0) + (totals?.by_severity?.high ?? 0);
    const activePhases = Object.keys(counts?.by_phase ?? {}).length;
    const customers = new Set(
      (summary?.engagements ?? [])
        .map((row) => row.customer)
        .filter((customer): customer is string => Boolean(customer)),
    ).size;
    return [
      { label: "Engagements", value: counts?.total ?? 0 },
      { label: "In progress", value: inProgress },
      { label: "Findings", value: totals?.total ?? 0 },
      { label: "Crit/High", value: critHigh, tone: critHigh > 0 ? "danger" : "ok" },
      { label: "Active phases", value: activePhases },
      { label: "Customers", value: customers },
    ];
  }, [summary]);

  const statusBreakdown = useMemo(
    () => sortedStatusBreakdown(summary?.engagement_counts.by_status ?? {}),
    [summary],
  );
  const statusBreakdownMax = statusBreakdown.reduce((max, [, n]) => Math.max(max, n), 0);

  const closeDialog = () => {
    setPendingDelete(null);
    setConfirmText("");
    setDeleteError(null);
    setIsSubmitting(false);
  };

  const submitDelete = async () => {
    if (!pendingDelete) return;
    if (confirmText !== pendingDelete.key) {
      setDeleteError("Typed key does not match.");
      return;
    }
    setIsSubmitting(true);
    setDeleteError(null);
    try {
      await deleteEngagement(pendingDelete.key);
      const deletedKey = pendingDelete.key;
      closeDialog();
      onEngagementDeleted?.(deletedKey);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
      setIsSubmitting(false);
    }
  };

  // The dashboard sections only render once we have a summary and it isn't
  // marked unavailable. While the first fetch is in flight we show chart
  // skeletons; on failure we hide the whole dashboard block.
  const showDashboard = !summaryUnavailable;
  const summaryLoading = summary === null;
  const severityTotals = summary?.finding_totals.by_severity ?? {};

  return (
    <main className="shell dashboard-shell">
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>Engagements</h1>
          <p className="lead">
            Local orchestrator view for the configured install root. Each engagement may carry multiple AI sessions.
          </p>
        </div>
        <div className="page-actions">
          <div className="filter-select-group">
            <label className="filter-label" htmlFor="engagement-sort">Sort</label>
            <select
              id="engagement-sort"
              className="filter-select"
              value={sort}
              onChange={(e) => setSort(e.target.value as EngagementSort)}
            >
              {ENGAGEMENT_SORT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
          <ThemeToggle />
        </div>
      </section>

      {/* ---- dashboard landing ---- */}
      {showDashboard ? (
        <section className="dashboard-landing" aria-label="Cross-engagement summary">
          <div className="panel dashboard-statbar-panel v-card-enter v-stagger-1">
            {summaryLoading ? (
              <CardSkeleton lines={1} title={false} />
            ) : (
              <SummaryStatBar items={statBarItems} />
            )}
          </div>

          <div className="dashboard-charts-row">
            <div className="panel dashboard-chart-card v-card-enter v-stagger-2">
              <div className="panel-header">
                <h2>Findings by severity</h2>
              </div>
              {summaryLoading ? (
                <ChartSkeleton variant="donut" height={160} label="Severity mix" />
              ) : (
                <SeverityDonut counts={severityTotals} size={160} legend />
              )}
            </div>

            <div className="panel dashboard-chart-card v-card-enter v-stagger-3">
              <div className="panel-header">
                <h2>Engagements by status</h2>
              </div>
              {summaryLoading ? (
                <ChartSkeleton variant="bar" height={160} />
              ) : statusBreakdown.length > 0 ? (
                <ul className="dashboard-status-breakdown">
                  {statusBreakdown.map(([statusName, count]) => (
                    <li key={statusName} className="dashboard-status-row">
                      <span className="dashboard-status-label">{statusName.replace(/_/g, " ")}</span>
                      <span className="dashboard-status-track" aria-hidden="true">
                        <span
                          className="dashboard-status-fill"
                          style={{ width: `${statusBreakdownMax > 0 ? (count / statusBreakdownMax) * 100 : 0}%` }}
                        />
                      </span>
                      <span className="dashboard-status-count">{count}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="meta-text">No engagements yet.</p>
              )}
            </div>
          </div>
        </section>
      ) : null}

      <section className="engagement-column">
        {sortedEngagements.map((engagement, index) => {
          const rollup = findingByKey.get(engagement.key);
          return (
            <article
              className="panel engagement-card engagement-card-clickable v-card-enter"
              style={{ animationDelay: `${Math.min(index, 6) * 60}ms` }}
              key={engagement.key}
              onClick={() => onOpenEngagement(engagement.key)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter") onOpenEngagement(engagement.key); }}
            >
              <div className="engagement-heading">
                <div>
                  <h2>{engagement.target}</h2>
                  <p className="meta-text">{engagement.key}</p>
                </div>
                <div className="engagement-actions">
                  {rollup ? (
                    <span
                      className="badge engagement-finding-badge"
                      title={`${rollup.count} live finding${rollup.count !== 1 ? "s" : ""}`}
                    >
                      {rollup.count} finding{rollup.count !== 1 ? "s" : ""}
                    </span>
                  ) : null}
                  <span className={`status-pill status-${engagement.status}`}>{engagement.status}</span>
                  <button
                    type="button"
                    className="engagement-delete-button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setPendingDelete(engagement);
                      setConfirmText("");
                      setDeleteError(null);
                    }}
                    aria-label={`Delete engagement ${engagement.key}`}
                    title="Delete engagement and all findings, probes, command runs, and code analysis."
                  >
                    Delete
                  </button>
                </div>
              </div>
              <p className="meta-text">
                Phase: {engagement.current_phase} &middot; {engagement.session_count} session{engagement.session_count !== 1 ? "s" : ""}
              </p>
              {rollup && rollup.count > 0 ? (
                <SeverityMiniBar counts={rollup.severities} />
              ) : null}
            </article>
          );
        })}
        {engagements.length === 0 && loading ? (
          // Initial load: skeleton cards stand in for the engagement list
          // until the first listing resolves, so cold load doesn't flash the
          // empty state.
          Array.from({ length: 3 }).map((_, i) => (
            <CardSkeleton key={i} lines={2} className="engagement-card" />
          ))
        ) : null}
        {engagements.length === 0 && !loading ? (
          <section className="panel empty-state">No engagements discovered under `agent/engagements`.</section>
        ) : null}
      </section>

      {pendingDelete ? (
        <div
          className="finding-overlay"
          onClick={closeDialog}
          role="presentation"
        >
          <div
            className="panel finding-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-engagement-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="delete-engagement-title">Delete engagement?</h2>
            <p>
              This will permanently remove <strong>{pendingDelete.key}</strong> and
              cascade-delete every associated finding, probe run, command-run audit
              record, credential, code analysis result, and attack chain. This
              cannot be undone from the UI.
            </p>
            <p className="meta-text">
              The filesystem directory under <code>agent/engagements/</code> is not
              touched — remove that yourself if you want the engagement gone from
              both the DB and disk.
            </p>
            <label className="delete-confirm-label">
              Type <code>{pendingDelete.key}</code> to confirm:
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                autoFocus
                spellCheck={false}
                autoComplete="off"
              />
            </label>
            {deleteError ? <p className="error-text">{deleteError}</p> : null}
            <div className="finding-modal-actions">
              <button type="button" onClick={closeDialog} disabled={isSubmitting}>
                Cancel
              </button>
              <button
                type="button"
                className="engagement-delete-button"
                onClick={submitDelete}
                disabled={isSubmitting || confirmText !== pendingDelete.key}
              >
                {isSubmitting ? "Deleting..." : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}
