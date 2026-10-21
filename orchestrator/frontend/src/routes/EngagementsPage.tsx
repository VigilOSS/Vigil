import { useEffect, useMemo, useRef, useState } from "react";
import { MoreHorizontal } from "lucide-react";
import {
  deleteEngagement,
  getDashboardSummary,
  type DashboardSummary,
  type Engagement,
} from "../lib/api";
import { ThemeToggle } from "../components/ThemeToggle";
import { TimeStamp } from "../components/formatting";
import { compareServerTime } from "../lib/serverTime";
import { CardSkeleton, ChartSkeleton } from "../components/Skeletons";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { SeverityMiniBar } from "../components/charts/SeverityMiniBar";
import { SummaryStatBar } from "../components/charts/SummaryStatBar";
import type { SummaryStatBarItem } from "../components/charts/SummaryStatBar";
import { ResultsSummary, SortIndicator, StatusPill, compareStatus, describeSort, statusLabel, type SortDirection, type SortKind } from "../components/ui";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import "../styles/workspace.css";

type EngagementsPageProps = {
  engagements: Engagement[];
  loading?: boolean;
  loadError?: string | null;
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
// The ledger column each sort orders (none for "created", which the ledger
// does not show), and the words for the order under the search.
type LedgerColumn = "engagement" | "lifecycle" | "findings" | "updated";
const ENGAGEMENT_SORT_ORDER: Record<EngagementSort, { column: LedgerColumn | null; label: string; direction: SortDirection; kind: SortKind }> = {
  activity: { column: "updated", label: "Updated", direction: "desc", kind: "time" },
  created: { column: null, label: "Created", direction: "desc", kind: "time" },
  findings: { column: "findings", label: "Current findings", direction: "desc", kind: "number" },
  target: { column: "engagement", label: "Engagement", direction: "asc", kind: "text" },
  status: { column: "lifecycle", label: "Lifecycle", direction: "desc", kind: "status" },
};
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


export function EngagementsPage({
  engagements,
  loading = false,
  loadError = null,
  onOpenEngagement,
  onEngagementDeleted,
}: EngagementsPageProps) {
  const [pendingDelete, setPendingDelete] = useState<Engagement | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [sort, setSort] = useState<EngagementSort>(() => readEngagementSort());
  const [query, setQuery] = useState("");
  const deleteDialogRef = useRef<HTMLDivElement | null>(null);
  const deleteOpenerRef = useRef<HTMLElement | null>(null);

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
    const needle = query.trim().toLowerCase();
    const copy = engagements.filter(row => !needle || `${row.target} ${row.key} ${row.status} ${statusLabel("engagement", row.status)}`.toLowerCase().includes(needle));
    copy.sort((a, b) => {
      switch (sort) {
        case "created":
          return compareServerTime(a.created_at, b.created_at, "desc");
        case "findings": {
          const ca = findingByKey.get(a.key)?.count ?? -1;
          const cb = findingByKey.get(b.key)?.count ?? -1;
          if (cb !== ca) return cb - ca;
          return (a.target || a.key).localeCompare(b.target || b.key);
        }
        case "target":
          return (a.target || a.key).localeCompare(b.target || b.key);
        case "status": {
          // Lifecycle order (in progress, completed, archived), not alphabetical.
          const cmp = compareStatus("engagement", a.status, b.status);
          if (cmp !== 0) return cmp;
          return (a.target || a.key).localeCompare(b.target || b.key);
        }
        case "activity":
        default:
          return compareServerTime(a.updated_at, b.updated_at, "desc");
      }
    });
    return copy;
  }, [engagements, sort, findingByKey, query]);

  const order = ENGAGEMENT_SORT_ORDER[sort];
  const sortHeader = (column: LedgerColumn, label: string) => (
    <th aria-sort={order.column === column ? (order.direction === "asc" ? "ascending" : "descending") : undefined}>
      {label}
      {order.column === column && <> <SortIndicator direction={order.direction} /></>}
    </th>
  );

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
      { label: "Current findings", value: totals?.total ?? 0 },
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

  const resetDialog = () => {
    setPendingDelete(null);
    setConfirmText("");
    setDeleteError(null);
    setIsSubmitting(false);
  };
  const closeDialog = () => {
    if (isSubmitting) return;
    resetDialog();
  };
  useBodyScrollLock(pendingDelete != null);
  useModalFocus(deleteDialogRef, closeDialog, pendingDelete != null, deleteOpenerRef);

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
      resetDialog();
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
    <main className="shell dashboard-shell engagement-index">
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Vigil workspace</p>
          <h1>Engagements</h1>
          <p className="lead">
            Engagement state, enabled tracks, and the findings ledger.
          </p>
        </div>
        <div className="page-actions">
          <input className="filter-input" type="search" aria-label="Search engagements" placeholder="Search engagements" value={query} onChange={event => setQuery(event.target.value)} />
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

          <details className="index-distribution"><summary>Severity and lifecycle distribution</summary><div className="dashboard-charts-row">
            <div className="panel dashboard-chart-card v-card-enter v-stagger-2">
              <div className="panel-header">
                <h2>Current findings by severity</h2>
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
                      <span className="dashboard-status-label">{statusLabel("engagement", statusName)}</span>
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
          </div></details>
        </section>
      ) : null}

      <section className="engagement-ledger">
        <p className="meta-text">Current findings exclude merged and false-positive records.</p>
        {engagements.length > 0 && (
          <ResultsSummary
            shown={sortedEngagements.length}
            total={engagements.length}
            noun="engagements"
            sort={describeSort(order.label, order.direction, order.kind)}
          />
        )}
        {loadError ? (
          <section className="panel empty-state error-text" role="alert">
            Engagement list unavailable: {loadError}
          </section>
        ) : null}
        {sortedEngagements.length > 0 && <div className="engagement-ledger-scroll" role="region" aria-label="Engagement ledger" tabIndex={0}><table className="engagement-ledger-table" aria-label="Engagements">
          <thead><tr>{sortHeader("engagement", "Engagement")}{sortHeader("lifecycle", "Lifecycle")}<th>Enabled tracks</th>{sortHeader("findings", "Current findings")}{sortHeader("updated", "Updated")}<th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>{sortedEngagements.map((engagement) => {
          const rollup = findingByKey.get(engagement.key);
          return (
            <tr key={engagement.key}>
              <td>
                    <button
                      type="button"
                      className="engagement-open-button"
                      aria-label={`Open engagement ${engagement.key}`}
                      onClick={() => onOpenEngagement(engagement.key)}
                    >
                      {engagement.target}
                    </button>
                  <p className="meta-text">{engagement.key}</p>
              </td>
              <td><StatusPill domain="engagement" value={engagement.status || "unknown"} size="sm" /></td>
              <td><div className="index-track-list">{Object.entries(engagement.track_state ?? {}).map(([name, state]) => <span key={name}>{name}: {state.phase || "unknown"}</span>)}
                {Object.keys(engagement.track_state ?? {}).length === 0 && <span className="meta-text">Track state unavailable · legacy: {engagement.current_phase}</span>}
                {engagement.aggregate_complete === true && <span className="meta-text">All tracks complete</span>}
              </div></td>
              <td>{rollup ? <><strong>{rollup.count}</strong>{rollup.count > 0 && <SeverityMiniBar counts={rollup.severities} />}</> : <span className="meta-text">Unavailable</span>}</td>
              <td><TimeStamp value={engagement.updated_at} fallback="Unknown" />{engagement.session_count > 0 && <p className="meta-text">{engagement.session_count} {engagement.session_count === 1 ? "session" : "sessions"}</p>}</td>
              <td>
                <RowActions
                  engagementKey={engagement.key}
                  onDelete={(opener) => {
                    deleteOpenerRef.current = opener;
                    setPendingDelete(engagement);
                    setConfirmText("");
                    setDeleteError(null);
                  }}
                />
              </td>
            </tr>
          );
        })}</tbody></table></div>}
        {engagements.length > 0 && sortedEngagements.length === 0 && <p className="empty-state">No engagements match your search.</p>}
        {engagements.length === 0 && loading ? (
          // Initial load: skeleton cards stand in for the engagement list
          // until the first listing resolves, so cold load doesn't flash the
          // empty state.
          Array.from({ length: 3 }).map((_, i) => (
            <CardSkeleton key={i} lines={2} className="engagement-card" />
          ))
        ) : null}
        {engagements.length === 0 && !loading && !loadError ? (
          <section className="panel empty-state">No engagements discovered under <code>agent/engagements</code>.</section>
        ) : null}
      </section>

      {pendingDelete ? (
        <div
          className="finding-overlay"
          onClick={closeDialog}
          role="presentation"
        >
          <div
            ref={deleteDialogRef}
            className="panel finding-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-engagement-title"
            tabIndex={-1}
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

// Per-row secondary actions behind one quiet button, so the ledger does not
// carry a destructive control on every row. Delete still opens the typed
// confirmation dialog.
function RowActions({ engagementKey, onDelete }: { engagementKey: string; onDelete: (opener: HTMLElement) => void }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const itemRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    itemRef.current?.focus();
    const close = (event: Event) => {
      if (event.target instanceof Node && wrapRef.current?.contains(event.target)) return;
      setOpen(false);
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("focusin", close);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("focusin", close);
    };
  }, [open]);

  return (
    <div className="engagement-row-actions" ref={wrapRef}>
      <button
        ref={buttonRef}
        type="button"
        className="engagement-row-actions-button"
        aria-label={`Actions for engagement ${engagementKey}`}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Engagement actions"
        onClick={() => setOpen((value) => !value)}
      >
        <MoreHorizontal size={16} aria-hidden="true" />
      </button>
      {open && (
        <div className="engagement-row-menu" role="menu" aria-label={`Actions for engagement ${engagementKey}`}>
          <button
            ref={itemRef}
            type="button"
            role="menuitem"
            className="engagement-row-menu-danger"
            aria-label={`Delete engagement ${engagementKey}`}
            title="Delete engagement and all findings, probes, command runs, and code analysis."
            onKeyDown={(event) => {
              if (event.key === "Escape" || event.key === "Tab") {
                if (event.key === "Escape") event.preventDefault();
                setOpen(false);
                buttonRef.current?.focus();
              }
            }}
            onClick={() => {
              setOpen(false);
              if (buttonRef.current) onDelete(buttonRef.current);
            }}
          >
            Delete engagement…
          </button>
        </div>
      )}
    </div>
  );
}
