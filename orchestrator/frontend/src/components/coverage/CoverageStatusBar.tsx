// Engagement-wide status distribution: a stacked bar plus a legend that names
// each status, its count and share, and what it means in plain words.

import { Skeleton } from "../Skeletons";
import { StatusPill } from "../ui";
import { compareCoverageStatus, coverageStatusLabel, coverageStatusMeaning } from "./coverageStatus";

type Props = {
  totals: Record<string, number> | null;
  /** One-line legend (meanings move to tooltips and screen-reader text). */
  compact?: boolean;
  /** Show the items behind one status. */
  onPickStatus: (status: string) => void;
};

function share(count: number, total: number): string {
  if (total <= 0) return "0%";
  const pct = (count / total) * 100;
  if (pct > 0 && pct < 0.1) return "<0.1%";
  return `${pct >= 10 ? pct.toFixed(0) : pct.toFixed(1)}%`;
}

export function CoverageStatusBar({ totals, compact = false, onPickStatus }: Props) {
  if (!totals) {
    return (
      <div className="cov-statusbar" aria-busy="true">
        <Skeleton height={12} rounded />
        <div className={`cov-legend ${compact ? "is-compact" : ""}`}>
          {Array.from({ length: 5 }).map((_, index) => (
            <Skeleton key={index} width="100%" height={compact ? 26 : 46} />
          ))}
        </div>
      </div>
    );
  }
  const statuses = Object.keys(totals).filter((status) => totals[status] > 0).sort(compareCoverageStatus);
  const total = statuses.reduce((sum, status) => sum + totals[status], 0);
  // An empty ledger has no distribution; the page body says it is empty.
  if (total === 0) return null;
  const description = statuses.map((status) => `${coverageStatusLabel(status)} ${totals[status].toLocaleString()}`).join(", ");
  return (
    <div className="cov-statusbar">
      <div className="cov-bar" role="img" aria-label={`Coverage status of all ${total.toLocaleString()} items: ${description}`}>
        {statuses.map((status) => (
          <span
            key={status}
            className={`cov-bar-segment cov-status-${status}`}
            style={{ width: `${(totals[status] / total) * 100}%` }}
            title={`${coverageStatusLabel(status)}: ${totals[status].toLocaleString()} (${share(totals[status], total)})`}
          />
        ))}
      </div>
      <ul className={`cov-legend ${compact ? "is-compact" : ""}`} aria-label="Status legend">
        {statuses.map((status) => (
          <li key={status}>
            <button
              type="button"
              className="cov-legend-item"
              onClick={() => onPickStatus(status)}
              title={compact ? coverageStatusMeaning(status) : undefined}
            >
              <span className="cov-legend-top">
                <StatusPill domain="coverage" value={status} title={compact ? coverageStatusMeaning(status) : undefined} />
                <strong>{totals[status].toLocaleString()}</strong>
                <span className="meta-text">{share(totals[status], total)}</span>
              </span>
              <span className={compact ? "sr-only" : "cov-legend-meaning"}>{coverageStatusMeaning(status)}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
