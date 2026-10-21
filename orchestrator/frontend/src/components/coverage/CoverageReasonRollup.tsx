// "Open work by reason": for each status, the latest recorded reasons with how
// many items share each one. Picking a reason opens All items filtered to it.

import { useLayoutEffect, useRef, useState } from "react";
import type { AssessmentServiceGap } from "../../lib/api";
import type { CoverageReasonEntry, CoverageReasonGroup, CoverageReasonRollup as Rollup } from "../../lib/coverageApi";
import { TimeStamp } from "../formatting";
import { CardSkeleton, SlowLoadHint } from "../Skeletons";
import { EmptyState, StatusPill } from "../ui";
import { compareCoverageStatus, coverageStatusMeaning } from "./coverageStatus";

// Each status opens with its most common reasons; the rest is one click away.
const REASONS_COLLAPSED = 5;

type Props = {
  rollup: Rollup | null;
  loading: boolean;
  error: string | null;
  /** Re-reads after a failed load. */
  onRetry: () => void;
  includeClosed: boolean;
  onIncludeClosedChange: (value: boolean) => void;
  /** True once every reason (not just the top ones) has been requested. */
  showingAllReasons: boolean;
  onShowAllReasons: () => void;
  onPickReason: (status: string, entry: CoverageReasonEntry) => void;
  serviceGaps: AssessmentServiceGap[];
  /** Engagement-wide item count, when known (an empty ledger reads differently). */
  ledgerTotal: number | null;
};

function ReasonRow({
  status,
  entry,
  groupCount,
  onPick,
}: {
  status: string;
  entry: CoverageReasonEntry;
  groupCount: number;
  onPick: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const textRef = useRef<HTMLParagraphElement | null>(null);
  // Offer "Show full reason" only when the clamp actually hides text.
  useLayoutEffect(() => {
    const element = textRef.current;
    if (!element || expanded) return undefined;
    const measure = () => setOverflows(element.scrollHeight > element.clientHeight + 1);
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [entry.reason, expanded]);
  const share = groupCount > 0 ? entry.count / groupCount : 0;
  return (
    <li className="cov-reason">
      <div className="cov-reason-count">
        <strong>{entry.count.toLocaleString()}</strong>
        <span className="cov-reason-share" aria-hidden="true">
          <span className={`cov-reason-share-fill cov-status-${status}`} style={{ width: `${Math.max(share * 100, 1.5)}%` }} />
        </span>
        <span className="cov-reason-pct">{share >= 0.001 ? `${(share * 100).toFixed(share >= 0.1 ? 0 : 1)}%` : "<0.1%"}</span>
      </div>
      <div className="cov-reason-text">
        {entry.reason ? (
          <p ref={textRef} className={expanded ? undefined : "is-clamped"}>{entry.reason}</p>
        ) : (
          <p className="cov-reason-none">
            No reason recorded yet <span className="meta-text">· created from: {entry.created_from || "—"}</span>
          </p>
        )}
        {overflows || expanded ? (
          <button type="button" className="cov-text-button" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>
            {expanded ? "Show less" : "Show full reason"}
          </button>
        ) : null}
      </div>
      <button type="button" className="cov-reason-open" onClick={onPick}>
        View {entry.count === 1 ? "item" : `${entry.count.toLocaleString()} items`}
        <span aria-hidden="true"> →</span>
      </button>
    </li>
  );
}

function StatusGroup({
  group,
  showingAllReasons,
  onShowAllReasons,
  onPickReason,
}: {
  group: CoverageReasonGroup;
  showingAllReasons: boolean;
  onShowAllReasons: () => void;
  onPickReason: (status: string, entry: CoverageReasonEntry) => void;
}) {
  const headingId = `cov-reasons-${group.status}`;
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? group.reasons : group.reasons.slice(0, REASONS_COLLAPSED);
  const collapsedCount = group.reasons.length - visible.length;
  const collapsedItems = group.reasons.slice(visible.length).reduce((sum, entry) => sum + entry.count, 0);
  return (
    <section className="panel cov-reason-group" aria-labelledby={headingId}>
      <header className="cov-reason-group-head">
        <h3 id={headingId}>
          <StatusPill domain="coverage" value={group.status} />
          <span>{group.count.toLocaleString()} {group.count === 1 ? "item" : "items"}</span>
        </h3>
        <p className="meta-text">
          {coverageStatusMeaning(group.status)} {group.distinct.toLocaleString()} distinct{" "}
          {group.distinct === 1 ? "reason" : "reasons"}.
        </p>
      </header>
      <ol className="cov-reason-list">
        {visible.map((entry) => (
          <ReasonRow
            key={`${entry.reason ?? ""}\u0000${entry.created_from ?? ""}`}
            status={group.status}
            entry={entry}
            groupCount={group.count}
            onPick={() => onPickReason(group.status, entry)}
          />
        ))}
      </ol>
      {collapsedCount > 0 || (expanded && group.reasons.length > REASONS_COLLAPSED) ? (
        <p className="cov-reason-more">
          <button type="button" className="cov-text-button" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>
            {expanded
              ? `Show only the top ${REASONS_COLLAPSED} reasons`
              : `Show ${collapsedCount.toLocaleString()} more ${collapsedCount === 1 ? "reason" : "reasons"} (${collapsedItems.toLocaleString()} ${collapsedItems === 1 ? "item" : "items"})`}
          </button>
        </p>
      ) : null}
      {group.omitted_count > 0 && (expanded || group.reasons.length <= REASONS_COLLAPSED) ? (
        <p className="cov-reason-more">
          {(group.distinct - group.reasons.length).toLocaleString()} less common reasons cover{" "}
          {group.omitted_count.toLocaleString()} more items.{" "}
          {!showingAllReasons ? (
            <button type="button" className="cov-text-button" onClick={onShowAllReasons}>
              Show every reason
            </button>
          ) : null}
        </p>
      ) : null}
    </section>
  );
}

export function CoverageReasonRollup({
  rollup,
  loading,
  error,
  onRetry,
  includeClosed,
  onIncludeClosedChange,
  showingAllReasons,
  onShowAllReasons,
  onPickReason,
  serviceGaps,
  ledgerTotal,
}: Props) {
  const groups = [...(rollup?.statuses ?? [])].sort((a, b) => compareCoverageStatus(a.status, b.status));
  return (
    <div className="cov-rollup" aria-busy={loading}>
      <div className="cov-rollup-bar">
        <p className="meta-text">
          {rollup
            ? `${rollup.total.toLocaleString()} ${includeClosed ? "items" : "open items"}, grouped by the latest reason recorded for each.`
            : "Grouping items by their latest recorded reason…"}
          {loading && rollup ? <span className="cov-refreshing"> Refreshing…</span> : null}
        </p>
        <label className="cov-check">
          <input type="checkbox" checked={includeClosed} onChange={(event) => onIncludeClosedChange(event.target.checked)} />
          Include covered and not-applicable items
        </label>
      </div>
      {error ? (
        <p className="error-text" role="alert">
          Reason rollup unavailable: {error}{" "}
          <button type="button" className="ui-clear-filters" onClick={onRetry} disabled={loading}>
            Try again
          </button>
        </p>
      ) : null}
      {!rollup && loading ? (
        <div className="cov-rollup-loading" role="status">
          <CardSkeleton lines={4} />
          <CardSkeleton lines={3} />
          <SlowLoadHint active={loading} what="the reason groups" detail="Large ledgers take a few seconds." />
        </div>
      ) : null}
      {rollup && groups.length === 0 ? (
        <div className="panel">
          {includeClosed || ledgerTotal === 0 ? (
            <EmptyState variant="empty" title="No coverage items recorded yet.">
              Items appear as Vigil observes the target's requests and services.
            </EmptyState>
          ) : (
            <EmptyState variant="empty" title="No open coverage work.">
              Every item is covered or not applicable. Include covered and not-applicable items to see them grouped by reason.
            </EmptyState>
          )}
        </div>
      ) : null}
      <div className={`cov-rollup-groups ${loading && rollup ? "cov-stale" : ""}`}>
        {groups.map((group) => (
          <StatusGroup
            key={group.status}
            group={group}
            showingAllReasons={showingAllReasons}
            onShowAllReasons={onShowAllReasons}
            onPickReason={onPickReason}
          />
        ))}
      </div>
      {serviceGaps.length > 0 ? (
        <details className="panel cov-service-gaps">
          <summary>
            Service-level status <span className="meta-text">· {serviceGaps.length} most recently updated open services</span>
          </summary>
          <p className="meta-text">
            A service's status rolls up its service-bound items, which are already counted in the reasons above.
          </p>
          <ul>
            {serviceGaps.map((gap, index) => (
              <li key={`${gap.endpoint}-${index}`}>
                <StatusPill domain="coverage" value={gap.coverage_status} size="sm" />
                <span className="mono-text">{gap.endpoint}</span>
                <span className="meta-text">{gap.service || "Unclassified service"}</span>
                <TimeStamp value={gap.updated_at} fallback="Not recorded" />
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}
