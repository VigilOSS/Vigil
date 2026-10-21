import { gridTimeMode } from "../../lib/serverTime";
import type { SubmissionDeskListing, SubmissionDeskRow } from "../../lib/submissionsApi";
import { TimeStamp } from "../formatting";
import { TableSkeleton } from "../Skeletons";
import { EmptyState, ResultsSummary, SeverityTag, StatusPill, describeSort, type Scope } from "../ui";

/**
 * A time on the desk: relative while recent, the absolute UTC minute once a
 * relative label would only be a bare date, so the time of day is never lost.
 */
export function SubmissionTime({ value, className }: { value: string | null | undefined; className?: string }) {
  return <TimeStamp value={value} mode={gridTimeMode(value)} className={className} />;
}

/** A finding's queue state, with the blocker count as its inline reason. */
export function QueuePill({ row, size = "sm" }: { row: Pick<SubmissionDeskRow, "readiness" | "blocker_count">; size?: "sm" | "md" }) {
  const reason = row.readiness === "blocked" && row.blocker_count > 0
    ? `${row.blocker_count} blocker${row.blocker_count === 1 ? "" : "s"}`
    : undefined;
  return <StatusPill domain="submission" value={row.readiness} size={size} reason={reason} />;
}

export function SubmissionQueue({
  listing,
  loading,
  error,
  selectedSlug,
  locked,
  loadingMore,
  filterLabel,
  filtersActive,
  scope,
  onClearFilters,
  onShowAll,
  onSelect,
  onLoadMore,
  onRetry,
}: {
  listing: SubmissionDeskListing | null;
  loading: boolean;
  error: string;
  selectedSlug: string;
  locked: boolean;
  loadingMore: boolean;
  /** The listing shown ("To do", "Filed"…), for the empty state. */
  filterLabel: string;
  /** Search, chips or recency narrow the list. */
  filtersActive: boolean;
  scope: Scope;
  onClearFilters: () => void;
  onShowAll: () => void;
  onSelect: (row: SubmissionDeskRow) => void;
  onLoadMore: () => void;
  onRetry: () => void;
}) {
  const rows = listing?.findings ?? [];
  const page = listing?.findings_page;
  const nothingRecorded = listing != null && listing.counts.all === 0;
  return (
    <aside className="subm-queue panel" aria-label="Submission queue" aria-busy={loading}>
      <div className="subm-queue-head">
        {page
          ? <ResultsSummary shown={rows.length} total={page.total} noun={page.total === 1 ? "finding" : "findings"} sort={describeSort("Changed", "desc", "time")} />
          : <strong>Findings</strong>}
      </div>
      <div className={`subm-queue-scroll ${loading && rows.length > 0 ? "is-reloading" : ""}`}>
        {error && (
          <div className="subm-inline-error" role="alert">
            <span>{error}</span>
            <button type="button" className="qa-btn" onClick={onRetry}>Retry</button>
          </div>
        )}
        {!listing && loading ? (
          <TableSkeleton rows={8} showHeader={false} columns={["6%", "70%", "24%"]} />
        ) : rows.length === 0 && !error && listing ? (
          nothingRecorded ? (
            <EmptyState variant="empty" compact title="No findings to submit yet.">
              Findings appear here once they are recorded; a verified finding becomes ready to draft.
            </EmptyState>
          ) : filtersActive ? (
            <EmptyState
              variant="filtered"
              compact
              title="No findings match these filters."
              onClearFilters={onClearFilters}
              action={scope === "attention" ? <button type="button" className="ui-button" onClick={onShowAll}>Show all findings</button> : undefined}
            />
          ) : (
            <EmptyState
              variant="filtered"
              compact
              title={`No findings are in ${filterLabel}.`}
              onClearFilters={onShowAll}
              clearLabel="Show all findings"
            />
          )
        ) : (
          <ul className="subm-queue-list">
            {rows.map((row) => {
              const selected = row.slug === selectedSlug;
              return (
                <li key={row.slug}>
                  <button
                    type="button"
                    className={`subm-queue-row ${selected ? "is-selected" : ""}`}
                    aria-pressed={selected}
                    disabled={locked}
                    onClick={() => onSelect(row)}
                  >
                    <span className={`subm-sevbar sevbar-${row.severity}`} aria-hidden="true" />
                    <span className="subm-queue-main">
                      <span className="subm-queue-title" title={row.title}>{row.title}</span>
                      <span className="subm-queue-meta">
                        <SeverityTag severity={row.severity} size="sm" />
                        <code>{row.slug}</code>
                        <QueuePill row={row} />
                        {row.latest_version_number != null && (
                          <span
                            className="subm-badge"
                            aria-label={`Latest immutable version ${row.latest_version_number}`}
                          >
                            v{row.latest_version_number}
                          </span>
                        )}
                        {row.failed_version_count > 0 && (
                          <span className="subm-badge is-danger">{row.failed_version_count} failed</span>
                        )}
                        <SubmissionTime value={row.updated_at} className="subm-queue-time" />
                      </span>
                      {row.readiness === "blocked" && row.first_blocker && (
                        <span className="subm-queue-reason" title={row.first_blocker}>{row.first_blocker}</span>
                      )}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
      {page && page.total > 0 && (
        <div className="list-footer subm-queue-foot">
          <span>{`Showing 1–${rows.length} of ${page.total}`}</span>
          {page.has_more && (
            <button type="button" className="pager-btn" onClick={onLoadMore} disabled={loadingMore || locked}>
              {loadingMore ? "Loading…" : "Load more"}
            </button>
          )}
        </div>
      )}
    </aside>
  );
}
