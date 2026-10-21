import { useCallback, useEffect, useState } from "react";

import type { CodeQueueItem, CodeQueuePage, CodeQueueStats, CodeRepo } from "../../lib/api";
import { listCodeQueueLane, type CodeQueueLane } from "../../lib/codeApi";
import { useCoalescedRequest } from "../../lib/useCoalescedRequest";
import { TimeStamp } from "../formatting";
import { CardSkeleton } from "../Skeletons";
import { humanizeStatus, statusLabel } from "../ui";
import { QUEUE_MODE_LABELS } from "./codeLabels";
import { finishedNotReviewed, isReference, repoLabel } from "./codeModel";
import { RiskTag } from "./RiskTag";
import { QUEUE_LANES, QUEUE_LANE_PAGE, type CodeData, type CodeSource } from "./useCodeData";
import { codeViewHref } from "./useCodeRoute";

type Props = {
  engagementKey: string;
  data: CodeData;
  /** Per-source read failures; a missing value without one is still loading. */
  errors: Partial<Record<CodeSource, string>>;
  pending: ReadonlySet<CodeSource>;
  refreshVersion: number;
};

const LANE_TITLES: Record<CodeQueueLane, string> = {
  error: "Errors",
  needs_context: "Waiting on context",
  processing: "Running now",
  pending: "Next up",
};

const LANE_EMPTY: Record<CodeQueueLane, string> = {
  error: "No review job has failed.",
  needs_context: "No review is waiting on more context.",
  processing: "No review job is running.",
  pending: "Nothing is queued.",
};

const BAR_SEGMENTS: Array<{ key: "done" | "processing" | "needs_context" | "error" | "pending"; label: string }> = (
  ["done", "processing", "needs_context", "error", "pending"] as const
).map((key) => ({ key, label: statusLabel("code-queue", key) }));

const LEAD_LABELS: Record<string, string> = {
  pending: "not yet followed",
  queued: "queued for review",
  resolved: "followed",
  external_context_unavailable: "need source outside the snapshot",
  source_equivalent_analyzed: "covered by an equivalent review",
  not_applicable: "not applicable",
};

export function CodeQueue({ engagementKey, data, errors, pending, refreshVersion }: Props) {
  const stats = data.queueStats;
  const repos = data.repos ?? [];
  const leads = data.coverage?.trigger_summary;
  const gap = finishedNotReviewed(data.progress);
  // Lanes with jobs get a list; empty lanes collapse into one sentence.
  const busyLanes = QUEUE_LANES.filter((lane) => (data.lanes?.[lane]?.total ?? 0) > 0);
  const quietLanes = QUEUE_LANES.filter((lane) => data.lanes?.[lane] && data.lanes[lane].total === 0);

  return (
    <>
      <section className="panel cv-section" aria-labelledby="cv-queue-title">
        <header className="cv-section-head">
          <h3 id="cv-queue-title">Review jobs</h3>
          <p className="meta-text">
            One job per file under review. Agents claim queued jobs, read the file, and record a result.
          </p>
        </header>
        {!stats ? (
          errors.queueStats && !pending.has("queueStats") ? (
            <p className="meta-text">Review job counts are unavailable.</p>
          ) : (
            <div aria-label="Loading review job counts">
              <CardSkeleton lines={2} title={false} />
            </div>
          )
        ) : (
          <>
            <div className="cv-bar" role="img" aria-label={BAR_SEGMENTS.map((segment) => `${segment.label} ${stats[segment.key]}`).join(", ")}>
              {stats.total > 0 &&
                BAR_SEGMENTS.map((segment) => {
                  const value = stats[segment.key];
                  return value > 0 ? (
                    <span
                      key={segment.key}
                      className={`cv-bar-seg cv-seg-${segment.key}`}
                      style={{ width: `${(value / stats.total) * 100}%` }}
                    />
                  ) : null;
                })}
            </div>
            <ul className="cv-legend" aria-label="Review job counts">
              {BAR_SEGMENTS.map((segment) => (
                <li key={segment.key}>
                  <span className={`cv-dot cv-seg-${segment.key}`} aria-hidden="true" />
                  {segment.label} <strong>{stats[segment.key].toLocaleString()}</strong>
                </li>
              ))}
              <li>
                Total <strong>{stats.total.toLocaleString()}</strong>
              </li>
            </ul>
            {gap ? (
              <div className="cv-inline-note is-warn" role="note" aria-label="Finished reviews that do not count">
                <p>
                  <strong>
                    {gap.finished.toLocaleString()} finished · {gap.reviewed.toLocaleString()} count as reviewed.
                  </strong>{" "}
                  A done job is not a reviewed file until it has a current receipt the review counts:
                </p>
                <ul>
                  {gap.reasons.map((reason) => <li key={reason.code}>{reason.message}</li>)}
                </ul>
              </div>
            ) : null}
            {stats.reference_repo_items.length > 0 && (
              <p className="meta-text">
                Not counted above — reference code never gets review jobs:{" "}
                {stats.reference_repo_items.map((repo) => `${repo.name} (${repo.queue_items})`).join(", ")}
              </p>
            )}
          </>
        )}
      </section>

      {data.lanes === null ? (
        <section className="panel cv-section">
          <CardSkeleton lines={4} />
        </section>
      ) : (
        <>
          <div className="cv-lanes">
            {busyLanes.map((lane) => (
              <QueueLane
                key={lane}
                engagementKey={engagementKey}
                lane={lane}
                firstPage={data.lanes![lane]}
                repos={repos}
                refreshVersion={refreshVersion}
              />
            ))}
          </div>
          {quietLanes.length > 0 && (
            <p className="meta-text cv-quiet-lanes">{quietLanes.map((lane) => LANE_EMPTY[lane]).join(" ")}</p>
          )}
        </>
      )}

      <section className="panel cv-section" aria-labelledby="cv-leads-title">
        <header className="cv-section-head">
          <h3 id="cv-leads-title">Cross-file leads</h3>
          <p className="meta-text">
            When a review finds that data flows into another file, it leaves a lead so that file gets reviewed with that context.
          </p>
        </header>
        {!leads ? (
          errors.coverage && !pending.has("coverage") ? (
            <p className="meta-text">Lead counts are unavailable.</p>
          ) : (
            <div aria-label="Loading lead counts">
              <CardSkeleton lines={1} title={false} />
            </div>
          )
        ) : (
          <ul className="cv-legend">
            {Object.entries(leads).map(([status, count]) => (
              <li key={status}>
                <strong>{count.toLocaleString()}</strong> {LEAD_LABELS[status] ?? humanizeStatus(status)}
              </li>
            ))}
          </ul>
        )}
      </section>

      {stats && <QueueDiagnostics stats={stats} />}
    </>
  );
}

function QueueLane({
  engagementKey,
  lane,
  firstPage,
  repos,
  refreshVersion,
}: {
  engagementKey: string;
  lane: CodeQueueLane;
  /** The lane's first page, loaded (and refreshed) with the section. */
  firstPage: CodeQueuePage;
  repos: CodeRepo[];
  refreshVersion: number;
}) {
  // Later pages load here (single-flight; a refresh mid-read re-reads once
  // after it); the first page comes with the section's data.
  const [offset, setOffset] = useState(0);
  const laterKey = `${engagementKey}\u0000${lane}\u0000${offset}`;
  const later = useCoalescedRequest<CodeQueuePage>(
    laterKey,
    useCallback(() => listCodeQueueLane(engagementKey, lane, { limit: QUEUE_LANE_PAGE, offset }), [engagementKey, lane, offset]),
    refreshVersion,
    offset > 0,
  );
  const error = offset > 0 ? later.error : null;
  // A lane that shrank under a later page steps back to its last page.
  const total = offset === 0 ? firstPage.total : later.data?.total ?? firstPage.total;
  useEffect(() => {
    if (offset > 0 && total > 0 && offset >= total) setOffset(Math.floor((total - 1) / QUEUE_LANE_PAGE) * QUEUE_LANE_PAGE);
  }, [offset, total]);

  const page = offset === 0 ? firstPage : later.dataKey === laterKey ? later.data : null;
  const shownFrom = page && page.items.length > 0 ? offset + 1 : 0;
  const shownTo = page ? offset + page.items.length : 0;
  const title = LANE_TITLES[lane];
  return (
    <section className={`panel cv-section cv-lane cv-lane-${lane}`} aria-label={title}>
      <header className="cv-lane-head">
        <h4>{title}</h4>
        <span className="cv-count">{total.toLocaleString()}</span>
      </header>
      {page ? (
        <ol className="cv-jobs">
          {page.items.map((item) => (
            <QueueJob key={item.id} engagementKey={engagementKey} item={item} repos={repos} />
          ))}
        </ol>
      ) : (
        <CardSkeleton lines={3} title={false} />
      )}
      {error ? <p className="error-text" role="alert">Review jobs unavailable: {error}</p> : null}
      <div className="cv-lane-foot">
        <span className="meta-text">
          {page && page.items.length > 0
            ? `Showing ${shownFrom.toLocaleString()}–${shownTo.toLocaleString()} of ${total.toLocaleString()} · highest priority first`
            : `${total.toLocaleString()} jobs · highest priority first`}
        </span>
        {total > QUEUE_LANE_PAGE ? (
          <span className="cv-lane-pager">
            <button
              type="button"
              className="ui-button"
              aria-label={`Previous page of ${title}`}
              disabled={offset === 0}
              onClick={() => setOffset((value) => Math.max(0, value - QUEUE_LANE_PAGE))}
            >
              ←
            </button>
            <button
              type="button"
              className="ui-button"
              aria-label={`Next page of ${title}`}
              disabled={offset + QUEUE_LANE_PAGE >= total}
              onClick={() => setOffset((value) => value + QUEUE_LANE_PAGE)}
            >
              →
            </button>
          </span>
        ) : null}
      </div>
    </section>
  );
}

function QueueJob({ engagementKey, item, repos }: { engagementKey: string; item: CodeQueueItem; repos: CodeRepo[] }) {
  const repo = repos.find((entry) => entry.id === item.repo_id);
  return (
    <li className="cv-job">
      <span className="cv-path" title={item.file_path}>{item.file_path}</span>
      <span className="cv-job-meta">
        <RiskTag classification={item.classification} />
        <span>{QUEUE_MODE_LABELS[item.queue_mode] ?? humanizeStatus(item.queue_mode)}</span>
        {repos.filter((entry) => !isReference(entry)).length > 1 && (
          <a href={codeViewHref(engagementKey, { view: "repositories", repo: item.repo_id })}>
            {repo ? repoLabel(repo, repos) : item.repo_key}
          </a>
        )}
        {item.agent_name && <span>{item.agent_name}</span>}
        <span title={`Job #${item.id}`}>priority {item.priority}</span>
        <TimeStamp value={item.lease_activity_at ?? item.updated_at} />
      </span>
      {item.skip_reason && <span className="meta-text">{item.skip_reason}</span>}
    </li>
  );
}

function QueueDiagnostics({ stats }: { stats: CodeQueueStats }) {
  const problems = stats.invalid_active_identity + stats.invalid_active_history;
  const counters = [
    { label: "Earlier attempts kept as history", value: stats.historical_total },
    { label: "Attempts replaced by a newer one", value: stats.superseded_history },
    { label: "Active jobs with an invalid identity", value: stats.invalid_active_identity },
    { label: "Files with an invalid active history", value: stats.invalid_active_history },
  ].filter((counter) => counter.value > 0);
  if (counters.length === 0) return null;
  return (
    <details className={`panel cv-section cv-diagnostics${problems > 0 ? " has-problems" : ""}`}>
      <summary>
        Diagnostics{problems > 0 ? ` — ${problems.toLocaleString()} integrity ${problems === 1 ? "problem" : "problems"}` : ""}
      </summary>
      <dl className="cv-facts">
        {counters.map((counter) => (
          <div key={counter.label}>
            <dt>{counter.label}</dt>
            <dd>{counter.value.toLocaleString()}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
