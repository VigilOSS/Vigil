// The Review queue's leads: what earlier reviews left for a later one to read.
// The counts come from the coverage summary; the leads behind one status are
// read a page at a time (`GET code/triggers?status=…`, paged and narrowed to a
// kind by the server), so every lead a count stands for can be read. The
// status, kind and page shown live in the URL (useCodeRoute), so a blocker
// links to exactly the leads it counts and a reload or Back returns to the
// page that was shown.

import { useCallback, useEffect, useRef, useState } from "react";

import type { CodeRepo } from "../../lib/api";
import { listCodeTriggers, type CodeTriggerPage } from "../../lib/codeApi";
import { useCoalescedRequest } from "../../lib/useCoalescedRequest";
import { TimeStamp } from "../formatting";
import { CardSkeleton, SlowLoadHint } from "../Skeletons";
import { EmptyState, FilterChip, FilterGroup } from "../ui";
import { LEAD_KIND_LABELS, LEAD_KIND_MEANINGS, familyLabel, leadKindLabel, leadStatusLabel } from "./codeLabels";
import { isReference, leadCounts, repoLabel } from "./codeModel";
import { CODE_LEAD_KINDS, codeViewHref, type CodeLeadKind, type CodeRoute } from "./useCodeRoute";

export const LEAD_PAGE_SIZE = 25;

type Props = {
  engagementKey: string;
  /** Lead counts by status (`coverage.trigger_summary`); null while loading or unavailable. */
  summary: Record<string, number> | null;
  /** The summary read failed (as opposed to still loading). */
  summaryUnavailable: boolean;
  repos: CodeRepo[];
  route: CodeRoute;
  refreshVersion: number;
  /** The sections above the leads have their data, so the leads' place on the page is settled. */
  ready: boolean;
};

export function CodeLeads({ engagementKey, summary, summaryUnavailable, repos, route, refreshVersion, ready }: Props) {
  const counts = leadCounts(summary);
  // The statuses the summary counts, in its order; an unknown status in the URL is still shown so its list can load.
  const statuses = counts ? counts.statuses.map((entry) => entry.status) : [];
  const status = route.leads ?? "pending";
  const kind = route.kind;
  const [retry, setRetry] = useState(0);
  const offset = (route.page - 1) * LEAD_PAGE_SIZE;
  // One status and kind is one list; its pages share this prefix.
  const listPrefix = `${engagementKey}\u0000${status}\u0000${kind ?? ""}\u0000`;
  const listKey = `${listPrefix}${offset}`;
  const leads = useCoalescedRequest<CodeTriggerPage>(
    listKey,
    useCallback(
      () => listCodeTriggers(engagementKey, status, { limit: LEAD_PAGE_SIZE, offset, origin: kind }),
      [engagementKey, status, kind, offset],
    ),
    refreshVersion + retry,
  );
  // The last loaded page of this list stays on screen (and keeps the pager, so
  // keyboard focus) while another of its pages loads; `current` says it
  // answers this request. Another status or kind starts from a placeholder.
  const current = leads.dataKey === listKey;
  const loaded = leads.data !== null && leads.dataKey?.startsWith(listPrefix) ? leads.data : null;
  const total = loaded?.total ?? 0;
  // Every lead in the status, whatever kind the list is narrowed to.
  const statusTotal = loaded ? loaded.by_origin.cross_file + loaded.by_origin.depth_floor : 0;
  const pages = Math.max(1, Math.ceil(total / LEAD_PAGE_SIZE));
  const rows = loaded?.items ?? [];
  const first = loaded ? loaded.offset + 1 : 0;
  const last = loaded ? loaded.offset + rows.length : 0;
  const { navigate } = route;
  // A page past the end (a bookmarked page of a list that shrank) moves to the last page.
  const pastEnd = loaded !== null && current && rows.length === 0 && total > 0;
  useEffect(() => {
    if (pastEnd) navigate({ view: "queue", leads: status, kind, page: pages }, "replace");
  }, [pastEnd, navigate, status, kind, pages]);

  // A link that names the leads it counts (a blocker's kind, a status, a page)
  // brings the list into view once, after the sections above it and the list
  // itself have their data: scrolling while they are placeholders lands short
  // of, or above, where the leads end up.
  // Only a link does that; choosing a chip here changes the URL without moving the page.
  const sectionRef = useRef<HTMLElement | null>(null);
  const linked = useRef(route.leads != null || route.kind != null || route.page > 1).current;
  const landed = useRef(false);
  const listSettled = loaded !== null || leads.error !== null;
  useEffect(() => {
    if (!linked || landed.current || !ready || !listSettled) return;
    landed.current = true;
    sectionRef.current?.scrollIntoView?.({ block: "start" });
  }, [linked, ready, listSettled]);

  // Kind counts: the summary splits the leads not yet followed; any other status is counted by the server with its page.
  const kindCount = (value: CodeLeadKind): number | null => {
    if (status === "pending" && counts) return value === "depth_floor" ? counts.depthFloorPending : counts.crossFilePending;
    return loaded ? loaded.by_origin[value] : null;
  };
  // A status or kind change starts again from the first page.
  const go = (next: { leads?: string; kind?: CodeLeadKind; page?: number }) =>
    navigate({ view: "queue", leads: next.leads ?? status, kind: "kind" in next ? next.kind : kind, page: next.page });
  // The button leaves with the error it sits in; focus moves to the section first so it is not dropped.
  const retryLoad = () => {
    sectionRef.current?.focus({ preventScroll: true });
    setRetry((value) => value + 1);
  };
  const multiRepo = repos.filter((repo) => !isReference(repo)).length > 1;
  const noun = total === 1 ? "lead" : "leads";

  return (
    <section ref={sectionRef} tabIndex={-1} className={`panel cv-section cv-focusable${linked ? " is-focused" : ""}`} aria-labelledby="cv-leads-title">
      <header className="cv-section-head">
        <h3 id="cv-leads-title">Leads to follow</h3>
        <p className="meta-text">
          A review leaves a lead when more reading is owed. <strong>{LEAD_KIND_LABELS.cross_file}</strong>:{" "}
          {LEAD_KIND_MEANINGS.cross_file} <strong>{LEAD_KIND_LABELS.depth_floor}</strong>: {LEAD_KIND_MEANINGS.depth_floor}
        </p>
      </header>

      {!counts ? (
        summaryUnavailable ? (
          <p className="meta-text">Lead counts are unavailable.</p>
        ) : (
          <div aria-label="Loading lead counts">
            <CardSkeleton lines={1} title={false} />
          </div>
        )
      ) : (
        <p className="cv-lead-totals" role="status">
          <strong>{counts.pending.toLocaleString()}</strong> not yet followed:{" "}
          <strong>{counts.crossFilePending.toLocaleString()}</strong> cross-file,{" "}
          <strong>{counts.depthFloorPending.toLocaleString()}</strong> depth floor.{" "}
          <strong>{counts.queued.toLocaleString()}</strong> queued for review, <strong>{counts.settled.toLocaleString()}</strong> settled.
        </p>
      )}

      <div className="cv-facets">
        <FilterGroup label="Status">
          {[...new Set([...statuses, status])].map((value) => (
            <FilterChip
              key={value}
              label={leadStatusLabel(value)}
              count={counts?.statuses.find((entry) => entry.status === value)?.count ?? null}
              selected={status === value}
              // One status at a time: its list is what loads. Pressing the selected one keeps it.
              onToggle={() => { if (status !== value) go({ leads: value }); }}
            />
          ))}
        </FilterGroup>
        <FilterGroup label="Kind">
          {CODE_LEAD_KINDS.map((value) => (
            <FilterChip
              key={value}
              label={LEAD_KIND_LABELS[value]}
              description={LEAD_KIND_MEANINGS[value]}
              count={kindCount(value)}
              selected={kind === value}
              onToggle={() => go({ kind: kind === value ? undefined : value })}
            />
          ))}
        </FilterGroup>
      </div>

      {leads.error ? (
        <p className="error-text" role="alert">
          Leads unavailable: {leads.error}{loaded ? " · Showing the last loaded page." : ""}{" "}
          <button type="button" className="ui-clear-filters" onClick={retryLoad}>
            Try again
          </button>
        </p>
      ) : null}

      {!loaded ? (
        leads.error ? null : (
          <div aria-label="Loading leads">
            <CardSkeleton lines={4} title={false} />
            <SlowLoadHint active={leads.loading} what="leads" />
          </div>
        )
      ) : total === 0 ? (
        kind && statusTotal > 0 ? (
          <EmptyState
            variant="filtered"
            compact
            title={`No ${leadKindLabel(kind).toLowerCase()} leads with status “${leadStatusLabel(status)}”.`}
            onClearFilters={() => go({ kind: undefined })}
            clearLabel={`Show all ${statusTotal.toLocaleString()} ${leadStatusLabel(status).toLowerCase()}`}
          />
        ) : (
          <EmptyState variant="empty" compact title={`No leads with status “${leadStatusLabel(status)}”.`} />
        )
      ) : (
        <>
          <div className="cv-results-summary">
            <p className="ui-results-summary" role="status">
              <strong>{total.toLocaleString()}</strong>
              {kind && statusTotal !== total ? <> of <strong>{statusTotal.toLocaleString()}</strong></> : null} {noun}{" "}
              {leadStatusLabel(status).toLowerCase()} · Most recently updated first
            </p>
            {rows.length > 0 ? (
              <span className="cv-results-range" role="status">
                {`Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}`}
              </span>
            ) : null}
            {leads.loading ? <span className="ui-page-status">Updating…</span> : null}
            {total > LEAD_PAGE_SIZE ? (
              <div className="cv-pager" role="group" aria-label="Lead pages">
                <span className="meta-text">Page {route.page.toLocaleString()} of {pages.toLocaleString()}</span>
                <button type="button" className="ui-button" aria-label="Previous leads page" disabled={route.page <= 1} onClick={() => go({ page: route.page - 1 })}>
                  ← Previous
                </button>
                <button
                  type="button"
                  className="ui-button"
                  aria-label="Next leads page"
                  disabled={current ? !loaded.has_more : route.page >= pages}
                  onClick={() => go({ page: route.page + 1 })}
                >
                  Next →
                </button>
              </div>
            ) : null}
          </div>
          <ol className={`cv-leads${leads.loading ? " is-refreshing" : ""}`} aria-label={`Leads ${leadStatusLabel(status).toLowerCase()}`}>
            {rows.map((lead) => {
              const target = lead.resolved_target_file_path || lead.target_file_path;
              const repo = repos.find((entry) => entry.id === lead.repo_id);
              const reviewed = lead.source_file_path || target;
              return (
                <li key={lead.id}>
                  <div className="cv-lead-head">
                    <span className="cv-path" title={target}>{target || "Unnamed file"}</span>
                    {lead.vuln_class ? <span className="tag" title={lead.vuln_class}>{familyLabel(lead.vuln_class)}</span> : null}
                    <span className="cv-chip" title={LEAD_KIND_MEANINGS[lead.origin as CodeLeadKind]}>{leadKindLabel(lead.origin)}</span>
                    {multiRepo && repo ? <span className="meta-text">{repoLabel(repo, repos)}</span> : null}
                    <TimeStamp value={lead.created_at} />
                  </div>
                  {lead.reason ? <p>{lead.reason}</p> : null}
                  {!lead.resolved_target_file_path && lead.target_file_path ? (
                    <p className="meta-text">The lead names a file that is not in the code snapshot.</p>
                  ) : null}
                  <p className="meta-text">
                    Lead #{lead.id}
                    {lead.source_file_path && lead.source_file_path !== target ? <> · left by the review of <span className="cv-mono">{lead.source_file_path}</span></> : null}
                    {lead.source_queue_item_id ? ` · review job #${lead.source_queue_item_id}` : ""}
                    {lead.resolved_queue_item_id ? ` · followed by review job #${lead.resolved_queue_item_id}` : ""}
                    {/* The review that left the lead; the results search splits on spaces, so only a path without one can be linked. */}
                    {reviewed && !/\s/.test(reviewed) ? (
                      <> · <a href={codeViewHref(engagementKey, { view: "results", q: `file:${reviewed}` })}>Results for the reviewed file</a></>
                    ) : null}
                  </p>
                  {lead.resolution_note ? (
                    <p className="cv-lead-resolution">
                      <strong>{leadStatusLabel(lead.status)}:</strong>{" "}
                      {lead.resolution_note}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ol>
        </>
      )}
    </section>
  );
}
