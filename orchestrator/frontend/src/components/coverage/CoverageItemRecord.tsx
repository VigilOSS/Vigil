// One coverage item's record, rendered inside the shared RecordView
// (CoverageTab owns the view, the list order and the URL). It answers "why is
// this item in this state": the latest reason and full note history, the work
// and probe runs tied to it, its request or service, and blocked techniques on
// its host.

import { useEffect, useRef, useState } from "react";
import { fetchCoverageItem, type CoverageItemDetail, type CoverageLedgerItem } from "../../lib/coverageApi";
import { engagementHref } from "../../lib/workspaceRoutes";
import { KV, KVTime } from "../drawer/DrawerKit";
import { TimeStamp } from "../formatting";
import { JsonView } from "../JsonView";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs } from "../record/RecordView";
import { CardSkeleton } from "../Skeletons";
import { StatusPill, humanizeStatus, statusTone } from "../ui";
import { coverageStatusMeaning, retryStateLabel } from "./coverageStatus";
import { coverageTargetLabel } from "./coverageGridModel";

/** The coverage record's sections (`dtab` in the URL). */
export type CoverageRecordTab = "why" | "work" | "probes" | "target" | "techniques" | "raw";

const COVERAGE_RECORD_TABS: readonly CoverageRecordTab[] = ["why", "work", "probes", "target", "techniques", "raw"];

export function isCoverageRecordTab(value: string | null | undefined): value is CoverageRecordTab {
  return typeof value === "string" && (COVERAGE_RECORD_TABS as readonly string[]).includes(value);
}

type Props = {
  engagementKey: string;
  itemId: number;
  /** The row the operator opened (or stepped to); shown while the detail loads. */
  row: CoverageLedgerItem | null;
  tab: CoverageRecordTab;
  onTabChange: (tab: CoverageRecordTab) => void;
  titleId: string;
  /** Bumped by live refresh: re-read the detail while keeping it on screen. */
  refreshToken: number;
  /** Reports the item row once the detail has it (a deep link opens without one). */
  onRow?: (row: CoverageLedgerItem) => void;
};

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

function WhySection({ item }: { item: CoverageLedgerItem }) {
  if (item.latest_reason) {
    return (
      <div className={`callout cov-why cov-status-${item.status}`}>
        <p className="section-title">Why</p>
        <p className="cov-prewrap">{item.latest_reason}</p>
      </div>
    );
  }
  const open = item.status !== "covered" && item.status !== "not_applicable";
  return (
    <div className={`callout cov-why cov-why-empty cov-status-${item.status}`}>
      <p className="section-title">Why</p>
      <p>
        {item.status === "pending" || item.status === "queued"
          ? "Not attempted yet — no reason has been recorded since the item was created."
          : open
            ? "No reason was recorded with this status. The creation note is the only history."
            : "No closing rationale was recorded after creation."}
      </p>
      <p className="meta-text">Created from: {item.created_from || "—"}</p>
    </div>
  );
}

export function CoverageItemRecord({ engagementKey, itemId, row, tab, onTabChange, titleId, refreshToken, onRow }: Props) {
  const [detail, setDetail] = useState<CoverageItemDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const onRowRef = useRef(onRow);
  onRowRef.current = onRow;

  // The record remounts per item, so a new id never shows the old detail; a
  // refresh re-reads it in place.
  useEffect(() => {
    let cancelled = false;
    setError(null);
    fetchCoverageItem(engagementKey, itemId)
      .then((value) => {
        if (cancelled) return;
        setDetail(value);
        onRowRef.current?.(value.item);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Coverage item unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, itemId, refreshToken]);

  // The detail is fresher than the row once it arrives.
  const current = detail?.item ?? row;
  const loading = !detail && !error;

  if (!current) {
    return (
      <>
        <RecordHeader id={`Coverage item #${itemId}`} title={`Coverage item #${itemId}`} titleId={titleId} />
        <RecordBody busy={loading}>
          {error ? (
            <p className="error-text" role="alert">Coverage item #{itemId} could not be opened: {error}</p>
          ) : (
            <div aria-label="Loading item detail">
              <CardSkeleton lines={4} />
              <CardSkeleton lines={3} />
            </div>
          )}
        </RecordBody>
      </>
    );
  }

  const { method, target } = coverageTargetLabel(current);
  const targetLabel = detail?.request_variant ? "Request" : detail?.service ? "Service" : "Target";
  return (
    <>
      <RecordHeader
        id={`Coverage item #${current.id}`}
        copyId={String(current.id)}
        copyIdLabel="Copy coverage item ID"
        title={
          <>
            {method ? <><span className={`cov-method m-${method.toLowerCase()}`}>{method}</span>{" "}</> : null}
            <span className="mono">{target}</span>
          </>
        }
        titleId={titleId}
        tone={statusTone("coverage", current.status)}
        actions={<RecordCopyLinkButton noun="coverage item" />}
        pills={
          <>
            <StatusPill domain="coverage" value={current.status} reason={coverageStatusMeaning(current.status)} />
            <span className="tag" title="Attack family">{current.attack_family}</span>
            <span className="tag mono" title="Input slot">{current.input_slot}</span>
            <span className="tag" title="Auth context">{current.auth_context}</span>
            {current.item_host ? <span className="tag mono" title="Host">{current.item_host}</span> : null}
          </>
        }
        datesLabel="Coverage item dates"
        dates={[
          { label: "Created", value: current.created_at },
          { label: "Last updated", value: current.updated_at },
        ]}
      />
      <RecordTabs
        label="Coverage item sections"
        active={tab}
        onChange={onTabChange}
        tabs={[
          { id: "why", label: "Why & history" },
          { id: "work", label: "Related work", count: detail?.work_items.total },
          { id: "probes", label: "Probe runs", count: detail?.probe_runs.total },
          { id: "target", label: targetLabel },
          { id: "techniques", label: "Blocked techniques", count: detail?.blocked_techniques.length },
          { id: "raw", label: "Raw record" },
        ]}
      />
      <RecordBody busy={loading}>
        {tab === "why" && <WhySection item={current} />}
        {error ? (
          <p className="error-text" role="alert">
            Item detail unavailable: {error}{detail ? " · Showing the last loaded detail." : ""}
          </p>
        ) : null}
        {!detail ? (
          error ? null : (
            <div aria-label="Loading item detail">
              <CardSkeleton lines={4} />
              <CardSkeleton lines={3} />
            </div>
          )
        ) : (
          <>
            {tab === "why" && (
              <section className="section" aria-labelledby={`${titleId}-history`}>
                <p className="section-title" id={`${titleId}-history`}>History</p>
                <ol className="cov-history">
                  {detail.note_lines.map((line, index) => (
                    <li key={index} className={line.provenance ? "is-provenance" : undefined}>
                      <span className="cov-history-label">
                        {line.provenance
                          ? "Created from"
                          : `Note ${index + (detail.note_lines[0]?.provenance ? 0 : 1)}${index === detail.note_lines.length - 1 ? " · latest" : ""}`}
                      </span>
                      <p className="cov-prewrap">{line.text}</p>
                    </li>
                  ))}
                </ol>
              </section>
            )}

            {tab === "work" && (
              <section className="section">
                <p className="section-title">Related work · {plural(detail.work_items.total, "item")}</p>
                {detail.work_items.total === 0 ? (
                  <p className="meta-text">No work-queue items are linked to this coverage item.</p>
                ) : (
                  <ul className="cov-related">
                    {detail.work_items.items.map((work) => (
                      <li key={work.id}>
                        <div className="cov-related-head">
                          <span className={`cov-tag cov-work-${work.status}`}>{humanizeStatus(work.status)}</span>
                          <strong>Work item #{work.id}</strong>
                          <span className="meta-text">
                            {[
                              work.retry_count > 0 ? plural(work.retry_count, "retry", "retries") : "",
                              work.type && work.type !== "unknown" ? work.type : "",
                              work.source,
                            ].filter(Boolean).join(" · ")}
                          </span>
                          <TimeStamp value={work.updated_at} className="cov-related-time" />
                        </div>
                        {work.terminal_reason ? <p><span className="cov-field">Ended because</span> {work.terminal_reason}</p> : null}
                        {work.triage_rationale ? <p><span className="cov-field">Triage</span> {work.triage_rationale}</p> : null}
                        {work.priority_reason && work.priority_reason !== work.triage_rationale ? (
                          <p className="meta-text">Priority {work.priority_score}: {work.priority_reason}</p>
                        ) : null}
                      </li>
                    ))}
                    {detail.work_items.total > detail.work_items.items.length ? (
                      <li className="meta-text">
                        Showing the {detail.work_items.items.length} most recently updated of {detail.work_items.total.toLocaleString()}.
                      </li>
                    ) : null}
                  </ul>
                )}
              </section>
            )}

            {tab === "probes" && (
              <section className="section">
                <p className="section-title">Probe runs · {plural(detail.probe_runs.total, "run")}</p>
                {detail.probe_runs.total === 0 ? (
                  <p className="meta-text">No probe run has been recorded against this item.</p>
                ) : (
                  <ul className="cov-related">
                    {detail.probe_runs.items.map((probe) => (
                      <li key={probe.id}>
                        <div className="cov-related-head">
                          <span className={`cov-tag cov-probe-${probe.result_status}`}>{humanizeStatus(probe.result_status)}</span>
                          <strong>{probe.tool_name}</strong>
                          <span className="meta-text">
                            {[probe.agent_name, probe.observed_http_status != null ? `HTTP ${probe.observed_http_status}` : "", probe.signal_type]
                              .filter(Boolean)
                              .join(" · ")}
                          </span>
                          <TimeStamp value={probe.created_at} className="cov-related-time" />
                        </div>
                        {probe.outcome_assertion ? <p>{probe.outcome_assertion}</p> : null}
                        {probe.evidence_ref ? <p className="mono-text cov-wrap">{probe.evidence_ref}</p> : null}
                        {probe.finding_slug ? (
                          <a href={engagementHref(engagementKey, { tab: "findings", finding: probe.finding_slug })}>
                            Finding {probe.finding_slug}
                          </a>
                        ) : null}
                      </li>
                    ))}
                    {detail.probe_runs.total > detail.probe_runs.items.length ? (
                      <li className="meta-text">
                        Showing the {detail.probe_runs.items.length} most recent of {detail.probe_runs.total.toLocaleString()}.
                      </li>
                    ) : null}
                  </ul>
                )}
              </section>
            )}

            {tab === "target" && (
              <>
                {detail.request_variant ? (
                  <section className="section">
                    <p className="section-title">Request</p>
                    <div className="kv-grid">
                      <KV k="Method" v={detail.request_variant.method} />
                      <KV k="Auth context" v={detail.request_variant.auth_context} />
                      <KV k="URL" v={detail.request_variant.canonical_url} mono />
                      <KV k="Discovered by" v={detail.request_variant.discovery_source} />
                      <KVTime k="First seen" v={detail.request_variant.first_seen_at} />
                      <KVTime k="Last seen" v={detail.request_variant.last_seen_at} />
                    </div>
                    <a
                      className="cov-link"
                      href={engagementHref(engagementKey, { tab: "http", request: detail.request_variant.id })}
                    >
                      Open request variant #{detail.request_variant.id}
                    </a>
                  </section>
                ) : null}
                {detail.service ? (
                  <section className="section">
                    <p className="section-title">Service</p>
                    <div className="kv-grid">
                      <KV k="Endpoint" v={detail.service.endpoint} mono />
                      <KV k="Service" v={detail.service.service} />
                      <KV k="State" v={detail.service.state} />
                      <KV k="Service coverage" v={detail.service.coverage_status} />
                      <KVTime k="Updated" v={detail.service.updated_at} />
                    </div>
                  </section>
                ) : null}
                {!detail.request_variant && !detail.service ? (
                  <p className="meta-text">This item is bound to neither a request variant nor a service.</p>
                ) : null}
              </>
            )}

            {tab === "techniques" && (
              <section className="section">
                <p className="section-title">
                  Blocked techniques on this host · {detail.blocked_techniques.length.toLocaleString()}
                </p>
                {detail.blocked_techniques.length === 0 ? (
                  <p className="meta-text">No blocked technique names this item's host or endpoint.</p>
                ) : (
                  <ul className="cov-related">
                    {detail.blocked_techniques.map((technique) => (
                      <li key={technique.id}>
                        <div className="cov-related-head">
                          <span className={`cov-tag cov-relation-${technique.relation}`}>
                            {technique.relation === "endpoint" ? "This endpoint" : "Same host"}
                          </span>
                          <strong>{technique.technique}</strong>
                          <span className="meta-text">{retryStateLabel(technique.retry_state)}</span>
                          <TimeStamp value={technique.updated_at} className="cov-related-time" />
                        </div>
                        <p className="mono-text cov-wrap">{technique.target_ref}</p>
                        <p className="cov-prewrap">{technique.reason}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            )}

            {tab === "raw" && (
              <section className="section">
                <p className="section-title">Raw record</p>
                <JsonView value={detail} label={`coverage item #${current.id}`} />
              </section>
            )}
          </>
        )}
      </RecordBody>
    </>
  );
}
