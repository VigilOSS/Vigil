// One analysis result's record, rendered inside the shared RecordView
// (CodeResults owns the view, the list order and the URL). It answers "what
// did this file review check, what did it find, and where does it stand": the
// reviewer's hypothesis and evidence, the source it is anchored to, its
// per-vulnerability-type coverage, the cross-file leads it left, and the raw
// receipt.

import { useCallback } from "react";

import {
  getCodeAnalysisResult,
  type CodeAnalysisResultDetail,
} from "../../lib/codeApi";
import type { CodeAnalysisResult } from "../../lib/api";
import { useCoalescedRequest } from "../../lib/useCoalescedRequest";
import { engagementHref } from "../../lib/workspaceRoutes";
import { TimeStamp } from "../formatting";
import { JsonView } from "../JsonView";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs } from "../record/RecordView";
import { CardSkeleton } from "../Skeletons";
import { EmptyState, StatusPill, humanizeStatus, statusTone } from "../ui";
import { familyLabel, receiptAnchorNote } from "./codeLabels";
import { codeViewHref } from "./useCodeRoute";

/** The result record's sections (`dtab` in the URL). */
export type CodeResultSection = "review" | "anchors" | "coverage" | "leads" | "raw";

const SECTIONS: readonly CodeResultSection[] = ["review", "anchors", "coverage", "leads", "raw"];

export function isCodeResultSection(value: string | null | undefined): value is CodeResultSection {
  return typeof value === "string" && (SECTIONS as readonly string[]).includes(value);
}

export const AWAITING_VERDICT_REASON =
  "Awaiting a verdict: the file's latest review is suspicious, and no finding or later clean review has settled it.";

type Props = {
  engagementKey: string;
  resultId: number;
  /** The row the operator opened or stepped to; shown while the receipt loads. */
  row: CodeAnalysisResult | null;
  section: CodeResultSection;
  onSectionChange: (section: CodeResultSection) => void;
  titleId: string;
  /** Bumped by live refresh: re-read the receipt while keeping it on screen. */
  refreshVersion: number;
};

function Field({ label, text }: { label: string; text: string }) {
  return (
    <div className="cv-result-field">
      <h3>{label}</h3>
      <p>{text}</p>
    </div>
  );
}

export function CodeResultRecord({ engagementKey, resultId, row, section, onSectionChange, titleId, refreshVersion }: Props) {
  // The record remounts per result, so a new id never shows the old receipt;
  // a refresh re-reads it in place, single-flight (a refresh mid-read re-reads
  // once after it instead of discarding it).
  const receipt = useCoalescedRequest<CodeAnalysisResultDetail>(
    `${engagementKey}\u0000${resultId}`,
    useCallback(() => getCodeAnalysisResult(engagementKey, resultId), [engagementKey, resultId]),
    refreshVersion,
  );
  const detail = receipt.data;
  const error = receipt.error;

  // The receipt is fresher than the row once it arrives.
  const shown = detail ?? row;
  if (!shown) {
    return (
      <>
        <RecordHeader id={`Result #${resultId}`} title={`Result #${resultId}`} titleId={titleId} />
        <RecordBody busy={!error}>
          {error ? (
            <p className="error-text" role="alert">Result #{resultId} could not be opened: {error}</p>
          ) : (
            <div aria-label="Loading result">
              <CardSkeleton lines={4} />
              <CardSkeleton lines={3} />
            </div>
          )}
        </RecordBody>
      </>
    );
  }

  const path = shown.file_path ?? `file #${shown.file_id}`;
  const callableCount = "callable_ref_count" in shown ? shown.callable_ref_count : shown.callable_refs.length;
  const anchors = shown.reviewed_spans.length + callableCount;
  const notCurrent = detail ? !detail.current : Boolean(shown.superseded_at);
  return (
    <>
      <RecordHeader
        id={`Result #${shown.id}`}
        copyId={String(shown.id)}
        copyIdLabel="Copy result ID"
        title={
          <>
            <span className="mono">{path}</span>
            {shown.function_name ? <span className="cv-record-fn"> · {shown.function_name}</span> : null}
          </>
        }
        titleId={titleId}
        tone={statusTone("code-disposition", shown.disposition)}
        actions={<RecordCopyLinkButton noun="analysis result" />}
        pills={
          <>
            <StatusPill
              domain="code-disposition"
              value={shown.disposition}
              reason={shown.awaiting_verdict ? AWAITING_VERDICT_REASON : undefined}
            />
            {shown.confidence ? <span className="tag">{humanizeStatus(shown.confidence)} confidence</span> : null}
            {shown.cwe_id ? <span className="tag mono">{shown.cwe_id}</span> : null}
            {shown.slot_type ? <span className="tag" title="Input type">{humanizeStatus(shown.slot_type.toLowerCase())}</span> : null}
            {shown.finding_slug ? (
              <a className="tag" href={engagementHref(engagementKey, { tab: "findings", finding: shown.finding_slug })}>
                Finding {shown.finding_slug}
              </a>
            ) : null}
            {shown.finding_workflow_status ? <StatusPill domain="finding-workflow" value={shown.finding_workflow_status} /> : null}
            {shown.finding_verification_status ? (
              <StatusPill domain="finding-verification" value={shown.finding_verification_status} />
            ) : null}
          </>
        }
        datesLabel="Result dates"
        dates={[
          { label: "Recorded", value: shown.created_at, detail: shown.agent_name ? <> · by {shown.agent_name}</> : undefined },
          ...(shown.superseded_at ? [{ label: "Superseded", value: shown.superseded_at }] : []),
        ]}
      >
        {notCurrent ? (
          <p className="cv-inline-note is-warn" role="status">
            Not a current result: a later review of this file replaced it.
            {detail?.replaced_by_result_id ? (
              <>
                {" "}
                <a href={codeViewHref(engagementKey, { view: "results", result: detail.replaced_by_result_id })}>
                  Open result #{detail.replaced_by_result_id}
                </a>
              </>
            ) : null}
          </p>
        ) : null}
      </RecordHeader>
      <RecordTabs
        label="Result sections"
        active={section}
        onChange={onSectionChange}
        tabs={[
          { id: "review", label: "Review" },
          { id: "anchors", label: "Source anchors", count: anchors },
          { id: "coverage", label: "Vulnerability coverage", count: detail?.cwe_coverage.length },
          { id: "leads", label: "Cross-file leads", count: detail?.cross_file_triggers.length },
          { id: "raw", label: "Raw record" },
        ]}
      />
      <RecordBody busy={!detail && !error}>
        {error ? (
          <p className="error-text" role="alert">
            Result detail unavailable: {error}{detail ? " · Showing the last loaded receipt." : ""}
          </p>
        ) : null}

        {section === "review" && (
          <section className="section cv-result-review" aria-label="Review">
            {shown.hypothesis ? <Field label="What was checked" text={shown.hypothesis} /> : null}
            {shown.evidence ? <Field label="What was found" text={shown.evidence} /> : null}
            {shown.notes ? <Field label="Notes" text={shown.notes} /> : null}
            {!shown.hypothesis && !shown.evidence && !shown.notes ? (
              <p className="meta-text">The reviewer recorded no hypothesis, evidence or notes with this result.</p>
            ) : null}
            <dl className="cv-facts">
              <div><dt>Reviewer</dt><dd>{shown.agent_name || "—"}</dd></div>
              <div><dt>Recorded</dt><dd><TimeStamp value={shown.created_at} mode="both" /></dd></div>
              {detail ? (
                <div><dt>Repository</dt><dd className="cv-mono">{detail.repo_key}{detail.repo_role === "reference" ? " (reference)" : ""}</dd></div>
              ) : null}
              <div>
                <dt>Review job</dt>
                <dd>
                  {shown.queue_item_id ? `#${shown.queue_item_id}` : "None"}
                  {detail?.queue_status ? ` · ${humanizeStatus(detail.queue_status).toLowerCase()}` : ""}
                  {detail?.latest_attempt && detail.latest_attempt.id !== shown.queue_item_id
                    ? ` · newer attempt #${detail.latest_attempt.id} ${humanizeStatus(detail.latest_attempt.status).toLowerCase()}`
                    : ""}
                </dd>
              </div>
              <div>
                <dt>Receipt</dt>
                <dd>#{shown.id} · {humanizeStatus(shown.receipt_kind)} receipt · {humanizeStatus(shown.receipt_binding_status).toLowerCase()}</dd>
              </div>
              {detail?.evidence_ref ? <div><dt>Evidence file</dt><dd className="cv-mono">{detail.evidence_ref}</dd></div> : null}
              {detail ? <div><dt>Code snapshot</dt><dd>Snapshot {detail.repo_generation}</dd></div> : null}
              {detail?.result_fingerprint ? (
                <div><dt>Fingerprint</dt><dd className="cv-mono">{detail.result_fingerprint}</dd></div>
              ) : null}
            </dl>
          </section>
        )}

        {section === "anchors" && (
          <section className="section" aria-label="Source anchors">
            {anchors === 0 ? (
              <p className="meta-text">{receiptAnchorNote(shown.receipt_binding_status)}</p>
            ) : null}
            {shown.reviewed_spans.length > 0 ? (
              <>
                <p className="section-title">
                  {shown.reviewed_spans.length} reviewed {shown.reviewed_spans.length === 1 ? "span" : "spans"}
                </p>
                <ul className="cv-anchor-list">
                  {shown.reviewed_spans.map((span, index) => (
                    <li key={`${span.file_id}:${span.start_line}:${span.end_line}:${index}`}>
                      <span className="cv-mono">
                        {span.file_path === shown.file_path ? "" : `${span.file_path}:`}
                        {span.start_line}–{span.end_line}
                      </span>
                      {span.label ? <span className="cv-anchor-label">{span.label}</span> : null}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
            {callableCount > 0 ? (
              <>
                <p className="section-title">
                  {callableCount.toLocaleString()} {callableCount === 1 ? "function" : "functions"} reviewed
                </p>
                <ul className="cv-anchor-list">
                  {shown.callable_refs.map((ref) => (
                    <li key={ref.callable_key}>
                      <span className="cv-mono">{ref.qualified_name}</span>{" "}
                      <span className="meta-text">
                        {ref.file_path === shown.file_path ? "" : `${ref.file_path}:`}
                        {ref.start_line}–{ref.end_line}
                      </span>
                    </li>
                  ))}
                </ul>
                {shown.callable_refs.length < callableCount ? (
                  <p className="meta-text">
                    {shown.callable_refs.length.toLocaleString()} of {callableCount.toLocaleString()} listed; the full receipt loads with the record.
                  </p>
                ) : null}
              </>
            ) : null}
          </section>
        )}

        {section === "coverage" && (
          <section className="section" aria-label="Vulnerability coverage">
            {!detail ? (
              error ? null : <CardSkeleton lines={3} />
            ) : detail.cwe_coverage.length === 0 ? (
              <EmptyState variant="empty" compact title="No per-type coverage recorded.">
                The reviewer did not record which vulnerability types this review covered.
              </EmptyState>
            ) : (
              <div className="cv-table-scroll">
                <table className="cv-table">
                  <thead>
                    <tr>
                      <th scope="col">Vulnerability type</th>
                      <th scope="col">Outcome</th>
                      <th scope="col" className="cv-num">Effort</th>
                      <th scope="col" className="cv-num">Functions</th>
                      <th scope="col" className="cv-num">Entry chains</th>
                      <th scope="col">Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.cwe_coverage.map((entry, index) => (
                      <tr key={`${entry.family}:${index}`}>
                        <th scope="row" title={entry.family}>{familyLabel(entry.family)}</th>
                        <td>{humanizeStatus(entry.disposition)}</td>
                        <td className="cv-num">{entry.effort ?? "—"}</td>
                        <td className="cv-num">{entry.functions_analyzed ?? "—"}</td>
                        <td className="cv-num">
                          {entry.entry_chains_traced ?? "—"}
                          {entry.total_entry_chains != null ? ` of ${entry.total_entry_chains}` : ""}
                        </td>
                        <td className="cv-coverage-notes">{entry.notes || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {section === "leads" && (
          <section className="section" aria-label="Cross-file leads">
            {!detail ? (
              error ? null : <CardSkeleton lines={3} />
            ) : detail.cross_file_triggers.length === 0 ? (
              <EmptyState variant="empty" compact title="No cross-file leads.">
                This review did not point at another file to review with its context.
              </EmptyState>
            ) : (
              <ul className="cv-leads">
                {detail.cross_file_triggers.map((lead, index) => (
                  <li key={`${lead.file_path ?? ""}:${index}`}>
                    <div className="cv-lead-head">
                      <span className="cv-path" title={lead.file_path}>{lead.file_path || "Unnamed file"}</span>
                      {lead.vuln_class ? <span className="tag">{familyLabel(lead.vuln_class)}</span> : null}
                    </div>
                    {lead.reason ? <p>{lead.reason}</p> : null}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {section === "raw" && (
          <section className="section" aria-label="Raw record">
            {detail ? <JsonView value={detail} label={`analysis result #${shown.id}`} /> : error ? null : <CardSkeleton lines={4} />}
          </section>
        )}
      </RecordBody>
    </>
  );
}
