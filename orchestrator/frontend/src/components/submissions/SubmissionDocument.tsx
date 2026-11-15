import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  FileArchive,
  Lock,
  RefreshCcw,
  X,
} from "lucide-react";

import { submissionVersionDownloadUrl } from "../../lib/api";
import type { SubmissionPendingVersion, SubmissionRecoveryResult } from "../../lib/api";
import type {
  SubmissionAttachmentRow,
  SubmissionBlockerItem,
  SubmissionDeskDetail,
  SubmissionDeskRow,
  SubmissionReadiness,
} from "../../lib/submissionsApi";
import { useToast } from "../../contexts/ToastContext";
import { CopyChip } from "../drawer/DrawerKit";
import { TimeStamp, formatBytes } from "../formatting";
import { MarkdownBlock } from "../Markdown";
import { Skeleton, SlowLoadHint } from "../Skeletons";
import { StatusPill } from "../ui";
import { FindingRecordHeader } from "../FindingRecordHeader";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs, type RecordTab } from "../record/RecordView";
import { operatorAuthorityOf } from "../../lib/findingWorkflow";
import { AttachmentPicker, type AttachmentMeta } from "./AttachmentPicker";
import {
  nextVersionNumber,
  operatorSection,
  platformLabel,
  safeExternalHref,
  shortHash,
  versionAttachmentNames,
} from "./model";
import { QueuePill, SubmissionTime } from "./SubmissionQueue";

/** The document's sections (`dtab` in the address). */
export const DOCUMENT_TABS = ["body", "notes", "package", "versions", "readiness"] as const;
export type DocumentTab = (typeof DOCUMENT_TABS)[number];
export type ViewMode = "rendered" | "raw";

/** The engagement-wide recovery of staged exports; it sits in the page header and in a record's Versions section. */
export function RecoverExportsButton({ count, recovering, disabled, onRecover }: {
  count: number;
  recovering: boolean;
  disabled: boolean;
  onRecover: () => void;
}) {
  return (
    <button
      type="button"
      className="ui-button subm-recover"
      onClick={onRecover}
      disabled={disabled}
      title="Verify and complete staged exports (writes only completed versions)"
    >
      <RefreshCcw size={13} aria-hidden="true" />
      {recovering ? "Recovering…" : `Recover ${count} staged export${count === 1 ? "" : "s"}`}
    </button>
  );
}

/** What a recovery could not finish: the exports that failed and staging paths no version owns. */
export function RecoveryIssues({ issues, onDismiss }: { issues: SubmissionRecoveryResult; onDismiss: () => void }) {
  return (
    <div className="subm-callout is-danger subm-recovery" role="alert">
      <div className="subm-recovery-head">
        <strong>Recovery incomplete.</strong>
        <button type="button" className="icon-btn" aria-label="Dismiss recovery details" onClick={onDismiss}>
          <X size={14} aria-hidden="true" />
        </button>
      </div>
      {issues.failed_versions.length > 0 && <PendingVersionRows versions={issues.failed_versions} />}
      {issues.orphaned_staging_paths.length > 0 && (
        <div>
          <p>Orphaned staging path{issues.orphaned_staging_paths.length === 1 ? "" : "s"}:</p>
          <ul>
            {issues.orphaned_staging_paths.map((path) => <li key={path}><code>{path}</code></li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function PendingVersionRows({ versions }: { versions: SubmissionPendingVersion[] }) {
  return (
    <ul className="subm-pending-list">
      {versions.map((version) => (
        <li className="subm-pending-row" key={version.id}>
          <strong>
            <code>{version.finding_slug}</code> · version {version.version_number} (#{version.id}){" "}
            <StatusPill domain="submission-version" value={version.status} size="sm" />
          </strong>
          {version.failure_reason && <p>{version.failure_reason}</p>}
          <dl>
            <div>
              <dt>Staging</dt>
              <dd><code>{version.staging_relative_path}</code></dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd><code>{version.relative_path}</code></dd>
            </div>
          </dl>
        </li>
      ))}
    </ul>
  );
}

// Blockers that share one fix are listed together under it, in first-seen order.
function groupBlockers(items: SubmissionBlockerItem[]): Array<{ messages: string[]; fix: string; command: string }> {
  const groups: Array<{ messages: string[]; fix: string; command: string }> = [];
  for (const item of items) {
    const group = (item.fix || item.command)
      ? groups.find((candidate) => candidate.fix === item.fix && candidate.command === item.command)
      : undefined;
    if (group) group.messages.push(item.message);
    else groups.push({ messages: [item.message], fix: item.fix, command: item.command });
  }
  return groups;
}

function ViewToggle({ mode, onChange }: { mode: ViewMode; onChange: (mode: ViewMode) => void }) {
  return (
    <div className="subm-segmented" role="group" aria-label="Document view">
      <button type="button" aria-pressed={mode === "rendered"} onClick={() => onChange("rendered")}>
        Rendered
      </button>
      <button type="button" aria-pressed={mode === "raw"} onClick={() => onChange("raw")}>
        Raw Markdown
      </button>
    </div>
  );
}

function MarkdownView({ text, mode }: { text: string; mode: ViewMode }) {
  return mode === "rendered" ? (
    <div className="subm-markdown"><MarkdownBlock text={text} /></div>
  ) : (
    <pre className="subm-raw">{text}</pre>
  );
}

// The single primary action, always in the record header: export, download the
// version that already captured this exact selection, or explain the block.
function PrimaryAction({
  engagementKey,
  detail,
  readiness,
  checking,
  locked,
  exporting,
  onExport,
  onShowReadiness,
  onShowRenderGuide,
}: {
  engagementKey: string;
  detail: SubmissionDeskDetail | null;
  readiness: SubmissionReadiness | null;
  checking: boolean;
  locked: boolean;
  exporting: boolean;
  onExport: () => void;
  onShowReadiness: () => void;
  onShowRenderGuide: () => void;
}) {
  if (!detail || !readiness || checking) {
    return (
      <button type="button" className="primary-button subm-primary" disabled>
        <FileArchive size={15} aria-hidden="true" />
        Checking readiness…
      </button>
    );
  }
  const existing = readiness.existing_version_number;
  if (existing != null) {
    return (
      <a
        className="primary-button subm-primary is-download"
        href={submissionVersionDownloadUrl(engagementKey, detail.finding.slug, existing)}
        download
      >
        <Download size={15} aria-hidden="true" />
        Already captured as v{existing} — Download
      </a>
    );
  }
  if (!detail.workspace.present) {
    return (
      <button
        type="button"
        className="subm-primary subm-blocked-button"
        onClick={onShowRenderGuide}
        aria-label="No rendered submission yet; show how to render one"
      >
        <Lock size={14} aria-hidden="true" />
        Needs a rendered draft
      </button>
    );
  }
  if (!readiness.final_ready) {
    const count = readiness.blockers.length;
    return (
      <button
        type="button"
        className="subm-primary subm-blocked-button"
        onClick={onShowReadiness}
        aria-label={`Export blocked by ${count} issue${count === 1 ? "" : "s"}; show readiness`}
      >
        <Lock size={14} aria-hidden="true" />
        Blocked ({count}) — see Readiness
      </button>
    );
  }
  const next = nextVersionNumber(detail);
  return (
    <button
      type="button"
      className="primary-button subm-primary"
      onClick={onExport}
      disabled={locked}
    >
      <FileArchive size={15} aria-hidden="true" />
      {exporting ? "Exporting…" : `Export v${next}…`}
    </button>
  );
}

/** One finding's submission record: the shared finding header, its sections and the open section. */
export function SubmissionDocument({
  engagementKey,
  slug,
  titleId,
  row,
  detail,
  detailLoading,
  detailError,
  readiness,
  checkingReadiness,
  selection,
  meta,
  tab,
  mode,
  showWholeWorkspace,
  locked,
  exporting,
  previewOutdated,
  stagingCount,
  recovering,
  recoveryIssues,
  loadingMoreVersions,
  loadingMorePending,
  onTab,
  onMode,
  onShowWholeWorkspace,
  onRefresh,
  onExport,
  onRecover,
  onDismissRecoveryIssues,
  onToggleAttachment,
  onReplaceAttachments,
  onAttachmentRows,
  onLoadMoreVersions,
  onLoadMorePending,
}: {
  engagementKey: string;
  /** The open finding, known before any of its data is. */
  slug: string;
  titleId: string;
  /** The finding's queue row; null when the list as loaded does not hold it. */
  row: SubmissionDeskRow | null;
  detail: SubmissionDeskDetail | null;
  detailLoading: boolean;
  detailError: string;
  readiness: SubmissionReadiness | null;
  checkingReadiness: boolean;
  selection: number[];
  meta: Map<number, AttachmentMeta>;
  tab: DocumentTab;
  /** Rendered or raw Markdown, for the body and the operator notes. */
  mode: ViewMode;
  /** Operator notes show the whole of submission.md, not only its operator section. */
  showWholeWorkspace: boolean;
  locked: boolean;
  exporting: boolean;
  previewOutdated: boolean;
  /** Staged exports across the engagement that recovery can complete. */
  stagingCount: number;
  recovering: boolean;
  /** What the last recovery could not finish. */
  recoveryIssues: SubmissionRecoveryResult | null;
  loadingMoreVersions: boolean;
  loadingMorePending: boolean;
  onTab: (tab: DocumentTab) => void;
  onMode: (mode: ViewMode) => void;
  onShowWholeWorkspace: (shown: boolean) => void;
  onRefresh: () => void;
  onExport: () => void;
  onRecover: () => void;
  onDismissRecoveryIssues: () => void;
  onToggleAttachment: (id: number) => void;
  onReplaceAttachments: (ids: number[]) => void;
  onAttachmentRows: (rows: SubmissionAttachmentRow[]) => void;
  onLoadMoreVersions: () => void;
  onLoadMorePending: () => void;
}) {
  const { toast } = useToast();

  if (!row && !detail) {
    // The named finding has no row and no detail yet: say whether it is loading or could not be read.
    return (
      <>
        <RecordHeader
          id={slug}
          copyId={slug}
          title={`Submission for ${slug}`}
          titleId={titleId}
          actions={<RecordCopyLinkButton noun="submission" />}
        />
        <RecordBody busy={detailLoading}>
          {detailError ? (
            <p className="error-text" role="alert">
              Submission for {slug} unavailable: {detailError}{" "}
              <button type="button" className="qa-btn" onClick={onRefresh} disabled={detailLoading}>Retry</button>
            </p>
          ) : (
            <p className="meta-text" role="status">Loading {slug}…</p>
          )}
        </RecordBody>
      </>
    );
  }

  const title = row?.title ?? detail?.finding.title ?? "";
  const severity = row?.severity ?? detail?.finding.severity ?? "info";
  const submissionStatus = row?.submission_status ?? detail?.finding.submission_status ?? "none";
  const submissionRef = row?.submission_ref ?? "";
  const submissionUrl = row?.submission_url ?? "";
  const externalHref = safeExternalHref(submissionUrl);
  const platform = detail?.platform ?? row?.default_platform ?? null;
  const latest = detail?.latest_version ?? null;
  const showingStale = detailLoading && detail != null;
  const pendingCount = detail?.pending_version_count ?? 0;
  // A merged or false-positive finding is in no submission list, whatever the filters.
  const retired = detail?.finding.workflow_status === "merged" ? "merged"
    : detail?.finding.workflow_status === "false_positive" ? "a false positive"
    : null;

  const workspace = detail?.workspace;
  // Section tabs carry a count only: the attachments selected, the immutable
  // versions, and the blockers while any stand.
  const tabs: RecordTab<DocumentTab>[] = [
    { id: "body", label: "Submission body" },
    { id: "notes", label: "Operator notes" },
    { id: "package", label: "Package", count: selection.length },
    { id: "versions", label: "Versions", count: detail?.versions_page.total ?? row?.version_count ?? 0 },
    {
      id: "readiness",
      label: "Readiness",
      count: readiness && !checkingReadiness && !readiness.final_ready ? readiness.blockers.length : undefined,
    },
  ];
  const operatorNotes = workspace?.present ? operatorSection(workspace.markdown) : null;
  const renderCommand = `vigil assess export submission ${slug} --platform ${platform ?? "<bugcrowd|hackerone|direct|ghsa>"} --draft`;

  let body: ReactNode;
  if (!detail) {
    body = detailError ? (
      <div className="subm-pane-message" role="alert">
        <p className="subm-inline-error">{detailError}</p>
        <button type="button" className="qa-btn" onClick={onRefresh}>Retry</button>
      </div>
    ) : (
      <div className="subm-doc-skeleton" aria-busy="true" role="status" aria-label="Loading submission">
        <Skeleton width="40%" height={18} />
        <Skeleton width="92%" />
        <Skeleton width="88%" />
        <Skeleton width="95%" />
        <Skeleton width="60%" />
        <Skeleton width="35%" height={16} style={{ marginTop: 18 }} />
        <Skeleton width="90%" />
        <Skeleton width="84%" />
        <SlowLoadHint active={detailLoading} what="this submission" detail="The backend re-reads the workspace and re-hashes the reviewed attachments." />
      </div>
    );
  } else if (tab === "body" || tab === "notes") {
    if (!workspace?.present) {
      body = (
        <div className="subm-no-draft">
          <h3>No rendered submission yet</h3>
          <p>Render a draft with the CLI, review it, then render the final version. This page reads those files.</p>
          <div className="subm-command">
            <code>{renderCommand}</code>
            <CopyChip text={renderCommand} toast={toast} label="Copy render command" />
          </div>
          <p>Rerun without <code>--draft</code> once its diagnostics are addressed to make it final-ready.</p>
          {readiness && readiness.blockers.length > 0 && (
            <p className="subm-muted">Reason: {readiness.blockers[0]}</p>
          )}
        </div>
      );
    } else if (tab === "body") {
      body = (
        <>
          <div className="subm-pane-toolbar">
            <span className="subm-muted">
              <code>submission-body.md</code> — exactly what the program receives
            </span>
            <span className="subm-hash">
              sha256 <code title={workspace.external_body_sha256 ?? undefined}>{shortHash(workspace.external_body_sha256)}</code>
              <CopyChip text={workspace.external_body_sha256 ?? ""} toast={toast} label="Copy body sha256" />
            </span>
          </div>
          {!workspace.external_body_valid_utf8 && (
            <p className="subm-pane-note is-warn">This body is not valid UTF-8; unreadable bytes are shown as �.</p>
          )}
          {workspace.external_body
            ? <MarkdownView text={workspace.external_body} mode={mode} />
            : <p className="subm-empty">The external body file is empty or missing. See Readiness.</p>}
        </>
      );
    } else {
      const notes = showWholeWorkspace ? workspace.markdown : operatorNotes;
      body = (
        <>
          <div className="subm-pane-toolbar">
            <span className="subm-muted">
              Internal reference from <code>submission.md</code> — never part of the export
            </span>
            <label className="subm-check">
              <input
                type="checkbox"
                checked={showWholeWorkspace}
                onChange={(event) => onShowWholeWorkspace(event.target.checked)}
              />
              Show all of submission.md
            </label>
          </div>
          {notes
            ? <MarkdownView text={notes} mode={mode} />
            : <p className="subm-empty">This render has no OPERATOR DETAILS section.</p>}
        </>
      );
    }
  } else if (tab === "package") {
    body = (
      <AttachmentPicker
        engagementKey={engagementKey}
        detail={detail}
        selection={selection}
        meta={meta}
        readiness={readiness}
        disabled={locked}
        onToggle={onToggleAttachment}
        onReplace={onReplaceAttachments}
        onRows={onAttachmentRows}
      />
    );
  } else if (tab === "versions") {
    body = (
      <div className="subm-versions">
        {recoveryIssues && <RecoveryIssues issues={recoveryIssues} onDismiss={onDismissRecoveryIssues} />}
        {detail.pending_versions.length > 0 && (
          <section className="subm-callout is-danger" aria-label="Incomplete export reservations">
            <h4>
              <AlertTriangle size={14} aria-hidden="true" /> {detail.pending_version_count} incomplete export
              {detail.pending_version_count === 1 ? "" : "s"}
            </h4>
            <p>Staged exports can be completed with “Recover staged exports”; failed ones keep their reason.</p>
            {stagingCount > 0 && (
              <div>
                <RecoverExportsButton count={stagingCount} recovering={recovering} disabled={locked} onRecover={onRecover} />
              </div>
            )}
            <PendingVersionRows versions={detail.pending_versions} />
            {detail.pending_versions_page.has_more && (
              <button type="button" className="pager-btn" onClick={onLoadMorePending} disabled={loadingMorePending}>
                {loadingMorePending ? "Loading incomplete exports…" : "Load more incomplete exports"}
              </button>
            )}
          </section>
        )}
        {detail.versions.length === 0 ? (
          <p className="subm-empty">No immutable versions yet. Exports are append-only; each one is listed here.</p>
        ) : (
          <div className="subm-table-scroll" role="region" aria-label="Version history" tabIndex={0}>
            <table className="subm-table">
              <thead>
                <tr>
                  <th scope="col">Version</th>
                  <th scope="col">Exported</th>
                  <th scope="col">Platform</th>
                  <th scope="col">Attachments</th>
                  <th scope="col">Finding version</th>
                  <th scope="col">Package</th>
                  <th scope="col"><span className="sr-only">Download</span></th>
                </tr>
              </thead>
              <tbody>
                {detail.versions.map((version) => {
                  const names = versionAttachmentNames(version);
                  return (
                    <tr key={version.id}>
                      <th scope="row">
                        v{version.version_number}
                        {readiness?.existing_version_number === version.version_number && (
                          <span className="subm-chip is-ok">matches current</span>
                        )}
                      </th>
                      <td>
                        <TimeStamp value={version.completed_at} mode="both" fallback="pending" />
                        <span className="subm-muted subm-actor">by {version.actor_surface}</span>
                      </td>
                      <td>{platformLabel(version.platform)}</td>
                      <td>
                        {names.length === 0 ? (
                          <span className="subm-muted">none</span>
                        ) : (
                          <span className="subm-names" title={names.join("\n")}>{names.join(", ")}</span>
                        )}
                      </td>
                      <td>
                        row {version.source_finding_row_version}
                        {version.stale
                          ? <StatusPill tone="warning" value="stale" label="Stale" size="sm" title="The finding changed after this version was exported" />
                          : <StatusPill tone="success" value="current" label="Current" size="sm" title="Exported from the finding as it is now" />}
                      </td>
                      <td>
                        {version.package_format.toUpperCase()} · {formatBytes(version.size_bytes)}
                        <span className="subm-hash">
                          <code title={version.sha256}>{shortHash(version.sha256)}</code>
                          <CopyChip text={version.sha256} toast={toast} label={`Copy v${version.version_number} sha256`} />
                        </span>
                      </td>
                      <td>
                        <a
                          className="qa-btn subm-download"
                          href={submissionVersionDownloadUrl(engagementKey, slug, version.version_number)}
                          download
                        >
                          <Download size={13} aria-hidden="true" /> Download v{version.version_number}
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {detail.versions_page.has_more && (
          <button type="button" className="pager-btn" onClick={onLoadMoreVersions} disabled={loadingMoreVersions}>
            {loadingMoreVersions ? "Loading versions…" : "Load more versions"}
          </button>
        )}
      </div>
    );
  } else {
    const triage = detail.blind_triage;
    const qc = readiness?.submission_qc ?? detail.submission_qc;
    // Rows as the reviewer recorded them. A value that is not text is shown as its JSON, and an
    // entry that is not a row object is shown whole; only an empty entry has nothing to show.
    const recorded = (value: unknown): string => (typeof value === "string" ? value : value == null ? "" : JSON.stringify(value));
    const failedRows = ((qc.failed_rows ?? []) as unknown[])
      .filter((failed) => failed != null)
      .map((failed) => (typeof failed === "object"
        ? { row: recorded((failed as { row?: unknown }).row), quote: recorded((failed as { quote?: unknown }).quote) }
        : { row: recorded(failed), quote: "" }));
    body = (
      <div className="subm-readiness">
        {!readiness || checkingReadiness ? (
          <p className="subm-muted" role="status">Checking every export gate for this selection…</p>
        ) : readiness.final_ready ? (
          <p className="subm-callout is-ok">
            <CheckCircle2 size={15} aria-hidden="true" /> Every export gate passes for the current body and
            {" "}{selection.length === 0 ? "no attachments" : `${selection.length} selected attachment${selection.length === 1 ? "" : "s"}`}.
            Export re-checks all of them and re-hashes every file.
          </p>
        ) : (
          <ol className="subm-blockers" aria-label={`${readiness.blockers.length} export blockers`}>
            {groupBlockers(readiness.items).map((group) => (
              <li key={group.messages[0]}>
                {group.messages.map((message) => <strong key={message}>{message}</strong>)}
                {group.fix && <p>{group.fix}</p>}
                {group.command && (
                  <div className="subm-command">
                    <code>{group.command}</code>
                    <CopyChip text={group.command} toast={toast} label="Copy command" />
                  </div>
                )}
              </li>
            ))}
          </ol>
        )}
        <dl className="subm-facts">
          <div>
            <dt>Submission QC</dt>
            <dd>
              <StatusPill domain="qc-review" value={qc.status} size="sm" />
              {qc.status === "missing" ? null : <>
                {qc.verdict && <> · verdict <code>{qc.verdict}</code></>}
                {qc.reviewer_dispatch_agent_id && <> · reviewer {qc.reviewer_dispatch_agent_id}</>}
                {qc.writer_dispatch_agent_id && <> · writer {qc.writer_dispatch_agent_id}</>}
                {qc.packet_id && <> · packet <code title={qc.packet_id ?? undefined}>{shortHash(qc.packet_id)}</code></>}
                {qc.decided_at && <> · <TimeStamp value={qc.decided_at} mode="both" /></>}
                {qc.issue && <p>{qc.issue}</p>}
                {failedRows.length > 0 && (
                  <ul aria-label="Failed QC rows">
                    {failedRows.map((failed, index) => (
                      <li key={index}>
                        <strong>{failed.row}</strong>{failed.quote ? <>: <q>{failed.quote}</q></> : null}
                      </li>
                    ))}
                  </ul>
                )}
              </>}
              <span className="subm-muted">
                {" "}({qc.required ? "a separate report-writer reviews every submission" : "not required for this engagement"})
              </span>
            </dd>
          </div>
          <div>
            <dt>Blind triage</dt>
            <dd>
              {triage.verdict
                ? <>{triage.verdict} · packet <code title={triage.packet_id ?? undefined}>{shortHash(triage.packet_id)}</code></>
                : "No verdict recorded"}
              {triage.decided_at && <> · <TimeStamp value={triage.decided_at} mode="both" /></>}
              <span className="subm-muted">
                {" "}({triage.required ? "required for Medium and above" : "not required at this severity"})
              </span>
            </dd>
          </div>
          <div>
            <dt>Reviewed body</dt>
            <dd>
              {triage.reviewed_body_sha256 ? <code title={triage.reviewed_body_sha256 ?? undefined}>{shortHash(triage.reviewed_body_sha256)}</code> : "—"}
              {triage.reviewed_body_sha256 && workspace?.external_body_sha256 && (
                triage.reviewed_body_sha256 === workspace.external_body_sha256
                  ? <span className="subm-chip is-ok">matches current body</span>
                  : <span className="subm-chip is-warn">differs from current body</span>
              )}
            </dd>
          </div>
          <div>
            <dt>Workspace</dt>
            <dd>
              <code>{workspace?.submission_path}</code>
              {workspace?.present && <> · mode {String(workspace.context.mode ?? "unknown")}</>}
            </dd>
          </div>
        </dl>
      </div>
    );
  }

  const proseSection = (tab === "body" || tab === "notes") && Boolean(workspace?.present);
  return (
    <>
      <FindingRecordHeader engagementKey={engagementKey} slug={slug} title={title}
        titleId={titleId} severity={severity}
        workflow={row?.workflow_status ?? detail?.finding.workflow_status}
        verification={row?.verification_status ?? detail?.finding.verification_status}
        // The disclosure package is the handoff to an external program, so
        // this is the last place a verdict taken on the operator's own
        // authority may look dispatch-verified.
        operatorAuthority={operatorAuthorityOf(detail?.finding)}
        submission={submissionStatus} workspace="submissions" section={tab}
        pills={row && <span className="finding-status-axis" role="group" aria-label="Package readiness">Package <QueuePill row={row} size="md" /></span>}
        dates={row ? [{ label: "Finding changed", value: row.updated_at }] : undefined}
        datesLabel="Submission dates"
        actions={<>
          <RecordCopyLinkButton noun="submission" />
          <div className="subm-record-action">
            <PrimaryAction
              engagementKey={engagementKey}
              detail={detail}
              readiness={readiness}
              checking={checkingReadiness}
              locked={locked}
              exporting={exporting}
              onExport={onExport}
              onShowReadiness={() => onTab("readiness")}
              onShowRenderGuide={() => onTab("body")}
            />
            <span className="subm-action-note">Exporting never submits anything.</span>
          </div>
        </>}
      >
        <div className="subm-record-meta">
          {latest ? (
            <span className={`subm-chip ${latest.stale ? "is-warn" : ""}`}>
              Latest v{latest.version_number}
              {latest.stale ? " · stale" : ""} · <SubmissionTime value={latest.completed_at} />
            </span>
          ) : !detail && row?.latest_version_number != null ? (
            <span className="subm-chip">
              Latest v{row.latest_version_number} · <SubmissionTime value={row.latest_version_completed_at} />
            </span>
          ) : (
            <span className="subm-chip">{detail ? "No version yet" : "Loading versions…"}</span>
          )}
          <span className="subm-chip">{platformLabel(platform)}</span>
          {submissionRef && <code>{submissionRef}</code>}
          {submissionUrl && (
            externalHref
              ? <a href={externalHref} target="_blank" rel="noopener noreferrer" className="subm-meta-link">Platform report <ExternalLink size={12} aria-hidden="true" /></a>
              : <code className="subm-chip" title="Not an http(s) URL; shown as text">{submissionUrl}</code>
          )}
        </div>
        {retired && (
          <div className="subm-header-notice is-info" role="status">
            <span>{slug} is {retired}, so no submission list includes it.</span>
          </div>
        )}
        {pendingCount > 0 && (
          <div className="subm-header-notice is-error" role="status">
            <AlertTriangle size={14} aria-hidden="true" />
            <span>
              {pendingCount.toLocaleString()} incomplete export{pendingCount === 1 ? "" : "s"}: staged or failed, and not among this
              finding&apos;s versions.
            </span>
            {tab !== "versions" && <button type="button" className="qa-btn" onClick={() => onTab("versions")}>Show in Versions</button>}
          </div>
        )}
        {previewOutdated && (
          <div className="subm-header-notice" role="status">
            <AlertTriangle size={14} aria-hidden="true" />
            <span>The finding changed while you were reviewing. Gates and preview are from the earlier state.</span>
            <button type="button" className="qa-btn" onClick={onRefresh} disabled={detailLoading}>
              <RefreshCcw size={13} aria-hidden="true" /> {detailLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        )}
        {detail && detailError && (
          <div className="subm-header-notice is-error" role="alert">
            <span>{detailError}</span>
            <button type="button" className="qa-btn" onClick={onRefresh}>Retry</button>
          </div>
        )}
      </FindingRecordHeader>
      <RecordTabs
        tabs={tabs}
        active={tab}
        onChange={onTab}
        label="Submission sections"
        trailing={proseSection ? <ViewToggle mode={mode} onChange={onMode} /> : undefined}
      />
      <RecordBody busy={detailLoading}>
        <div className={`subm-section${showingStale ? " is-reloading" : ""}`}>
          <SlowLoadHint active={showingStale} what={`the latest state for ${slug}`} />
          {body}
        </div>
      </RecordBody>
    </>
  );
}
