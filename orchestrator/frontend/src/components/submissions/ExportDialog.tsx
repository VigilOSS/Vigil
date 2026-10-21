import { useRef } from "react";
import { FileArchive, X } from "lucide-react";

import { useBodyScrollLock, useModalFocus } from "../../lib/modalScrollLock";
import type { SubmissionDeskDetail, SubmissionReadiness } from "../../lib/submissionsApi";
import { formatBytes } from "../formatting";
import type { AttachmentMeta } from "./AttachmentPicker";
import { basename, dirname, platformLabel } from "./model";

// Confirmation for the one irreversible action on this page. It states exactly
// what will be sealed so the operator never exports an unseen selection.
export function ExportDialog({
  detail,
  readiness,
  selection,
  meta,
  nextVersion,
  exporting,
  error,
  onConfirm,
  onClose,
}: {
  detail: SubmissionDeskDetail;
  readiness: SubmissionReadiness;
  selection: number[];
  meta: Map<number, AttachmentMeta>;
  nextVersion: number;
  exporting: boolean;
  error: string;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const panelRef = useRef<HTMLDivElement | null>(null);
  const close = () => {
    if (!exporting) onClose();
  };
  useModalFocus(panelRef, close);
  useBodyScrollLock();
  const latest = detail.latest_version;
  const bodyUnchanged = Boolean(
    latest && latest.submission_sha256 === readiness.external_body_sha256,
  );
  const platform = readiness.platform ?? detail.platform;
  return (
    <div
      className="subm-dialog-overlay"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <div
        ref={panelRef}
        className="subm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="subm-export-title"
        aria-describedby="subm-export-summary"
        tabIndex={-1}
      >
        <header className="subm-dialog-head">
          <h2 id="subm-export-title">Export immutable v{nextVersion} of {detail.finding.slug}?</h2>
          <button type="button" className="icon-btn" onClick={close} aria-label="Cancel export" disabled={exporting}>
            <X size={16} aria-hidden="true" />
          </button>
        </header>
        <p id="subm-export-summary" className="subm-dialog-lede">
          This seals the exact bytes below as version {nextVersion}. A version can never be edited or
          deleted; a correction is a later version. <strong>Exporting changes nothing on {platformLabel(platform)}</strong>
          {" "}— you still file the downloaded package yourself.
        </p>
        <dl className="subm-dialog-facts">
          <div>
            <dt>Body</dt>
            <dd>
              <code>submission-body.md</code> · sha256 <code>{readiness.external_body_sha256}</code>
            </dd>
          </div>
          <div>
            <dt>Platform</dt>
            <dd>{platformLabel(platform)}</dd>
          </div>
          <div>
            <dt>Finding</dt>
            <dd>row version {readiness.finding_row_version ?? detail.finding.row_version}</dd>
          </div>
          <div>
            <dt>Package</dt>
            <dd>
              {selection.length === 0
                ? "Markdown file (no attachments)"
                : `ZIP with the body, an attachment manifest, and ${selection.length} attachment${selection.length === 1 ? "" : "s"} (${formatBytes(readiness.attachment_total_bytes)})`}
            </dd>
          </div>
        </dl>
        {selection.length > 0 && (
          <ul className="subm-dialog-files" aria-label="Attachments to seal">
            {selection.map((id) => {
              const row = meta.get(id);
              return (
                <li key={id}>
                  <span className="subm-dialog-file" title={row?.relative_path}>
                    <span>{row ? basename(row.relative_path) : `Artifact #${id}`}</span>
                    <span className="subm-dialog-folder">
                      <span>{row ? dirname(row.relative_path) : "metadata not loaded"}</span> · artifact #{id}
                    </span>
                  </span>
                  <span>{row?.size_bytes != null ? formatBytes(row.size_bytes) : ""}</span>
                </li>
              );
            })}
          </ul>
        )}
        {bodyUnchanged && latest && (
          <p className="subm-dialog-warn" role="note">
            The body is identical to v{latest.version_number}; only the attachments or finding version differ.
          </p>
        )}
        {error && <p className="subm-inline-error" role="alert">{error}</p>}
        <footer className="subm-dialog-actions">
          <button type="button" className="ghost-button" onClick={close} disabled={exporting}>
            Cancel
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={onConfirm}
            disabled={exporting}
          >
            <FileArchive size={15} aria-hidden="true" />
            {exporting ? "Verifying and sealing…" : `Seal v${nextVersion}`}
          </button>
        </footer>
      </div>
    </div>
  );
}
