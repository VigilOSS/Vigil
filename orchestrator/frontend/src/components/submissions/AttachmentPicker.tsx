import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, AlertTriangle, Info } from "lucide-react";

import { listSubmissionAttachments } from "../../lib/submissionsApi";
import type {
  SubmissionAttachmentRow,
  SubmissionAttachmentScope,
  SubmissionDeskDetail,
  SubmissionReadiness,
} from "../../lib/submissionsApi";
import { formatBytes } from "../formatting";
import { EmptyState, SegmentedControl, StatusPill } from "../ui";
import { basename, dirname, sameIdSet, shortHash } from "./model";
import { SubmissionTime } from "./SubmissionQueue";

export type AttachmentMeta = {
  id: number;
  relative_path: string;
  size_bytes: number | null;
  kind?: string;
  updated_at?: string;
  internal?: boolean;
};

const PAGE_SIZE = 100;
const ATTACHMENT_LIMIT_BYTES = 256 * 1024 * 1024;

type BrowseState = {
  scope: SubmissionAttachmentScope;
  query: string;
  rows: SubmissionAttachmentRow[];
  total: number;
  hasMore: boolean;
  nextOffset: number | null;
};

function groupByFolder(rows: SubmissionAttachmentRow[]): Array<[string, SubmissionAttachmentRow[]]> {
  const groups = new Map<string, SubmissionAttachmentRow[]>();
  for (const row of rows) {
    const folder = dirname(row.relative_path);
    const group = groups.get(folder);
    if (group) group.push(row);
    else groups.set(folder, [row]);
  }
  return [...groups.entries()];
}

export function AttachmentPicker({
  engagementKey,
  detail,
  selection,
  meta,
  readiness,
  disabled,
  onToggle,
  onReplace,
  onRows,
}: {
  engagementKey: string;
  detail: SubmissionDeskDetail;
  selection: number[];
  meta: Map<number, AttachmentMeta>;
  readiness: SubmissionReadiness | null;
  disabled: boolean;
  onToggle: (id: number) => void;
  onReplace: (ids: number[]) => void;
  onRows: (rows: SubmissionAttachmentRow[]) => void;
}) {
  const slug = detail.finding.slug;
  const initialBrowse = useMemo<BrowseState>(() => ({
    scope: "finding",
    query: "",
    rows: detail.eligible_attachments,
    total: detail.eligible_attachments_page.total,
    hasMore: detail.eligible_attachments_page.has_more,
    nextOffset: detail.eligible_attachments_page.next_offset,
  }), [detail]);
  const [browse, setBrowse] = useState<BrowseState>(initialBrowse);
  const [searchText, setSearchText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);

  // A new finding (or a reloaded detail) restarts from its linked files.
  useEffect(() => {
    generation.current += 1;
    setBrowse(initialBrowse);
    setSearchText("");
    setLoading(false);
    setError("");
  }, [initialBrowse]);

  const load = (scope: SubmissionAttachmentScope, query: string, offset: number) => {
    const current = ++generation.current;
    setLoading(true);
    setError("");
    void listSubmissionAttachments(engagementKey, slug, { scope, q: query, offset, limit: PAGE_SIZE })
      .then((page) => {
        if (current !== generation.current) return;
        onRows(page.attachments);
        setBrowse((previous) => {
          const rows = offset === 0 ? page.attachments : [
            ...previous.rows,
            ...page.attachments.filter((row) => !previous.rows.some((known) => known.id === row.id)),
          ];
          return {
            scope,
            query,
            rows,
            total: page.page.total,
            hasMore: page.page.has_more,
            nextOffset: page.page.next_offset,
          };
        });
      })
      .catch((cause: unknown) => {
        if (current === generation.current) {
          setError(cause instanceof Error ? cause.message : "Attachments could not be loaded");
        }
      })
      .finally(() => {
        if (current === generation.current) setLoading(false);
      });
  };

  // Debounced server search within the active scope.
  useEffect(() => {
    if (searchText === browse.query) return undefined;
    const timer = setTimeout(() => load(browse.scope, searchText, 0), 300);
    return () => clearTimeout(timer);
    // Only typing starts a search; scope switches and paging call load directly.
  }, [searchText]);

  const switchScope = (scope: SubmissionAttachmentScope) => {
    if (scope === browse.scope) return;
    if (scope === "finding" && !searchText) {
      generation.current += 1;
      setBrowse(initialBrowse);
      setLoading(false);
      return;
    }
    setBrowse((previous) => ({ ...previous, scope, rows: [], total: 0, hasMore: false, nextOffset: null }));
    load(scope, searchText, 0);
  };

  const triage = detail.blind_triage;
  const reviewedIds = triage.attachment_ids;
  const latest = detail.latest_version;
  const matchesReviewed = reviewedIds != null && sameIdSet(selection, reviewedIds);
  const matchesLatest = latest != null && sameIdSet(selection, latest.attachment_ids);
  const totalBytes = readiness && sameIdSet(readiness.attachment_ids, selection)
    ? readiness.attachment_total_bytes
    : selection.reduce((sum, id) => sum + (meta.get(id)?.size_bytes ?? 0), 0);
  const limitBytes = readiness?.attachment_limit_bytes ?? ATTACHMENT_LIMIT_BYTES;
  const overLimit = totalBytes > limitBytes;
  const selectedSet = new Set(selection);
  const groups = groupByFolder(browse.rows);

  return (
    <div className="subm-pkg">
      <div className="subm-pkg-summary" aria-live="polite">
        <div className="subm-pkg-total">
          <strong>
            {selection.length === 0
              ? "No attachments — exports the body as Markdown"
              : `${selection.length} attachment${selection.length === 1 ? "" : "s"} — exports a ZIP`}
          </strong>
          <span className={overLimit ? "is-over" : ""}>
            {formatBytes(totalBytes)} of {formatBytes(limitBytes)} limit
          </span>
          <div className="subm-meter" aria-hidden="true">
            <span style={{ width: `${Math.min(100, (totalBytes / limitBytes) * 100)}%` }} />
          </div>
        </div>
        {reviewedIds != null ? (
          matchesReviewed ? (
            <p className="subm-pkg-note is-ok">
              <CheckCircle2 size={14} aria-hidden="true" />
              <span>
                Reviewed by blind triage (packet <code>{shortHash(triage.packet_id)}</code>
                {triage.verdict ? `, ${triage.verdict}` : ""}). Every file is re-hashed at export.
              </span>
            </p>
          ) : (
            <p className={`subm-pkg-note ${triage.required ? "is-warn" : "is-info"}`}>
              <AlertTriangle size={14} aria-hidden="true" />
              <span>
                This selection differs from the {reviewedIds.length} file{reviewedIds.length === 1 ? "" : "s"} blind
                triage reviewed (packet <code>{shortHash(triage.packet_id)}</code>).
                {triage.required
                  ? " Export stays blocked until a new packet with this exact selection is accepted."
                  : " This finding's severity does not require blind triage."}
              </span>
            </p>
          )
        ) : (
          <p className="subm-pkg-note is-info">
            <Info size={14} aria-hidden="true" />
            <span>
              {triage.packet_id
                ? `The latest blind-triage packet's file list is unavailable: ${triage.manifest_error}`
                : triage.required
                  ? "No blind-triage verdict yet. The packet must review exactly the files selected here."
                  : "No blind-triage packet; this finding's severity does not require one."}
            </span>
          </p>
        )}
        <div className="subm-pkg-actions">
          {reviewedIds != null && !matchesReviewed && (
            <button type="button" className="qa-btn" disabled={disabled} onClick={() => onReplace(reviewedIds)}>
              Use reviewed set ({reviewedIds.length})
            </button>
          )}
          {latest && !matchesLatest && !(reviewedIds != null && sameIdSet(reviewedIds, latest.attachment_ids)) && (
            <button
              type="button"
              className="qa-btn"
              disabled={disabled}
              onClick={() => onReplace(latest.attachment_ids)}
            >
              Reuse attachments from v{latest.version_number} ({latest.attachment_ids.length})
            </button>
          )}
          {selection.length > 0 && reviewedIds?.length !== 0 && (
            <button type="button" className="qa-btn" disabled={disabled} onClick={() => onReplace([])}>
              Clear selection
            </button>
          )}
        </div>
      </div>

      {selection.length > 0 && (
        <section className="subm-pkg-section" aria-label="Selected attachments">
          <h4>Selected</h4>
          <ul className="subm-file-list">
            {selection.map((id) => {
              const row = meta.get(id);
              return (
                <li key={id}>
                  <label className="subm-file">
                    <input
                      type="checkbox"
                      checked
                      disabled={disabled}
                      onChange={() => onToggle(id)}
                      aria-label={`Remove ${row?.relative_path ?? `artifact ${id}`}`}
                    />
                    <span className="subm-file-name" title={row?.relative_path}>
                      {row ? basename(row.relative_path) : `Artifact #${id}`}
                    </span>
                    <span className="subm-file-path">{row ? dirname(row.relative_path) : "metadata not loaded"}</span>
                    <span className="subm-file-size">{row?.size_bytes != null ? formatBytes(row.size_bytes) : ""}</span>
                    {row?.internal && <StatusPill tone="warning" value="internal" label="Internal workspace file" size="sm" />}
                  </label>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <section className="subm-pkg-section" aria-label="Choose attachments">
        <div className="subm-pkg-browse-head">
          <SegmentedControl<SubmissionAttachmentScope>
            label="Attachment source"
            value={browse.scope}
            onChange={switchScope}
            options={[
              { value: "finding", label: `Linked to ${slug}`, count: detail.eligible_attachments_page.total },
              { value: "engagement", label: "All engagement files", count: detail.engagement_attachment_total },
            ]}
          />
          <input
            type="search"
            className="subm-input"
            value={searchText}
            placeholder={browse.scope === "finding" ? "Filter linked files by path…" : "Search every engagement file by path…"}
            aria-label="Search attachment paths"
            onChange={(event) => setSearchText(event.target.value)}
          />
        </div>
        <p className="subm-muted subm-pkg-count">
          {loading && browse.rows.length === 0
            ? "Loading files…"
            : `Showing ${browse.rows.length} of ${browse.total.toLocaleString()} ${
              browse.scope === "finding" ? "files linked to this finding" : "engagement files"
            }${browse.query ? ` matching “${browse.query}”` : ""}, newest first.`}
          {" "}Submission workspaces, blind-triage packets, replies, and version packages are never offered.
        </p>
        {error && <p className="subm-inline-error" role="alert">{error}</p>}
        {browse.rows.length === 0 && !loading ? (
          browse.query ? (
            <EmptyState
              variant="filtered"
              compact
              title={`No ${browse.scope === "finding" ? "linked" : "engagement"} files match “${browse.query}”.`}
              onClearFilters={() => setSearchText("")}
              clearLabel="Clear search"
            />
          ) : (
            <EmptyState variant="empty" compact title={browse.scope === "finding" ? "No registered files are linked to this finding." : "No engagement files are registered."}>
              {browse.scope === "finding" ? "Try All engagement files." : undefined}
            </EmptyState>
          )
        ) : (
          <div className={`subm-file-groups ${loading ? "is-reloading" : ""}`}>
            {groups.map(([folder, rows]) => (
              <div className="subm-file-group" key={folder}>
                <h5 title={folder}>{folder}</h5>
                <ul className="subm-file-list">
                  {rows.map((row) => (
                    <li key={row.id}>
                      <label className="subm-file">
                        <input
                          type="checkbox"
                          checked={selectedSet.has(row.id)}
                          disabled={disabled}
                          onChange={() => onToggle(row.id)}
                          aria-label={`Attach ${row.relative_path}`}
                        />
                        <span className="subm-file-name" title={row.relative_path}>{basename(row.relative_path)}</span>
                        <span className="subm-file-path">
                          #{row.id} · {row.kind}
                          {row.related_finding_slug && row.related_finding_slug !== slug
                            ? ` · linked to ${row.related_finding_slug}`
                            : ""}
                        </span>
                        <span className="subm-file-size">{formatBytes(row.size_bytes)}</span>
                        <SubmissionTime value={row.updated_at} className="subm-file-time" />
                      </label>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
        {browse.hasMore && browse.nextOffset != null && (
          <button
            type="button"
            className="pager-btn"
            disabled={loading}
            onClick={() => load(browse.scope, browse.query, browse.nextOffset ?? browse.rows.length)}
          >
            {loading ? "Loading files…" : `Load ${Math.min(PAGE_SIZE, browse.total - browse.rows.length)} more`}
          </button>
        )}
      </section>
    </div>
  );
}
