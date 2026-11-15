// ── ArtifactViewer ────────────────────────────────────────────────────
// Presentational pieces of the Files tab: the list of the engagement's root
// documents grouped by role (working documents first, then snapshots and
// config), and one file's record (header, Rendered / Raw sections, body) for
// the shared record view. FilesTab owns fetching, the open file and the
// address; these components only render.
//
// Operator data renders verbatim (ADR 0019). File text can echo target
// output, so Markdown goes through MarkdownBlock (no raw HTML, inert images)
// and JSON through JsonView's text tokenizer (ADR 0018). "Raw" always shows
// the exact text the backend returned.

import { memo, useEffect, useMemo, useState, type ReactNode } from "react";
import type { EngagementFile, EngagementFileMeta } from "../lib/filesApi";
import { TimeStamp, formatBytes } from "./formatting";
import { JsonView } from "./JsonView";
import { MarkdownBlock } from "./Markdown";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs, type RecordTab } from "./record/RecordView";
import { Skeleton, SlowLoadHint } from "./Skeletons";
import { EmptyState, StatusPill } from "./ui";
import "../styles/files.css";

// The role metadata is optional so a file renders even when the listing
// omits it (it then groups as a working document).
type FileIdentity = Pick<EngagementFile, "name" | "relative_path" | "media_type" | "exists">;
export type ViewerFile = FileIdentity & Partial<EngagementFileMeta>;
export type ViewerContent = ViewerFile & {
  content: string;
  truncated?: boolean;
  returned_bytes?: number;
};

/** A file record's sections: the rendered document, or the exact text. */
export type FileSection = "rendered" | "raw";

export function isFileSection(value: string | undefined): value is FileSection {
  return value === "rendered" || value === "raw";
}

const JSONL_PAGE_ROWS = 100;
const BRIEF_NAMES = new Set(["ENGAGEMENT.md", "RULES.md"]);

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function summarizeJsonValue(value: JsonValue) {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  if (value && typeof value === "object") return `${Object.keys(value).length} field${Object.keys(value).length === 1 ? "" : "s"}`;
  if (typeof value === "string") return value;
  return String(value);
}

// Collapsible JSON tree shared with the Findings and Intel drawers.
export function JsonTree({ label, value, defaultOpen = false }: { label?: string; value: JsonValue; defaultOpen?: boolean }) {
  if (Array.isArray(value)) {
    return (
      <details className="json-node" open={defaultOpen}>
        <summary>
          {label ? <span className="json-key">{label}</span> : "Array"} <span className="json-meta">{summarizeJsonValue(value)}</span>
        </summary>
        <div className="json-children">
          {value.map((item, index) => (
            <JsonTree key={index} label={`[${index}]`} value={item} />
          ))}
        </div>
      </details>
    );
  }

  if (value && typeof value === "object") {
    return (
      <details className="json-node" open={defaultOpen}>
        <summary>
          {label ? <span className="json-key">{label}</span> : "Object"} <span className="json-meta">{summarizeJsonValue(value)}</span>
        </summary>
        <div className="json-children">
          {Object.entries(value).map(([key, item]) => (
            <JsonTree key={key} label={key} value={item} />
          ))}
        </div>
      </details>
    );
  }

  return (
    <div className="json-leaf">
      {label && <span className="json-key">{label}</span>}
      <span className={`json-value json-value-${value === null ? "null" : typeof value}`}>{String(value)}</span>
    </div>
  );
}

/** What decides how a file renders: its name and media type, known from the list before its text arrives. */
type FileShape = Pick<ViewerFile, "name" | "media_type">;

function isJsonArtifact(artifact: FileShape) {
  return artifact.media_type.includes("json") || artifact.name.endsWith(".json");
}

function isJsonlArtifact(artifact: FileShape) {
  return artifact.name.endsWith(".jsonl");
}

function isMarkdownArtifact(artifact: FileShape) {
  return artifact.media_type.includes("markdown") || artifact.name.endsWith(".md");
}

function hasRenderedView(artifact: FileShape) {
  return isJsonlArtifact(artifact) || isJsonArtifact(artifact) || isMarkdownArtifact(artifact);
}

const FENCE = /^ {0,3}(`{3,}|~{3,})/;
const HTML_COMMENT = /<!--[\s\S]*?-->/g;

/** Markdown text split into runs of fenced code and prose, in order. */
function fencedChunks(text: string): Array<{ code: boolean; lines: string[] }> {
  const chunks: Array<{ code: boolean; lines: string[] }> = [];
  let fence: string | null = null;
  for (const line of text.split("\n")) {
    const marker = FENCE.exec(line)?.[1];
    const code = fence !== null || Boolean(marker);
    if (!chunks.length || chunks[chunks.length - 1].code !== code) chunks.push({ code, lines: [] });
    chunks[chunks.length - 1].lines.push(line);
    if (marker && fence === null) fence = marker;
    else if (marker && fence !== null && marker[0] === fence[0] && marker.length >= fence.length) fence = null;
  }
  return chunks;
}

/**
 * Markdown text with its HTML comments removed outside fenced code, for the
 * rendered view (template guidance in a stub brief is not content). Raw keeps
 * the exact bytes. Returns how many comments were hidden.
 */
export function stripHtmlComments(text: string): { text: string; hidden: number } {
  const chunks = fencedChunks(text);
  let hidden = 0;
  const out = chunks.map((chunk) => {
    const joined = chunk.lines.join("\n");
    if (chunk.code) return joined;
    return joined.replace(HTML_COMMENT, () => {
      hidden += 1;
      return "";
    });
  });
  return { text: out.join("\n"), hidden };
}

function RawText({ content }: { content: string }) {
  return <pre className="files-raw">{content}</pre>;
}

function JsonlContent({ content, truncated }: { content: string; truncated: boolean }) {
  const rows = useMemo(() => content.split("\n").filter((line) => line.trim().length > 0), [content]);
  const [visible, setVisible] = useState(JSONL_PAGE_ROWS);
  useEffect(() => setVisible(JSONL_PAGE_ROWS), [content]);
  return (
    <div className="files-jsonl">
      <p className="meta-text">
        {rows.length.toLocaleString()} record{rows.length === 1 ? "" : "s"}
        {truncated ? " in the loaded part" : ""} · showing {Math.min(visible, rows.length).toLocaleString()}
      </p>
      {rows.slice(0, visible).map((line, index) => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          // A truncated read can end mid-record; show the line as-is.
          return <RawText key={index} content={line} />;
        }
        return (
          <details key={index} className="files-jsonl-row" open={index < 3}>
            <summary>Record {index + 1}</summary>
            <JsonView value={parsed} copyable={false} gutterThreshold={Infinity} />
          </details>
        );
      })}
      {visible < rows.length && (
        <button type="button" className="ghost-button files-more" onClick={() => setVisible((n) => n + JSONL_PAGE_ROWS)}>
          Show {Math.min(JSONL_PAGE_ROWS, rows.length - visible).toLocaleString()} more of {(rows.length - visible).toLocaleString()} remaining
        </button>
      )}
    </div>
  );
}

function MarkdownContent({ content }: { content: string }) {
  const { text, hidden } = useMemo(() => stripHtmlComments(content), [content]);
  return (
    <div className="files-markdown">
      {hidden > 0 && (
        <p className="meta-text files-hidden-note">
          {hidden} HTML comment{hidden === 1 ? "" : "s"} hidden; Raw shows the exact file.
        </p>
      )}
      {/* The document's own "# Title" sits under the record's level-2 title. */}
      <MarkdownBlock text={text} headingOffset={2} />
    </div>
  );
}

/** A JSON document's parsed value; null when its text does not parse. */
type ParsedJson = { value: unknown } | null;

function parseJsonArtifact(artifact: ViewerContent): ParsedJson {
  try {
    return { value: JSON.parse(artifact.content) };
  } catch {
    // A read cut at the view limit, or a damaged file.
    return null;
  }
}

// Rendering a large document is the costly part of this view, so it happens
// once per content: the record's other updates (loading states, a refresh
// that read the same text) leave it alone.
const RenderedBody = memo(function RenderedBody({ artifact, json }: { artifact: ViewerContent; json: ParsedJson }) {
  if (isJsonlArtifact(artifact)) {
    return <JsonlContent content={artifact.content} truncated={Boolean(artifact.truncated)} />;
  }
  if (json) return <JsonView value={json.value} />;
  if (isMarkdownArtifact(artifact)) return <MarkdownContent content={artifact.content} />;
  return <RawText content={artifact.content} />;
});

function StubNotice({ waiver }: { waiver: string }) {
  if (waiver.trim()) {
    return (
      <div className="files-notice" role="note">
        <strong>Unfilled template, waived by the operator.</strong>{" "}
        The operator recorded that this engagement has no separate program brief: <q>{waiver}</q>
      </div>
    );
  }
  return (
    <div className="files-notice files-notice-warn" role="note">
      <strong>Unfilled template.</strong>{" "}
      Target-facing commands are blocked until this brief holds the program&apos;s rules, or the operator
      records that the engagement has no separate program brief.
    </div>
  );
}

function stubPill(file: Pick<ViewerFile, "is_stub" | "stub_waiver">, className?: string) {
  if (!file.is_stub) return null;
  const waived = Boolean(file.stub_waiver?.trim());
  return (
    <StatusPill
      className={className}
      size="sm"
      value={waived ? "waived" : "unfilled"}
      tone={waived ? "neutral" : "warning"}
      label={waived ? "Template · waived" : "Unfilled template"}
      title={waived ? "An unfilled template the operator waived" : "Target-facing commands are blocked until this brief is filled in or waived"}
    />
  );
}

function FileRow({ file, onOpen }: { file: ViewerFile; onOpen: (name: string, invoker: HTMLElement) => void }) {
  return (
    <li>
      <button
        type="button"
        className="files-row"
        data-record-key={file.name}
        onClick={(event) => onOpen(file.name, event.currentTarget)}
      >
        <span className="files-row-main">
          <span className="files-row-name">{file.name}</span>
          {file.relative_path !== file.name && <span className="files-row-path">{file.relative_path}</span>}
          {stubPill(file, "files-flag")}
        </span>
        <span className="files-row-about">
          {file.role && <span className="files-row-role">{file.role}</span>}
          {file.description && <span className="files-row-desc">{file.description}</span>}
        </span>
        <span className="files-row-meta">
          {file.size_bytes != null && <span>{formatBytes(file.size_bytes)}</span>}
          {file.modified_at && <TimeStamp value={file.modified_at} />}
        </span>
      </button>
    </li>
  );
}

/** The files a record's Previous / Next walk, in the order the list shows them: working documents, then snapshots and config. */
export function shownFileOrder(files: ViewerFile[]): string[] {
  const present = files.filter((file) => file.exists);
  return [
    ...present.filter((file) => (file.group ?? "working") === "working"),
    ...present.filter((file) => file.group === "snapshot"),
  ].map((file) => file.name);
}

type FileListProps = {
  files: ViewerFile[];
  /** Id of the page heading that names this list. */
  labelledBy?: string;
  // First list load still in flight (no list yet).
  loading?: boolean;
  // Failure loading the file list.
  error?: string | null;
  // A background re-read of the list is running.
  refreshing?: boolean;
  // Why the file the address named is not open.
  notice?: ReactNode;
  // Re-reads the list after a failure.
  onRetry?: () => void;
  /** Open a file's record; `invoker` is the row used, where focus returns. */
  onOpen: (name: string, invoker: HTMLElement) => void;
};

/** The tab's results: every engagement file, grouped by role, the brief first. */
export function FileList({ files, labelledBy, loading = false, error, refreshing = false, notice, onRetry, onOpen }: FileListProps) {
  const present = files.filter((file) => file.exists);
  const missing = files.filter((file) => !file.exists);
  const working = present.filter((file) => (file.group ?? "working") === "working");
  const snapshots = present.filter((file) => file.group === "snapshot");
  const hasBrief = present.some((file) => BRIEF_NAMES.has(file.name));
  const hasScope = present.some((file) => file.name === "scope.json");
  return (
    <section className="panel files-view" aria-labelledby={labelledBy}>
      {error && (
        <div className="files-list-error">
          <p className="error-text" role="alert">
            {files.length ? `File list refresh failed: ${error} (showing the last loaded list)` : `File list unavailable: ${error}`}
          </p>
          {onRetry && <button type="button" className="ui-button" onClick={onRetry} disabled={refreshing}>Try again</button>}
        </div>
      )}
      {notice && <div className="files-notice files-notice-warn" role="status">{notice}</div>}
      {!loading && files.length > 0 && !hasBrief && (
        <div className="files-notice" role="note">
          <strong>No program brief.</strong>{" "}
          {hasScope
            ? "This engagement has no ENGAGEMENT.md, so agents work from scope.json without program-specific rules of engagement."
            : "This engagement has no ENGAGEMENT.md and no scope.json, so agents have neither program-specific rules of engagement nor a recorded scope."}
        </div>
      )}
      <nav className="files-list" aria-label="Engagement files">
        {loading && files.length === 0 ? (
          <div className="files-list-skeleton" aria-hidden="true">
            {[0, 1, 2, 3].map((index) => <Skeleton key={index} height={44} />)}
          </div>
        ) : (
          <>
            {working.length > 0 && (
              <div className="files-group">
                <h3 className="files-group-title">Working documents</h3>
                <ul>
                  {working.map((file) => <FileRow key={file.name} file={file} onOpen={onOpen} />)}
                </ul>
              </div>
            )}
            {snapshots.length > 0 && (
              <div className="files-group">
                <h3 className="files-group-title">Snapshots &amp; config</h3>
                <ul>
                  {snapshots.map((file) => <FileRow key={file.name} file={file} onOpen={onOpen} />)}
                </ul>
              </div>
            )}
            {missing.length > 0 && (
              <details className="files-missing">
                <summary>Not created yet ({missing.length})</summary>
                <ul>
                  {missing.map((file) => (
                    <li key={file.name}>
                      <span className="files-row-name">{file.name}</span>
                      {file.role && <span className="files-row-role">{file.role}</span>}
                      {file.description && <span className="files-missing-desc">{file.description}</span>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {!loading && !error && present.length === 0 && (
              <EmptyState variant="empty" compact title="No engagement files exist yet.">
                The brief, handoff notes and memory documents appear here once the engagement writes them.
              </EmptyState>
            )}
          </>
        )}
      </nav>
    </section>
  );
}

type FileRecordProps = {
  /** The open file's name; the record shows its loading shape until `content` is this file's. */
  name: string;
  /** The file's entry in the list, once the list is known. */
  file: ViewerFile | null;
  /** The text last read; ignored while it belongs to another file. */
  content: ViewerContent | null;
  // Failure reading the file.
  loadError?: string | null;
  // The file is being (re)read; previous content stays visible.
  loading?: boolean;
  section: FileSection;
  onSectionChange: (next: FileSection) => void;
  // Reads the file again after a failure.
  onRetry?: () => void;
  /** Id for the record heading (RecordView focuses it on open). */
  titleId: string;
};

/** One file inside the shared RecordView (FilesTab owns the view, the list and the address). */
export function FileRecord({ name, file, content, loadError, loading = false, section, onSectionChange, onRetry, titleId }: FileRecordProps) {
  const displayed = content?.name === name ? content : null;
  const waiting = !displayed && !loadError;
  const meta: Partial<EngagementFileMeta> & { relative_path?: string } = { ...file, ...displayed };
  const known = Boolean(file || displayed);
  const shape: FileShape = { name, media_type: displayed?.media_type ?? file?.media_type ?? "" };
  const json = useMemo<ParsedJson>(
    () => (displayed && isJsonArtifact(displayed) && !isJsonlArtifact(displayed) ? parseJsonArtifact(displayed) : null),
    [displayed],
  );
  // A JSON file whose text does not parse has no rendered view: it shows as its exact text.
  const unparsedJson = Boolean(displayed) && isJsonArtifact(displayed!) && !isJsonlArtifact(displayed!) && json === null;
  const renderable = hasRenderedView(shape) && !unparsedJson;
  const shown: FileSection = renderable ? section : "raw";
  const path = meta.relative_path ?? name;
  const tabs: RecordTab<FileSection>[] = [
    { id: "rendered", label: "Rendered", hidden: !renderable },
    { id: "raw", label: "Raw" },
  ];

  return (
    <>
      <RecordHeader
        id={
          <>
            {!known ? "Engagement file" : meta.group === "snapshot" ? "Snapshot or config file" : "Working document"}
            {path !== name && <> · <span className="mono">{path}</span></>}
          </>
        }
        copyId={path}
        copyIdLabel="Copy path"
        title={name}
        titleId={titleId}
        actions={<RecordCopyLinkButton noun="file" />}
        pills={known ? (
          <>
            {meta.role && <span className="tag">{meta.role}</span>}
            {stubPill(meta)}
            {meta.size_bytes != null && <span className="record-pill-reason">{formatBytes(meta.size_bytes)}</span>}
          </>
        ) : undefined}
        dates={known ? [{ label: "Modified", value: meta.modified_at }] : undefined}
        datesLabel="File dates"
      >
        {meta.description && <p className="files-record-desc">{meta.description}</p>}
        {displayed?.is_stub && <StubNotice waiver={displayed.stub_waiver ?? ""} />}
        {displayed?.truncated && (
          <div className="files-notice" role="note">
            <strong>Showing the first {formatBytes(displayed.returned_bytes)} of {formatBytes(displayed.size_bytes)}.</strong>{" "}
            Open {displayed.relative_path} in the engagement directory for the rest.
          </div>
        )}
        {unparsedJson && displayed && (
          <div className="files-notice" role="note">
            <strong>No rendered view.</strong>{" "}
            This file's text does not parse as JSON{displayed.truncated ? " (the read stops partway through it)" : ""}, so it is shown exactly as stored.
          </div>
        )}
      </RecordHeader>
      <RecordTabs tabs={tabs} active={shown} onChange={onSectionChange} label="File sections" />
      <RecordBody>
        <article className="files-document" aria-busy={loading || waiting} aria-label={`${name} contents`}>
          {loadError && (
            <div className="files-list-error">
              <p className="error-text" role="alert">
                {displayed
                  ? `Showing last available content for ${name}. Refresh failed: ${loadError}`
                  : `${name} unavailable: ${loadError}`}
              </p>
              {onRetry && <button type="button" className="ui-button" onClick={onRetry} disabled={loading}>Try again</button>}
            </div>
          )}
          {displayed ? (
            <div className="files-body">
              {shown === "raw" ? <RawText content={displayed.content} /> : <RenderedBody artifact={displayed} json={json} />}
            </div>
          ) : waiting ? (
            <>
              <div className="files-body-skeleton" role="status" aria-label={`Loading ${name}`}>
                <Skeleton height={18} width="40%" />
                <Skeleton height={12} />
                <Skeleton height={12} />
                <Skeleton height={12} width="85%" />
                <Skeleton height={12} width="70%" />
              </div>
              <SlowLoadHint active what={name} />
            </>
          ) : null}
        </article>
      </RecordBody>
    </>
  );
}
