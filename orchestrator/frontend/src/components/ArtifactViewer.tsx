// ── ArtifactViewer ────────────────────────────────────────────────────
// Presentational Files view: the engagement's root documents grouped by role
// (working documents first, then snapshots and config), with a reading pane.
// FilesTab owns fetching and selection; this component only renders.
//
// Operator data renders verbatim (ADR 0019). File text can echo target
// output, so Markdown goes through MarkdownBlock (no raw HTML, inert images)
// and JSON through JsonView's text tokenizer (ADR 0018). "Raw" always shows
// the exact text the backend returned.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { EngagementFile, EngagementFileMeta } from "../lib/filesApi";
import { TimeStamp, formatBytes } from "./formatting";
import { JsonView } from "./JsonView";
import { MarkdownBlock } from "./Markdown";
import { Skeleton, SlowLoadHint } from "./Skeletons";
import { EmptyState, PageHeader, SegmentedControl, StatusPill } from "./ui";
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

type ArtifactViewerProps = {
  artifacts: ViewerFile[];
  selectedName: string | null;
  selectedArtifact: ViewerContent | null;
  // Failure reading the selected file.
  loadError?: string | null;
  // First list load still in flight (no list yet).
  listLoading?: boolean;
  // Failure loading the file list.
  listError?: string | null;
  // The selected file is being (re)read; previous content stays visible.
  contentLoading?: boolean;
  // A background re-read of the list or the open file (shown as "Updating…").
  refreshing?: boolean;
  // Why the file the URL named is not the one shown.
  routeNotice?: ReactNode;
  // Re-reads the list (and the open file) after a failure.
  onRetry?: () => void;
  onSelect: (name: string) => void;
};

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

function isJsonArtifact(artifact: ViewerContent) {
  return artifact.media_type.includes("json") || artifact.name.endsWith(".json");
}

function isJsonlArtifact(artifact: ViewerContent) {
  return artifact.name.endsWith(".jsonl");
}

function isMarkdownArtifact(artifact: ViewerContent) {
  return artifact.media_type.includes("markdown") || artifact.name.endsWith(".md");
}

function hasRenderedView(artifact: ViewerContent) {
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
      {/* The document's own "# Title" sits under the page's one level-1 heading. */}
      <MarkdownBlock text={text} headingOffset={1} />
    </div>
  );
}

function RenderedBody({ artifact }: { artifact: ViewerContent }) {
  if (isJsonlArtifact(artifact)) {
    return <JsonlContent content={artifact.content} truncated={Boolean(artifact.truncated)} />;
  }
  if (isJsonArtifact(artifact)) {
    try {
      return <JsonView value={JSON.parse(artifact.content)} />;
    } catch {
      return <RawText content={artifact.content} />;
    }
  }
  if (isMarkdownArtifact(artifact)) return <MarkdownContent content={artifact.content} />;
  return <RawText content={artifact.content} />;
}

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

function FileRow({ file, selected, onSelect }: { file: ViewerFile; selected: boolean; onSelect: (name: string) => void }) {
  const stubLabel = file.is_stub ? (file.stub_waiver?.trim() ? "Template · waived" : "Unfilled template") : null;
  return (
    <li>
      <button
        type="button"
        className="files-row"
        aria-pressed={selected}
        aria-current={selected ? "true" : undefined}
        onClick={() => onSelect(file.name)}
      >
        <span className="files-row-name">{file.name}</span>
        {file.role && <span className="files-row-role">{file.role}</span>}
        {file.relative_path !== file.name && <span className="files-row-path">{file.relative_path}</span>}
        <span className="files-row-meta">
          {file.size_bytes != null && <span>{formatBytes(file.size_bytes)}</span>}
          {file.modified_at && <TimeStamp value={file.modified_at} />}
        </span>
        {stubLabel && (
          <StatusPill
            className="files-flag"
            size="sm"
            value={file.stub_waiver?.trim() ? "waived" : "unfilled"}
            tone={file.stub_waiver?.trim() ? "neutral" : "warning"}
            label={stubLabel}
            title={file.stub_waiver?.trim() ? "An unfilled template the operator waived" : "Target-facing commands are blocked until this brief is filled in or waived"}
          />
        )}
      </button>
    </li>
  );
}

export function ArtifactViewer({
  artifacts,
  selectedName,
  selectedArtifact,
  loadError,
  listLoading = false,
  listError,
  contentLoading = false,
  refreshing = false,
  routeNotice,
  onRetry,
  onSelect,
}: ArtifactViewerProps) {
  const [view, setView] = useState<"rendered" | "raw">("rendered");
  // Each file opens rendered; Raw is a per-file choice.
  useEffect(() => setView("rendered"), [selectedName]);
  const displayedArtifact = selectedArtifact?.name === selectedName ? selectedArtifact : null;
  const selectedFile = artifacts.find((file) => file.name === selectedName) ?? null;
  const present = artifacts.filter((file) => file.exists);
  const missing = artifacts.filter((file) => !file.exists);
  const working = present.filter((file) => (file.group ?? "working") === "working");
  const snapshots = present.filter((file) => file.group === "snapshot");
  const hasBrief = present.some((file) => BRIEF_NAMES.has(file.name));
  const hasScope = present.some((file) => file.name === "scope.json");
  const waiting = Boolean(selectedName) && !displayedArtifact && !loadError;
  const meta: Partial<EngagementFileMeta> & { relative_path?: string } = { ...selectedFile, ...displayedArtifact };
  const renderable = displayedArtifact ? hasRenderedView(displayedArtifact) : false;
  const effectiveView = renderable ? view : "raw";

  return (
    <div className="files-page">
    <PageHeader
      title="Files"
      titleId="files-title"
      purpose="The engagement's working documents: the program brief, handoff notes, memory and snapshots. Start with the brief."
      stats={listLoading && artifacts.length === 0 ? [] : [
        { value: present.length, label: present.length === 1 ? "document" : "documents" },
        { value: missing.length || null, label: "not created yet" },
      ]}
      status={refreshing ? "Updating…" : null}
    />
    <section className="panel files-view" aria-labelledby="files-title">
      {listError && (
        <div className="files-list-error">
          <p className="error-text" role="alert">
            {artifacts.length ? `File list refresh failed: ${listError} (showing the last loaded list)` : `File list unavailable: ${listError}`}
          </p>
          {onRetry && <button type="button" className="ui-button" onClick={onRetry} disabled={refreshing}>Try again</button>}
        </div>
      )}
      {routeNotice && <div className="files-notice files-notice-warn" role="status">{routeNotice}</div>}
      {!listLoading && artifacts.length > 0 && !hasBrief && (
        <div className="files-notice" role="note">
          <strong>No program brief.</strong>{" "}
          {hasScope
            ? "This engagement has no ENGAGEMENT.md, so agents work from scope.json without program-specific rules of engagement."
            : "This engagement has no ENGAGEMENT.md and no scope.json, so agents have neither program-specific rules of engagement nor a recorded scope."}
        </div>
      )}
      <div className="files-layout">
        <nav className="files-list" aria-label="Engagement files">
          {listLoading && artifacts.length === 0 ? (
            <div className="files-list-skeleton" aria-hidden="true">
              {[0, 1, 2, 3].map((index) => <Skeleton key={index} height={44} />)}
            </div>
          ) : (
            <>
              {working.length > 0 && (
                <div className="files-group">
                  <h3 className="files-group-title">Working documents</h3>
                  <ul>
                    {working.map((file) => (
                      <FileRow key={file.name} file={file} selected={file.name === selectedName} onSelect={onSelect} />
                    ))}
                  </ul>
                </div>
              )}
              {snapshots.length > 0 && (
                <div className="files-group">
                  <h3 className="files-group-title">Snapshots &amp; config</h3>
                  <ul>
                    {snapshots.map((file) => (
                      <FileRow key={file.name} file={file} selected={file.name === selectedName} onSelect={onSelect} />
                    ))}
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
            </>
          )}
        </nav>
        <article
          className="files-viewer"
          aria-busy={contentLoading || waiting}
          aria-label={selectedName ? `${selectedName} contents` : "File contents"}
        >
          {selectedName && (
            <header className="files-viewer-head">
              <div className="files-viewer-title">
                <strong>{selectedName}</strong>
                {meta.role && <span className="files-row-role">{meta.role}</span>}
                {renderable && (
                  <SegmentedControl
                    className="files-view-switch"
                    label="File view"
                    value={effectiveView}
                    onChange={setView}
                    options={[{ value: "rendered", label: "Rendered" }, { value: "raw", label: "Raw" }]}
                  />
                )}
              </div>
              {meta.description && <p className="files-viewer-desc">{meta.description}</p>}
              <p className="files-viewer-meta">
                {meta.relative_path && meta.relative_path !== selectedName && <span className="mono">{meta.relative_path}</span>}
                {meta.size_bytes != null && <span>{formatBytes(meta.size_bytes)}</span>}
                {meta.modified_at && <span>Modified <TimeStamp value={meta.modified_at} mode="both" /></span>}
              </p>
            </header>
          )}
          {loadError && (
            <p className="error-text" role="alert">
              {displayedArtifact
                ? `Showing last available content for ${selectedName}. Refresh failed: ${loadError}`
                : `${selectedName} unavailable: ${loadError}`}
            </p>
          )}
          {displayedArtifact ? (
            <>
              {displayedArtifact.is_stub && <StubNotice waiver={displayedArtifact.stub_waiver ?? ""} />}
              {displayedArtifact.truncated && (
                <div className="files-notice" role="note">
                  <strong>Showing the first {formatBytes(displayedArtifact.returned_bytes)} of {formatBytes(displayedArtifact.size_bytes)}.</strong>{" "}
                  Open {displayedArtifact.relative_path} in the engagement directory for the rest.
                </div>
              )}
              <div className="files-body">
                {effectiveView === "raw" ? <RawText content={displayedArtifact.content} /> : <RenderedBody artifact={displayedArtifact} />}
              </div>
            </>
          ) : waiting ? (
            <>
              <div className="files-body-skeleton" role="status" aria-label={`Loading ${selectedName}`}>
                <Skeleton height={18} width="40%" />
                <Skeleton height={12} />
                <Skeleton height={12} />
                <Skeleton height={12} width="85%" />
                <Skeleton height={12} width="70%" />
              </div>
              <SlowLoadHint active what={selectedName ?? "the file"} />
            </>
          ) : !loadError && !listLoading ? (
            present.length ? (
              <p className="meta-text files-pick" role="status">Select a file to read it.</p>
            ) : (
              <EmptyState variant="empty" compact title="No engagement files exist yet.">
                The brief, handoff notes and memory documents appear here once the engagement writes them.
              </EmptyState>
            )
          ) : null}
        </article>
      </div>
    </section>
    </div>
  );
}
