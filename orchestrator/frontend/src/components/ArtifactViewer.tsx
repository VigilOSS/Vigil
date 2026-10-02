import { useState } from "react";
import type { Artifact, ArtifactContent } from "../lib/api";
import { MarkdownBlock } from "./Markdown";

type ArtifactViewerProps = {
  artifacts: Artifact[];
  selectedName: string | null;
  selectedArtifact: ArtifactContent | null;
  loadError?: string | null;
  onSelect: (name: string) => void;
};

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function isJsonArtifact(artifact: ArtifactContent) {
  return artifact.media_type.includes("json") || artifact.name.endsWith(".json");
}

function isJsonlArtifact(artifact: ArtifactContent) {
  return artifact.name.endsWith(".jsonl");
}

function isMarkdownArtifact(artifact: ArtifactContent) {
  return artifact.media_type.includes("markdown") || artifact.name.endsWith(".md");
}

function summarizeJsonValue(value: JsonValue) {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  if (value && typeof value === "object") return `${Object.keys(value).length} field${Object.keys(value).length === 1 ? "" : "s"}`;
  if (typeof value === "string") return value;
  return String(value);
}

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

function MarkdownContent({ content }: { content: string }) {
  return <div className="artifact-markdown"><MarkdownBlock text={content} /></div>;
}

function JsonlContent({ content }: { content: string }) {
  const rows = content.split("\n").filter((line) => line.trim().length > 0);
  return (
    <div className="artifact-jsonl">
      {rows.map((line, index) => {
        try {
          const parsed = JSON.parse(line) as JsonValue;
          return (
            <details key={index} className="artifact-jsonl-row" open={index < 3}>
              <summary>Row {index + 1}</summary>
              <JsonTree value={parsed} defaultOpen />
            </details>
          );
        } catch {
          return <pre key={index} className="artifact-code-block">{line}</pre>;
        }
      })}
    </div>
  );
}

function ArtifactBody({ artifact }: { artifact: ArtifactContent }) {
  if (isJsonlArtifact(artifact)) {
    return <JsonlContent content={artifact.content} />;
  }

  if (isJsonArtifact(artifact)) {
    try {
      const parsed = JSON.parse(artifact.content) as JsonValue;
      return <JsonTree value={parsed} defaultOpen />;
    } catch {
      return <pre>{artifact.content}</pre>;
    }
  }

  if (isMarkdownArtifact(artifact)) {
    return <MarkdownContent content={artifact.content} />;
  }

  return <pre>{artifact.content}</pre>;
}

export function ArtifactViewer({
  artifacts,
  selectedName,
  selectedArtifact,
  loadError,
  onSelect,
}: ArtifactViewerProps) {
  const [view, setView] = useState<"rendered" | "raw">("rendered");
  const displayedArtifact = selectedArtifact?.name === selectedName ? selectedArtifact : null;
  return (
    <section className="panel artifact-panel">
      <div className="panel-header">
        <h2>Engagement files</h2>
        <p className="meta-text">Root working documents; indexed evidence lives in the artifact ledger</p>
      </div>
      <div className="artifact-layout">
        <aside className="artifact-list" aria-label="Engagement files">
          {artifacts.map((artifact) => (
            <button
              key={artifact.name}
              type="button"
              className={`artifact-row ${selectedName === artifact.name ? "artifact-active" : ""}`}
              disabled={!artifact.exists}
              aria-pressed={selectedName === artifact.name}
              onClick={() => onSelect(artifact.name)}
            >
              <div>
                <strong>{artifact.name}</strong>
                {artifact.relative_path !== artifact.name && <p className="meta-text">{artifact.relative_path}</p>}
              </div>
              <div className="artifact-tags">
                <span className="badge">{artifact.exists ? "Available" : "Missing"}</span>
              </div>
            </button>
          ))}
        </aside>
        <article className="artifact-content">
          {loadError && <p className="error-text" role="alert">{displayedArtifact ? `Showing last available content for ${selectedName}. Refresh failed: ${loadError}` : `${selectedName} unavailable: ${loadError}`}</p>}
          {displayedArtifact ? (
            <>
              <div className="artifact-content-header">
                <strong>{displayedArtifact.name}</strong>
                <span className="meta-text">{displayedArtifact.media_type}</span>
                <div className="artifact-view-switch" role="group" aria-label="File view">
                  <button type="button" aria-pressed={view === "rendered"} onClick={() => setView("rendered")}>Rendered</button>
                  <button type="button" aria-pressed={view === "raw"} onClick={() => setView("raw")}>Raw</button>
                </div>
              </div>
              {view === "raw" ? <pre>{displayedArtifact.content}</pre> : <ArtifactBody artifact={displayedArtifact} />}
            </>
          ) : !loadError ? (
            <p className="empty-state" role="status">{selectedName ? `Loading ${selectedName}…` : "Select an available artifact to inspect it."}</p>
          ) : null}
        </article>
      </div>
    </section>
  );
}
