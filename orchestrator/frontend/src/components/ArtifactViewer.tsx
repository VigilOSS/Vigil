import type { ReactNode } from "react";
import type { Artifact, ArtifactContent } from "../lib/api";
import { UntrustedDataNotice } from "./drawer/DrawerKit";

type ArtifactViewerProps = {
  artifacts: Artifact[];
  selectedName: string | null;
  selectedArtifact: ArtifactContent | null;
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

function renderInlineMarkdown(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return <code key={index}>{part.slice(1, -1)}</code>;
    }
    return part;
  });
}

function MarkdownContent({ content }: { content: string }) {
  const lines = content.split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    if (!line.trim()) {
      index += 1;
      continue;
    }

    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      index += 1;
      blocks.push(<pre key={blocks.length} className="artifact-code-block">{codeLines.join("\n")}</pre>);
      continue;
    }

    if (/^#{1,6}\s+/.test(line)) {
      const depth = line.match(/^#+/)?.[0].length ?? 1;
      const text = line.replace(/^#{1,6}\s+/, "");
      if (depth === 1) blocks.push(<h1 key={blocks.length}>{text}</h1>);
      else if (depth === 2) blocks.push(<h2 key={blocks.length}>{text}</h2>);
      else if (depth === 3) blocks.push(<h3 key={blocks.length}>{text}</h3>);
      else blocks.push(<p key={blocks.length} className="artifact-subheading">{text}</p>);
      index += 1;
      continue;
    }

    if (line.trim() === "---") {
      blocks.push(<hr key={blocks.length} className="artifact-rule" />);
      index += 1;
      continue;
    }

    if (line.includes("|") && index + 1 < lines.length && /^[:|\-\s]+$/.test(lines[index + 1].trim())) {
      const header = line.split("|").map((cell) => cell.trim()).filter(Boolean);
      const rows: string[][] = [];
      index += 2;
      while (index < lines.length && lines[index].includes("|")) {
        rows.push(lines[index].split("|").map((cell) => cell.trim()).filter(Boolean));
        index += 1;
      }
      blocks.push(
        <div key={blocks.length} className="artifact-table-wrap">
          <table className="artifact-table">
            <thead>
              <tr>
                {header.map((cell, cellIndex) => (
                  <th key={cellIndex}>{renderInlineMarkdown(cell)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={rowIndex}>
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex}>{renderInlineMarkdown(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^[-*]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^[-*]\s+/, ""));
        index += 1;
      }
      blocks.push(
        <ul key={blocks.length} className="artifact-list-block">
          {items.map((item, itemIndex) => (
            <li key={itemIndex}>{renderInlineMarkdown(item)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^\d+\.\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\d+\.\s+/, ""));
        index += 1;
      }
      blocks.push(
        <ol key={blocks.length} className="artifact-list-block">
          {items.map((item, itemIndex) => (
            <li key={itemIndex}>{renderInlineMarkdown(item)}</li>
          ))}
        </ol>,
      );
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length && lines[index].trim() && !/^#{1,6}\s+/.test(lines[index]) && !/^[-*]\s+/.test(lines[index]) && !/^\d+\.\s+/.test(lines[index]) && !lines[index].startsWith("```")) {
      paragraph.push(lines[index]);
      index += 1;
    }

    blocks.push(
      <p key={blocks.length}>
        {renderInlineMarkdown(paragraph.join(" "))}
      </p>,
    );
  }

  return <div className="artifact-markdown">{blocks}</div>;
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
  onSelect,
}: ArtifactViewerProps) {
  return (
    <section className="panel artifact-panel">
      <div className="panel-header">
        <h2>Artifacts</h2>
        <p className="meta-text">Documents and engagement outputs</p>
      </div>
      <div className="artifact-layout">
        <aside className="artifact-list">
          {artifacts.map((artifact) => (
            <button
              key={artifact.name}
              type="button"
              className={`artifact-row ${selectedName === artifact.name ? "artifact-active" : ""}`}
              disabled={!artifact.exists}
              onClick={() => onSelect(artifact.name)}
            >
              <div>
                <strong>{artifact.name}</strong>
                <p className="meta-text">{artifact.relative_path}</p>
              </div>
              <div className="artifact-tags">
                <span className="badge">{artifact.exists ? "Available" : "Missing"}</span>
              </div>
            </button>
          ))}
        </aside>
        <article className="artifact-content">
          {selectedArtifact ? (
            <>
              <div className="artifact-content-header">
                <strong>{selectedArtifact.name}</strong>
                <span className="meta-text">{selectedArtifact.media_type}</span>
              </div>
              <UntrustedDataNotice />
              <ArtifactBody artifact={selectedArtifact} />
            </>
          ) : (
            <p className="empty-state">Select an available artifact to inspect it.</p>
          )}
        </article>
      </div>
    </section>
  );
}
