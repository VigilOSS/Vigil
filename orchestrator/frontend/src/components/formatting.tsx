// Shared presentational helpers for Notes, Provenance, and PoC sections
// across the Intel + Findings drawers (Issue 4). Centralized here because
// the contracts are identical: a notes blob that deserves paragraphs +
// inline code + auto-linked URLs, a provenance object with a canonical
// four-field shape, and a copy-to-clipboard affordance for mono refs.

import { useState, type ReactNode } from "react";

// ── Relative time helpers ─────────────────────────────────────────────

/**
 * Compact relative time ("3h ago"). Both tabs had near-identical copies
 * of this; extract the shared version so behavior stays consistent.
 */
export function relTime(iso: string | undefined | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const diffSec = Math.max(0, Math.round((now.getTime() - d.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const min = Math.round(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.round(min / 60);
  if (h < 24) return `${h}h ago`;
  const day = Math.round(h / 24);
  if (day < 7) return `${day}d ago`;
  return d.toISOString().slice(0, 10);
}

/** Full ISO for the title-attribute tooltip on a relative-time span. */
export function absTime(iso: string | undefined | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace("Z", " UTC");
}

export function RelTime({ iso }: { iso: string | undefined | null }) {
  const rel = relTime(iso);
  if (!rel) return null;
  return (
    <span className="rel-time" title={absTime(iso)}>
      {rel}
    </span>
  );
}

// ── Copy-to-clipboard ─────────────────────────────────────────────────

export function CopyInline({
  text,
  children,
  ariaLabel,
}: {
  text: string;
  children?: ReactNode;
  ariaLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  const onCopy = () => {
    try {
      void navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      /* best-effort */
    }
  };
  return (
    <button
      type="button"
      className={`copy-inline ${copied ? "is-copied" : ""}`}
      onClick={onCopy}
      aria-label={ariaLabel ?? "Copy to clipboard"}
    >
      {copied ? "Copied" : children ?? "Copy"}
    </button>
  );
}

// ── Notes body ────────────────────────────────────────────────────────
//
// Markdown-lite: `\n\n` splits paragraphs; inline `code`, **bold**, and
// bare URLs get rendered. A full markdown parser would be overkill here
// and also pulls in chroma. The callers (Intel notes, Findings notes)
// only ever store a note body — no tables, no headings deeper than h3,
// no lists — so this scope matches the data.

const URL_RE = /\bhttps?:\/\/[^\s<>()"]+/g;

function renderInlineSegment(text: string, key: string): ReactNode {
  // Tokenize on `code` spans, then on **bold**, then auto-link URLs.
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  const out: ReactNode[] = [];
  for (let i = 0; i < parts.length; i += 1) {
    const p = parts[i];
    if (p.startsWith("`") && p.endsWith("`")) {
      out.push(<code key={`${key}-c-${i}`}>{p.slice(1, -1)}</code>);
      continue;
    }
    if (p.startsWith("**") && p.endsWith("**")) {
      out.push(<strong key={`${key}-b-${i}`}>{p.slice(2, -2)}</strong>);
      continue;
    }
    // Auto-link URLs inside plain text.
    let last = 0;
    URL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = URL_RE.exec(p)) !== null) {
      if (m.index > last) out.push(p.slice(last, m.index));
      out.push(
        <a
          key={`${key}-u-${i}-${m.index}`}
          href={m[0]}
          target="_blank"
          rel="noopener noreferrer"
        >
          {m[0]}
        </a>,
      );
      last = m.index + m[0].length;
    }
    if (last < p.length) out.push(p.slice(last));
  }
  return out;
}

/**
 * Render free-form notes as paragraphs. `\n\n` (or any sequence of blank
 * lines) splits paragraphs; single newlines within a paragraph are
 * preserved via <br>. Leading `# `/`## `/`### ` on a line becomes an h3
 * so longer structured notes render with visible hierarchy. A bare URL
 * auto-links; inline `code` and **bold** survive the round-trip.
 */
export function NotesBody({ text }: { text: string }) {
  if (!text || !text.trim()) return null;
  const paragraphs = text.replace(/\r\n/g, "\n").split(/\n\s*\n/);
  return (
    <div className="notes-body">
      {paragraphs.map((para, pIdx) => {
        const trimmed = para.trim();
        if (!trimmed) return null;
        if (/^#{1,6}\s+/.test(trimmed)) {
          const heading = trimmed.replace(/^#{1,6}\s+/, "");
          return <h3 key={pIdx}>{renderInlineSegment(heading, `h-${pIdx}`)}</h3>;
        }
        // Preserve single newlines inside a paragraph via <br> so note
        // authors who deliberately break lines don't have their intent
        // flattened.
        const lines = para.split("\n");
        const children: ReactNode[] = [];
        lines.forEach((line, lIdx) => {
          if (lIdx > 0) children.push(<br key={`br-${pIdx}-${lIdx}`} />);
          children.push(renderInlineSegment(line, `p-${pIdx}-${lIdx}`));
        });
        return <p key={pIdx}>{children}</p>;
      })}
    </div>
  );
}

// ── Provenance block ──────────────────────────────────────────────────

type ProvenanceBlockProps = {
  agent?: string;
  captured?: string;
  artifactRef?: string;
  evidenceQuote?: string;
};

/**
 * Canonical provenance rendering: agent_name + captured_at + artifact_ref
 * + evidence_quote. Each gets its own row so the label tier stays muted
 * and the value tier stays primary ink. Missing fields are dropped.
 */
export function ProvenanceBlock({
  agent,
  captured,
  artifactRef,
  evidenceQuote,
}: ProvenanceBlockProps) {
  const hasAny = agent || captured || artifactRef || evidenceQuote;
  if (!hasAny) return null;
  return (
    <div className="provenance-list">
      <div className="provenance-row">
        {agent && (
          <div className="provenance-line">
            <span className="provenance-label">Agent</span>
            <span className="agent-chip">{agent}</span>
          </div>
        )}
        {captured && (
          <div className="provenance-line">
            <span className="provenance-label">Captured</span>
            <RelTime iso={captured} />
          </div>
        )}
        {artifactRef && (
          <div className="provenance-line">
            <span className="provenance-label">Artifact</span>
            <span className="provenance-value mono">{artifactRef}</span>
            <CopyInline text={artifactRef} ariaLabel="Copy artifact ref">
              Copy
            </CopyInline>
          </div>
        )}
        {evidenceQuote && (
          <blockquote className="evidence-quote">{evidenceQuote}</blockquote>
        )}
      </div>
    </div>
  );
}

// ── PoC helpers ───────────────────────────────────────────────────────

export function isCurlLike(s: string | undefined | null): boolean {
  if (!s) return false;
  return /^\s*curl\b/i.test(s);
}

export function CodeBlock({
  label,
  text,
  copyable = true,
}: {
  label?: string;
  text: string;
  copyable?: boolean;
}) {
  return (
    <div>
      {(label || copyable) && (
        <div className="code-block-header">
          {label ? <span className="code-block-label">{label}</span> : <span />}
          {copyable && <CopyInline text={text} />}
        </div>
      )}
      <pre className="code-block">{text}</pre>
    </div>
  );
}
