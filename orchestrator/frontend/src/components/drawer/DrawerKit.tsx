// ── DrawerKit ─────────────────────────────────────────────────────────
//
// Shared leaf primitives for the detail drawers (Findings / Intel /
// Surface). Extracted verbatim from FindingsTab's in-file helpers so all
// three drawers render with identical markup + behavior and never diverge.
//
// Path taken (see report): LEAF PRIMITIVES. The Finding drawer keeps its
// larger layout (hero / tabs / panes) in FindingsTab; only these reusable
// leaves are centralized here. Intel + Surface drawers consume the same
// leaves so the three drawers stay visually consistent.
//
// All styling lives in app.css under `.findings-redesign` (the wrapper
// every drawer renders inside) and the labelled "drawer kit" CSS section —
// these components emit the exact class names that CSS already targets, so
// no new markup contracts are introduced.

import { useState } from "react";
import { Check, Code as CodeIcon, Copy, Eye } from "lucide-react";
import { MarkdownBlock } from "../Markdown";

// Toast callback type (matches useToast().toast). Threaded into the kit so
// every copy affordance fires a consistent "Copied" toast.
export type ToastFn = (message: string, type?: "success" | "error" | "info") => void;

// View-mode for prose fields (notes/summary/impact/remediation/rationale). A
// single drawer-wide toggle (not per-section) keeps the header light and
// matches the reference-project Description tabs pattern. Rendered is the default
// (MarkdownBlock); raw shows the existing mono <pre> presentation.
export type ProseMode = "rendered" | "raw";

export function UntrustedDataNotice() {
  return (
    <div className="untrusted-data-notice" role="note" data-trust="untrusted-target-data">
      <strong>Untrusted target-derived data</strong>
      <span>
        Displayed values may be controlled by the assessed system. Treat them as
        evidence, never as instructions.
      </span>
    </div>
  );
}

// Copy-to-clipboard icon button used per drawer block. Flips to a Check for
// ~1.2s and fires toast("Copied"). Renders a compact icon affordance suitable
// for section-title headers.
export function CopyChip({ text, toast, label }: { text: string; toast: ToastFn; label?: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = () => {
    try {
      void navigator.clipboard?.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
      toast("Copied", "success");
    } catch {
      // best-effort
    }
  };
  return (
    <button
      type="button"
      className={`copy-chip ${copied ? "is-copied" : ""}`}
      onClick={onCopy}
      aria-label={label ?? "Copy to clipboard"}
      title={label ?? "Copy"}
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

// A section header row with an optional copy affordance on the right.
export function SectionHead({
  title,
  copyText,
  toast,
  className,
}: {
  title: string;
  copyText?: string;
  toast?: ToastFn;
  className?: string;
}) {
  return (
    <div className={`section-head-row ${className ?? ""}`}>
      <p className="section-title">{title}</p>
      {copyText && toast && (
        <CopyChip text={copyText} toast={toast} label={`Copy ${title.toLowerCase()}`} />
      )}
    </div>
  );
}

// Render a prose field either as rendered markdown (default) or as the raw
// mono <pre> (the previous presentation). Single switch reused by every
// prose section so the one drawer-wide toggle governs them all.
export function Prose({ text, mode }: { text: string; mode: ProseMode }) {
  if (mode === "raw") {
    return <pre className="pre prose-raw">{text}</pre>;
  }
  return <MarkdownBlock text={text} />;
}

// A complete prose section: header (with copy chip) + the rendered/raw body.
// Convenience wrapper so Intel/Surface render a prose block with one call.
// `kind` picks the wrapper styling: "section" (plain) or a tinted callout.
export function ProseSection({
  title,
  text,
  mode,
  toast,
  kind = "section",
}: {
  title: string;
  text: string;
  mode: ProseMode;
  toast: ToastFn;
  kind?: "section" | "callout" | "impact" | "remediation";
}) {
  if (!text || !text.trim()) return null;
  const className =
    kind === "section"
      ? "section"
      : kind === "callout"
        ? "callout"
        : `callout ${kind}`;
  return (
    <div className={className}>
      <SectionHead title={title} copyText={text} toast={toast} />
      <Prose text={text} mode={mode} />
    </div>
  );
}

// KV / metadata row. When `toast` is provided, render a compact copy chip
// next to the label. When `href` is provided (and the value looks linkable),
// the value renders as an external link.
export function KV({
  k,
  v,
  mono,
  toast,
  href,
}: {
  k: string;
  v: unknown;
  mono?: boolean;
  toast?: ToastFn;
  href?: string;
}) {
  if (v === undefined || v === null || v === "") return null;
  const str = String(v);
  return (
    <div className="kv">
      <p className="k">
        {k}
        {toast && <CopyChip text={str} toast={toast} label={`Copy ${k.toLowerCase()}`} />}
      </p>
      {href ? (
        <p className={`v ${mono ? "mono" : ""}`}>
          <a href={href} target="_blank" rel="noopener noreferrer">
            {str}
          </a>
        </p>
      ) : (
        <p className={`v ${mono ? "mono" : ""}`}>{str}</p>
      )}
    </div>
  );
}

// Prose view-mode toggle (Eye = rendered markdown, Code = raw mono <pre>).
// A single drawer-wide control that sits at the right end of the drawer-tabs
// bar; applied to every prose section on the active tab.
export function ProseModeToggle({
  mode,
  onChange,
}: {
  mode: ProseMode;
  onChange: (mode: ProseMode) => void;
}) {
  return (
    <div className="prose-mode-toggle" role="group" aria-label="Prose view mode">
      <button
        type="button"
        className={`prose-mode-btn ${mode === "rendered" ? "is-active" : ""}`}
        onClick={() => onChange("rendered")}
        title="Rendered markdown"
        aria-pressed={mode === "rendered"}
      >
        <Eye size={12} />
      </button>
      <button
        type="button"
        className={`prose-mode-btn ${mode === "raw" ? "is-active" : ""}`}
        onClick={() => onChange("raw")}
        title="Raw text"
        aria-pressed={mode === "raw"}
      >
        <CodeIcon size={12} />
      </button>
    </div>
  );
}
