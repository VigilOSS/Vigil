// Shared presentational helpers for Notes, Provenance, and PoC sections
// across the Intel + Findings drawers (Issue 4). Centralized here because
// the contracts are identical: a notes blob that deserves paragraphs +
// inline code + auto-linked URLs, a provenance object with a canonical
// four-field shape, and a copy-to-clipboard affordance for mono refs.

import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";

import {
  formatAbsoluteTime,
  formatAge,
  formatRelativeTime,
  parseServerTime,
  type AbsoluteTimePrecision,
  type ServerTimeInput,
} from "../lib/serverTime";

// ── Timestamps ────────────────────────────────────────────────────────
//
// Parsing and text formatting live in lib/serverTime.ts (zone-less database
// timestamps are UTC). <TimeStamp> is the one way to render a backend time.

// One shared 30 s clock keeps every mounted relative label honest without a
// timer per row.
const CLOCK_TICK_MS = 30_000;
const clockListeners = new Set<() => void>();
let clockNow = Date.now();
let clockTimer: ReturnType<typeof setInterval> | null = null;

function subscribeClock(listener: () => void) {
  clockListeners.add(listener);
  if (clockTimer === null) {
    clockNow = Date.now();
    clockTimer = setInterval(() => {
      clockNow = Date.now();
      clockListeners.forEach((notify) => notify());
    }, CLOCK_TICK_MS);
  }
  return () => {
    clockListeners.delete(listener);
    if (clockListeners.size === 0 && clockTimer !== null) {
      clearInterval(clockTimer);
      clockTimer = null;
    }
  };
}

function readClock() {
  return clockNow;
}

type TimeStampProps = {
  value: ServerTimeInput;
  /**
   * relative: "4h ago" with absolute UTC on hover (tables, lists).
   * absolute: "2026-10-20 14:07 UTC" with the age on hover.
   * both: "2026-10-20 14:07:07 UTC · 4h ago" (detail panes); older times
   *   keep counting ("· 3mo ago") rather than repeating the date.
   */
  mode?: "relative" | "absolute" | "both";
  /** Precision of the absolute text; defaults to minutes (absolute) or seconds. */
  precision?: AbsoluteTimePrecision;
  /** Rendered when the value is missing. */
  fallback?: ReactNode;
  className?: string;
};

const BYTE_UNITS = ["KB", "MB", "GB", "TB"] as const;

/**
 * A byte count in binary units with one decimal ("1.5 KB", "24.6 MB").
 * An unknown size renders `empty` rather than a misleading zero.
 */
export function formatBytes(value: number | null | undefined, empty = "—"): string {
  if (value == null || !Number.isFinite(value) || value < 0) return empty;
  if (value < 1024) return `${Math.round(value)} B`;
  let size = value / 1024;
  let unit = 0;
  // Step up when rounding would print 1024.0 of the smaller unit.
  while (unit < BYTE_UNITS.length - 1 && Number(size.toFixed(1)) >= 1024) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

/**
 * A backend timestamp as `<time dateTime=ISO>`. Every mode carries the
 * absolute UTC time in `title` or visible text, and in the accessible label.
 * An unparseable value renders verbatim so recorded text is never hidden.
 */
export function TimeStamp({ value, mode = "relative", precision, fallback = "—", className }: TimeStampProps) {
  // Subscribing re-renders on each shared tick; the label itself reads the
  // current time so a first render after a long idle period is never stale.
  useSyncExternalStore(subscribeClock, readClock, readClock);
  const parsed = parseServerTime(value);
  if (!parsed) {
    if (!value) return <>{fallback}</>;
    return <span className={className} title="Unrecognized timestamp format">{value}</span>;
  }
  const relative = formatRelativeTime(value);
  const absolute = formatAbsoluteTime(value, precision ?? (mode === "absolute" ? "minute" : "second"));
  const classes = ["timestamp", className].filter(Boolean).join(" ");
  if (mode === "both") {
    const age = formatAge(value);
    return (
      <time className={classes} dateTime={parsed.toISOString()} aria-label={`${absolute} (${age})`}>
        {absolute}
        <span className="timestamp-age" aria-hidden="true"> · {age}</span>
      </time>
    );
  }
  const text = mode === "absolute" ? absolute : relative;
  const label = mode === "absolute" ? `${absolute} (${relative})` : `${relative} (${absolute})`;
  return (
    <time
      className={classes}
      dateTime={parsed.toISOString()}
      title={mode === "absolute" ? relative : absolute}
      aria-label={label}
    >
      {text}
    </time>
  );
}

// ── Copy-to-clipboard ─────────────────────────────────────────────────

export function CopyInline({
  text,
  children,
  ariaLabel,
  onCopied,
}: {
  text: string;
  children?: ReactNode;
  ariaLabel?: string;
  // Optional post-copy hook (e.g. fire a toast). Kept optional so existing
  // non-drawer callers (IntelTab provenance) are unaffected.
  onCopied?: () => void;
}) {
  const scope = useMemo(() => ({}), [text]);
  const activeScope = useRef<object | null>(scope);
  const activeRequest = useRef<object | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [feedback, setFeedback] = useState<{ scope: object; result: "copied" | "failed" } | null>(null);
  activeScope.current = scope;
  const copied = feedback?.scope === scope && feedback.result === "copied";
  const failed = feedback?.scope === scope && feedback.result === "failed";

  useEffect(() => {
    activeScope.current = scope;
    return () => {
      if (activeScope.current === scope) activeScope.current = null;
      activeRequest.current = null;
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, [scope]);

  const onCopy = async () => {
    const request = {};
    activeRequest.current = request;
    const current = () => activeScope.current === scope && activeRequest.current === request;
    setFeedback(null);
    if (timer.current !== null) clearTimeout(timer.current);
    try {
      if (!navigator.clipboard) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(text);
      if (!current()) return;
      setFeedback({ scope, result: "copied" });
      timer.current = setTimeout(() => { if (current()) setFeedback(null); }, 1200);
      onCopied?.();
    } catch {
      if (current()) setFeedback({ scope, result: "failed" });
    }
  };
  return (
    <>
    <button
      type="button"
      className={`copy-inline ${copied ? "is-copied" : ""}`}
      onClick={onCopy}
      aria-label={ariaLabel ?? "Copy to clipboard"}
    >
      {copied ? "Copied" : children ?? "Copy"}
    </button>
    {failed && <span className="error-text" role="alert">Could not copy. Select and copy the text manually.</span>}
    </>
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
            <TimeStamp value={captured} />
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
  onCopied,
}: {
  label?: string;
  text: string;
  copyable?: boolean;
  // Forwarded to CopyInline so drawer callers can toast on copy.
  onCopied?: () => void;
}) {
  return (
    <div>
      {(label || copyable) && (
        <div className="code-block-header">
          {label ? <span className="code-block-label">{label}</span> : <span />}
          {copyable && <CopyInline text={text} onCopied={onCopied} />}
        </div>
      )}
      <pre className="code-block">{text}</pre>
    </div>
  );
}
