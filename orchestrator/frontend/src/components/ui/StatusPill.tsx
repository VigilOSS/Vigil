import type { ReactNode } from "react";

import { statusEntry, type StatusDomain, type StatusTone } from "./statusTones";
import "../../styles/ui.css";

/** The shape that pairs with each tone's color, so status never relies on hue alone. */
export function StatusGlyph({ tone }: { tone: StatusTone }) {
  const common = {
    viewBox: "0 0 12 12",
    width: 11,
    height: 11,
    "aria-hidden": true,
    focusable: false,
    className: "ui-status-glyph",
  } as const;
  switch (tone) {
    case "danger":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.6" />
          <path d="M2.8 9.2 9.2 2.8" stroke="currentColor" strokeWidth="1.6" />
        </svg>
      );
    case "warning":
      return (
        <svg {...common}>
          <path d="M6 1.6 10.8 10H1.2Z" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
          <path d="M6 4.8v2.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          <circle cx="6" cy="8.6" r="0.75" fill="currentColor" />
        </svg>
      );
    case "paused":
      return (
        <svg {...common}>
          <path d="M4 2.5v7M8 2.5v7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      );
    case "progress":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.4" />
          <path d="M6 3.4V6l1.8 1.2" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        </svg>
      );
    case "pending":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.2" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="2.2 1.6" />
        </svg>
      );
    case "info":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="1.4" />
          <circle cx="6" cy="6" r="2" fill="currentColor" />
        </svg>
      );
    case "success":
      return (
        <svg {...common}>
          <path d="M2.4 6.3 5 8.8l4.6-5.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <path d="M2.5 6h7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      );
  }
}

type StatusPillProps = {
  /** Vocabulary the value belongs to (statusTones.ts); supplies label, tone and meaning. */
  domain?: StatusDomain;
  /** The stored status value. */
  value: string | null | undefined;
  /** Replaces the vocabulary label (keep it sentence case). */
  label?: ReactNode;
  /** Replaces the vocabulary tone; required in practice when `domain` is omitted. */
  tone?: StatusTone;
  /**
   * Why the record is in this status, shown in text right after the pill
   * (never tooltip-only), e.g. "2 open obligations".
   */
  reason?: ReactNode;
  /** Hover text; defaults to the vocabulary meaning. */
  title?: string;
  /** `sm` for grid cells and dense rows, `md` (default) for headers and cards. */
  size?: "sm" | "md";
  className?: string;
};

/**
 * The one status pill: sentence-case label, tone color and tone glyph, with
 * an optional inline reason.
 *
 *   <StatusPill domain="run" value={run.status} reason={health.reason} />
 *   <StatusPill domain="coverage" value="blocked" size="sm" />
 *   <StatusPill tone="warning" value="attention" label="Needs attention" />
 */
export function StatusPill({ domain, value, label, tone, reason, title, size = "md", className }: StatusPillProps) {
  const known = domain ? statusEntry(domain, value) : null;
  const resolvedTone = tone ?? known?.tone ?? "neutral";
  const text = label ?? known?.label ?? value ?? "";
  const pill = (
    <span
      className={["ui-status", size === "sm" ? "ui-status-sm" : null, reason ? null : className].filter(Boolean).join(" ")}
      data-tone={resolvedTone}
      data-status={value ?? ""}
      title={title ?? known?.meaning}
    >
      <StatusGlyph tone={resolvedTone} />
      <span className="ui-status-label">{text}</span>
    </span>
  );
  if (!reason) return pill;
  return (
    <span className={["ui-status-group", className].filter(Boolean).join(" ")}>
      {pill}
      <span className="ui-status-reason">{reason}</span>
    </span>
  );
}
