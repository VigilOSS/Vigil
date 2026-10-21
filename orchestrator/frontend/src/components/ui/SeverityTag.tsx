import type { CSSProperties } from "react";

import "../../styles/ui.css";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

/** The severity's color token; an unknown or unrecorded severity uses Info's. */
export function severityColor(severity: string | null | undefined): string {
  return SEVERITY_COLORS[severity ?? ""] || "var(--sev-info)";
}

/** "high" → "High"; an unrecorded severity reads "Unrated". */
export function severityLabel(severity: string | null | undefined): string {
  const value = (severity ?? "").trim();
  return value ? value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ") : "Unrated";
}

/**
 * A severity as colour, shape and word, so it never relies on hue alone. The
 * pill (`md`) is for headers and cards; `sm` is a dot and word for dense rows
 * and table cells.
 *
 *   <SeverityTag severity={finding.severity} size="sm" />
 */
export function SeverityTag({ severity, size = "md", title }: { severity: string; size?: "sm" | "md"; title?: string }) {
  return (
    <span
      className={`sev-tag${size === "sm" ? " sev-tag-sm" : ""}`}
      style={{ "--sev-tag-color": severityColor(severity) } as CSSProperties}
      title={title ?? `Severity: ${severityLabel(severity)}`}
    >
      <span className="sev-tag-dot" aria-hidden="true" />
      {severityLabel(severity)}
    </span>
  );
}
