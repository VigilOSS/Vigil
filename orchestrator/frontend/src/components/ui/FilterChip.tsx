import type { CSSProperties, ReactNode } from "react";

import { StatusGlyph } from "./StatusPill";
import { statusEntry, type StatusDomain } from "./statusTones";
import "../../styles/ui.css";

type FilterChipProps = {
  label: ReactNode;
  /** Matching rows; omit while unknown. */
  count?: number | null;
  /** The count covers only loaded rows; more may match ("1,000+"). */
  partial?: boolean;
  selected: boolean;
  onToggle: () => void;
  /**
   * Category color as a CSS value ("var(--sev-high)", "var(--m-get)"): a dot
   * before the label and the selected tint. Status chips pass `status` instead.
   */
  color?: string;
  /** Status chips: the vocabulary glyph and tone replace the dot (label still comes from `label`). */
  status?: { domain: StatusDomain; value: string };
  /** A value that cannot match in the current view; still visible, not clickable. */
  disabled?: boolean;
  /** Plain-language definition, shown on hover and to assistive technology. */
  description?: string;
};

/**
 * A filter toggle: label, optional dot or status glyph, count. Selected chips
 * are pressed buttons with the category tint.
 *
 *   <FilterChip label="High" color="var(--sev-high)" count={35} selected={sev.has("high")} onToggle={() => toggle("high")} />
 *   <FilterChip label={statusLabel("command", s)} status={{ domain: "command", value: s }} count={n} selected={…} onToggle={…} />
 */
export function FilterChip({ label, count, partial, selected, onToggle, color, status, disabled, description }: FilterChipProps) {
  const tone = status ? statusEntry(status.domain, status.value).tone : undefined;
  const style = color ? ({ "--ui-chip-color": color } as CSSProperties) : undefined;
  return (
    <button
      type="button"
      className="ui-chip"
      aria-pressed={selected}
      disabled={disabled}
      title={description ?? (status ? statusEntry(status.domain, status.value).meaning : undefined)}
      data-tone={tone}
      style={style}
      onClick={onToggle}
    >
      {tone ? <StatusGlyph tone={tone} /> : color ? <span className="ui-chip-dot" aria-hidden="true" /> : null}
      <span className="ui-chip-label">{label}</span>
      {count != null && <span className="ui-chip-count">{count.toLocaleString("en-US")}{partial ? "+" : ""}</span>}
      {description && <span className="sr-only">: {description}</span>}
    </button>
  );
}

/** A labelled row of chips for one dimension ("Status", "Tool"). */
export function FilterGroup({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={["ui-filter-group", className].filter(Boolean).join(" ")} role="group" aria-label={label}>
      <span className="ui-filter-label" aria-hidden="true">{label}</span>
      {children}
    </div>
  );
}

/** The one clear-all control: "Clear filters (n)", disabled when nothing is set. */
export function ClearFiltersButton({ count, onClear }: { count: number; onClear: () => void }) {
  return (
    <button type="button" className="ui-clear-filters" disabled={count === 0} onClick={onClear}>
      Clear filters{count > 0 ? ` (${count})` : ""}
    </button>
  );
}
