// ── FacetChipGroup ────────────────────────────────────────────────────
// One labelled row of filter chips for a dimension with any number of values
// (Source, Host, Method…), built from the shared FilterChip. The most common
// values show first; the rest stay one click away behind "Show all N" rather
// than being cut off, and a selected value is always shown so it can be
// cleared. Used by the Intel, Surfaces, HTTP and Commands filter bars.

import { useState, type ReactNode } from "react";

import { FilterChip, FilterGroup } from "./FilterChip";
import type { StatusDomain } from "./statusTones";

export type FacetChipValue = {
  value: string;
  /** Matching rows; null while unknown. */
  count: number | null;
};

type FacetChipGroupProps = {
  label: string;
  /** Values in display order (usually most common first). */
  values: FacetChipValue[];
  selected: ReadonlySet<string>;
  onToggle: (value: string) => void;
  /** Chip text for a value (defaults to the value; an empty value reads "Not recorded"). */
  labelFor?: (value: string) => string;
  /** Category dot color for a value. */
  colorFor?: (value: string) => string | undefined;
  /** Status vocabulary for status values (glyph + tone instead of a dot). */
  statusDomain?: StatusDomain;
  /** Plain-language definition of a value, for hover and assistive technology. */
  descriptionFor?: (value: string) => string | undefined;
  /** Chips shown before "Show all". */
  collapsedLimit?: number;
  /** Counts cover only loaded rows (a windowed ledger); shows "N+". */
  partial?: boolean;
  /** Values the source counted but did not list (a server facet limit). */
  unlistedCount?: number;
  /** What to do about the unlisted values (default "search to narrow"). */
  unlistedHint?: ReactNode;
};

const DEFAULT_COLLAPSED_LIMIT = 8;

export function FacetChipGroup({
  label,
  values,
  selected,
  onToggle,
  labelFor,
  colorFor,
  statusDomain,
  descriptionFor,
  collapsedLimit = DEFAULT_COLLAPSED_LIMIT,
  partial,
  unlistedCount = 0,
  unlistedHint = "search to narrow",
}: FacetChipGroupProps) {
  const [expanded, setExpanded] = useState(false);
  const overflow = values.length > collapsedLimit;
  const head = expanded || !overflow ? values : values.slice(0, collapsedLimit);
  // A selected value outside the shown chips stays visible so it can be cleared.
  const shown = new Set(head.map((entry) => entry.value));
  const pinned = [...selected].filter((value) => !shown.has(value)).map((value) => (
    values.find((entry) => entry.value === value) ?? { value, count: 0 }
  ));
  const chips = [...head, ...pinned];
  const text = (value: string) => labelFor?.(value) ?? (value || "Not recorded");
  return (
    <FilterGroup label={label}>
      {chips.map((entry) => (
        <FilterChip
          key={entry.value}
          label={text(entry.value)}
          count={entry.count}
          partial={partial}
          selected={selected.has(entry.value)}
          onToggle={() => onToggle(entry.value)}
          color={statusDomain ? undefined : colorFor?.(entry.value)}
          status={statusDomain ? { domain: statusDomain, value: entry.value } : undefined}
          description={descriptionFor?.(entry.value)}
        />
      ))}
      {overflow && (
        <button
          type="button"
          className="ui-clear-filters"
          aria-expanded={expanded}
          onClick={() => setExpanded((open) => !open)}
        >
          {expanded ? "Show fewer" : `Show all ${values.length.toLocaleString("en-US")}`}
        </button>
      )}
      {unlistedCount > 0 && (expanded || !overflow) && (
        <span className="meta-text">
          {unlistedCount.toLocaleString("en-US")} more not listed; {unlistedHint}
        </span>
      )}
    </FilterGroup>
  );
}
