// A facet as a compact menu button: opens a checkbox list of values with
// server counts, filterable by typing. Used for dimensions with many values
// (family, auth, slot, method, host) so the grid keeps the screen.

import { useEffect, useId, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import type { CoverageFacetGroup } from "../../lib/coverageApi";

type Props = {
  label: string;
  group: CoverageFacetGroup | undefined;
  active: string[];
  formatValue: (value: string) => string;
  onToggle: (value: string) => void;
  /** Allow filtering by a typed value the counted list does not include. */
  allowCustom?: (typed: string) => string | null;
};

export function CoverageFacetMenu({ label, group, active, formatValue, onToggle, allowCustom }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const rootRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const panelId = useId();

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey, true);
    };
  }, [open]);

  const values = group?.values ?? [];
  const needle = query.trim().toLowerCase();
  const matches = needle
    ? values.filter((entry) => formatValue(entry.value).toLowerCase().includes(needle))
    : values;
  const custom = allowCustom && needle ? allowCustom(query) : null;
  const showCustom = custom != null && !values.some((entry) => entry.value === custom) && !active.includes(custom);
  // Selected values the counted list does not include (a typed value, or a
  // rare value past the list's cut-off) stay listed so they can be unchecked.
  const unlisted = active.filter(
    (value) => !values.some((entry) => entry.value === value)
      && (!needle || formatValue(value).toLowerCase().includes(needle)),
  );
  const distinct = group?.distinct ?? 0;

  return (
    <div className={`cov-menu ${open ? "is-open" : ""}`} ref={rootRef}>
      <button
        ref={buttonRef}
        type="button"
        className={`cov-menu-button ${active.length ? "has-selection" : ""}`}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        {label}
        <span className="cov-menu-count">{active.length ? `${active.length} selected` : distinct.toLocaleString()}</span>
        <ChevronDown size={13} aria-hidden="true" />
      </button>
      {open ? (
        <div className="cov-menu-panel" id={panelId} role="group" aria-label={`${label} filter`}>
          {values.length > 8 || allowCustom ? (
            <input
              type="search"
              className="cov-menu-find"
              aria-label={`Find ${label.toLowerCase()}`}
              placeholder={`Find ${label.toLowerCase()}…`}
              value={query}
              autoFocus
              onChange={(event) => setQuery(event.target.value)}
            />
          ) : null}
          <ul className="cov-menu-list">
            {showCustom && custom != null ? (
              <li>
                <button type="button" className="cov-text-button" onClick={() => { onToggle(custom); setQuery(""); }}>
                  Filter by “{custom}”
                </button>
              </li>
            ) : null}
            {unlisted.map((value) => (
              <li key={`unlisted:${value}`}>
                <label className="cov-menu-option">
                  <input type="checkbox" checked onChange={() => onToggle(value)} />
                  <span className="cov-menu-text" title={formatValue(value)}>{formatValue(value)}</span>
                  <span className="cov-menu-n" title="Not among the counted values">not counted</span>
                </label>
              </li>
            ))}
            {matches.map((entry) => {
              const checked = active.includes(entry.value);
              return (
                <li key={entry.value}>
                  <label className="cov-menu-option">
                    <input type="checkbox" checked={checked} onChange={() => onToggle(entry.value)} />
                    <span className="cov-menu-text" title={formatValue(entry.value)}>{formatValue(entry.value)}</span>
                    <span className="cov-menu-n">{entry.count.toLocaleString()}</span>
                  </label>
                </li>
              );
            })}
            {matches.length === 0 && unlisted.length === 0 && !showCustom ? <li className="meta-text">No matching values.</li> : null}
          </ul>
          {group && group.omitted_count > 0 ? (
            <p className="cov-menu-note">
              {(group.distinct - group.values.length).toLocaleString()} rarer values ({group.omitted_count.toLocaleString()} items)
              are not listed{allowCustom ? "; type one to filter by it" : "; use search to reach them"}.
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
