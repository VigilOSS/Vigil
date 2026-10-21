// Shared workspace primitives: one visual language for every tab.
//
//   PageHeader        title, one-sentence purpose, counts and actions
//   StatusPill        every status (tone + glyph + sentence-case label, inline reason)
//   SeverityTag       a severity as dot + word (severityColor / severityLabel)
//   statusTones       the one status vocabulary (labels, tones, meanings, order)
//   ScopeToggle       "Needs attention N · All N"
//   SegmentedControl  view switches
//   EmptyState        nothing recorded yet vs. no matches (with Clear filters)
//   FilterChip / FilterGroup / ClearFiltersButton
//   FacetChipGroup    a labelled chip row for any number of values ("Show all N")
//   ResultsSummary / describeSort / SortIndicator / ariaSort
//
// Styles live in styles/ui.css; each primitive imports it.

export { EmptyState } from "./EmptyState";
export { FacetChipGroup, type FacetChipValue } from "./FacetChipGroup";
export { ClearFiltersButton, FilterChip, FilterGroup } from "./FilterChip";
export { PageHeader, type PageStat } from "./PageHeader";
export { ScopeToggle, SegmentedControl, type Scope, type SegmentedOption } from "./SegmentedControl";
export { SeverityTag, severityColor, severityLabel } from "./SeverityTag";
export { ResultsSummary, SortIndicator, ariaSort, describeSort, type SortDirection, type SortKind } from "./Sorting";
export { StatusGlyph, StatusPill } from "./StatusPill";
export {
  compareStatus,
  humanizeStatus,
  statusEntry,
  statusLabel,
  statusOrder,
  statusTone,
  type StatusDomain,
  type StatusEntry,
  type StatusTone,
} from "./statusTones";
