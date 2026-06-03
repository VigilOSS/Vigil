// Summary stat bar (UI/UX adoption wave, Tier 1b).
//
// Generic KPI bar ported from the reference-project workbench SummaryCards
// (designs/dark/SummaryCards.tsx): an inline row of LABEL / big-mono-value
// pairs separated by `|` dividers. Translated from their Tailwind + hard-coded
// hex to our plain CSS — the small uppercase label uses `--muted`, the value
// uses our mono font + `tabular-nums`, and a per-item `tone` maps to a theme
// var (`--ok` / `--danger` / `--warn` / `--muted` / `--accent`) so it reads
// correctly in both themes. Wraps onto multiple rows on narrow screens.
//
// Presentation-only: every value arrives via props so a later cross-engagement
// dashboard can reuse the same bar.

export type StatTone = "ok" | "danger" | "warn" | "muted" | "accent";

export interface SummaryStatBarItem {
  label: string;
  value: string | number;
  tone?: StatTone;
}

const TONE_VAR: Record<StatTone, string> = {
  ok: "var(--ok)",
  danger: "var(--danger)",
  warn: "var(--warn)",
  muted: "var(--muted)",
  accent: "var(--accent)",
};

export interface SummaryStatBarProps {
  items: SummaryStatBarItem[];
}

export function SummaryStatBar({ items }: SummaryStatBarProps) {
  return (
    <div className="v-statbar">
      {items.map((item, index) => (
        <span key={item.label} className="v-statbar-item">
          {index > 0 && <span className="v-statbar-divider" aria-hidden="true">|</span>}
          <span className="v-statbar-label">{item.label}</span>
          <span className="v-statbar-value" style={{ color: TONE_VAR[item.tone ?? "accent"] }}>
            {item.value}
          </span>
        </span>
      ))}
    </div>
  );
}

export default SummaryStatBar;
