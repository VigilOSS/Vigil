// Severity mini-bar (UI/UX adoption wave, Tier 2c).
//
// A tiny horizontal stacked bar of a single engagement's finding severities,
// for the cross-engagement dashboard landing card. Segment widths are
// proportional to each severity count; colors come straight from the `--sev-*`
// theme vars so it reads in both light and dark. A `title` tooltip spells out
// the exact per-severity counts ("critical: n · high: n · ...").
//
// Presentation-only: all data arrives via the `counts` prop. Renders an empty
// track when there are no findings so the card still aligns visually.

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export interface SeverityMiniBarProps {
  counts: Record<string, number>;
}

export function SeverityMiniBar({ counts }: SeverityMiniBarProps) {
  const segments = SEVERITY_ORDER.map(
    (severity) => [severity, counts[severity] ?? 0] as const,
  ).filter(([, count]) => count > 0);
  const total = segments.reduce((sum, [, count]) => sum + count, 0);

  const tooltip =
    total > 0
      ? segments.map(([severity, count]) => `${severity}: ${count}`).join(" · ")
      : "No findings";

  return (
    <div
      className="sev-minibar"
      title={tooltip}
      role="img"
      aria-label={`Findings by severity — ${tooltip}`}
    >
      {total > 0 ? (
        segments.map(([severity, count]) => (
          <span
            key={severity}
            className="sev-minibar-segment"
            style={{
              flexGrow: count,
              background: `var(--sev-${severity})`,
            }}
          />
        ))
      ) : (
        <span className="sev-minibar-empty" />
      )}
    </div>
  );
}

export default SeverityMiniBar;
