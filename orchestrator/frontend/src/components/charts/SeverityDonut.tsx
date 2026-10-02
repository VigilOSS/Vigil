// Severity donut (UI/UX adoption wave, Tier 1b).
//
// Pure-SVG donut ported from the reference-project workbench DonutChart
// (designs/dark/FindingsChart.tsx): stroke-dasharray segments drawn on a
// single circle (r=36, strokeWidth=16, viewBox 100), animated by flipping each
// segment's dash length from 0 → length on the first rAF tick so the CSS
// transition on `.v-donut-segment` sweeps the ring in. The legend treatment
// (label + count + percent + colored swatch) follows static-reports'
// SeverityDonut.
//
// Palette maps to plain CSS instead of their Tailwind/hard-coded hex: segment
// colors come straight from the `--sev-*` theme vars (they resolve in both
// light and dark), the background ring uses `--border`, and label text uses
// `--ink` / `--muted`. Presentation-only — all data arrives via props so a
// later cross-engagement dashboard can reuse it.

import { useEffect, useMemo, useState } from "react";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const PIE_RADIUS = 36;
const PIE_CIRCUMFERENCE = 2 * Math.PI * PIE_RADIUS;
const PIE_SIZE = 100;
const PIE_CENTER = PIE_SIZE / 2;

function sevColor(severity: string): string {
  return `var(--sev-${severity})`;
}

export interface SeverityDonutProps {
  counts: Record<string, number>;
  size?: number;
  centerLabel?: string;
  legend?: boolean;
}

export function SeverityDonut({ counts, size = PIE_SIZE, centerLabel, legend = false }: SeverityDonutProps) {
  const [animated, setAnimated] = useState(false);

  useEffect(() => {
    const id = requestAnimationFrame(() => setAnimated(true));
    return () => cancelAnimationFrame(id);
  }, []);

  // Stable severity order so colors never reshuffle between renders.
  const data = useMemo(
    () => SEVERITY_ORDER.map((severity) => [severity, counts[severity] ?? 0] as const).filter(([, count]) => count > 0),
    [counts],
  );
  const total = data.reduce((sum, [, count]) => sum + count, 0);

  const segments = useMemo(() => {
    let accumulated = 0;
    return data.map(([severity, count]) => {
      const ratio = count / total;
      const length = ratio * PIE_CIRCUMFERENCE;
      const offset = -accumulated;
      accumulated += length;
      return { severity, count, length, offset };
    });
  }, [data, total]);

  const centerText = centerLabel ?? String(total);

  return (
    <div className="v-donut" style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${PIE_SIZE} ${PIE_SIZE}`}
        className="v-donut-svg"
        role="img"
        aria-label={total > 0 ? `Findings by severity, ${total} total: ${data.map(([severity, count]) => `${severity}: ${count}`).join(" · ")}` : "No findings"}
      >
        {/* Background ring — always rendered (also serves as the zero-total empty ring). */}
        <circle
          cx={PIE_CENTER}
          cy={PIE_CENTER}
          r={PIE_RADIUS}
          fill="none"
          stroke="var(--border)"
          strokeWidth="16"
        />
        {segments.map((seg) => (
          <circle
            key={seg.severity}
            cx={PIE_CENTER}
            cy={PIE_CENTER}
            r={PIE_RADIUS}
            fill="none"
            stroke={sevColor(seg.severity)}
            strokeWidth="16"
            className="v-donut-segment"
            strokeDasharray={animated ? `${seg.length} ${PIE_CIRCUMFERENCE}` : `0 ${PIE_CIRCUMFERENCE}`}
            strokeDashoffset={seg.offset}
            transform={`rotate(-90 ${PIE_CENTER} ${PIE_CENTER})`}
          />
        ))}
        <text
          x={PIE_CENTER}
          y={PIE_CENTER}
          textAnchor="middle"
          dominantBaseline="central"
          className="v-donut-total"
          fill={total > 0 ? "var(--ink)" : "var(--muted)"}
        >
          {total > 0 ? centerText : "0"}
        </text>
      </svg>

      {legend && total > 0 && (
        <ul className="v-donut-legend">
          {segments.map((seg) => {
            const pct = Math.round((seg.count / total) * 100);
            return (
              <li key={seg.severity} className="v-donut-legend-row">
                <span className="v-donut-swatch" style={{ background: sevColor(seg.severity) }} aria-hidden="true" />
                <span className="v-donut-legend-label">{seg.severity}</span>
                <span className="v-donut-legend-count">{seg.count}</span>
                <span className="v-donut-legend-pct">({pct}%)</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export default SeverityDonut;
