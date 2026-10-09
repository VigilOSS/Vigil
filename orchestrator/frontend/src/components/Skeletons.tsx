// Loading skeletons (UI/UX adoption wave, Tier 1a).
//
// Uses a small set of plain-CSS classes (defined in app.css under
// "/* ---- skeletons ---- */")
// plus inline styles for the dynamic dimensions. The shimmer itself lives on
// the `v-skeleton` class so every variant shares one animation.
//
// Var mapping from their palette to ours:
//   --v-border       → --border
//   --v-surface      → --panel-soft
//   --v-text-muted   → --muted
//
// aria-busy / aria-hidden semantics are preserved so assistive tech treats a
// loading region as transient rather than reading the placeholder bars.

import type { CSSProperties, ReactNode } from "react";

interface SkeletonProps {
  width?: number | string;
  height?: number | string;
  className?: string;
  style?: CSSProperties;
  rounded?: boolean;
}

export function Skeleton({ width, height = 12, className = "", style, rounded }: SkeletonProps) {
  return (
    <span
      className={`v-skeleton ${className}`.trim()}
      style={{
        display: "inline-block",
        width: typeof width === "number" ? `${width}px` : width ?? "100%",
        height: typeof height === "number" ? `${height}px` : height,
        borderRadius: rounded ? "999px" : undefined,
        ...style,
      }}
      aria-hidden="true"
    />
  );
}

interface TableSkeletonProps {
  rows?: number;
  columns?: Array<number | string>;
  showHeader?: boolean;
  className?: string;
}

export function TableSkeleton({
  rows = 10,
  columns = ["10%", "12%", "20%", "40%", "18%"],
  showHeader = true,
  className = "",
}: TableSkeletonProps) {
  return (
    <div className={`skeleton-table ${className}`.trim()} aria-busy="true" role="status" aria-label="Loading table">
      {showHeader && (
        <div className="skeleton-table-row skeleton-table-head">
          {columns.map((w, i) => (
            <Skeleton key={i} width={w} height={10} />
          ))}
        </div>
      )}
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="skeleton-table-row" style={{ opacity: 1 - r * 0.05 }}>
          {columns.map((w, c) => (
            <Skeleton key={c} width={w} height={10} />
          ))}
        </div>
      ))}
    </div>
  );
}

interface ChartSkeletonProps {
  variant?: "donut" | "bar" | "line";
  height?: number;
  label?: string;
  className?: string;
}

export function ChartSkeleton({
  variant = "donut",
  height = 200,
  label,
  className = "",
}: ChartSkeletonProps) {
  if (variant === "donut") {
    return (
      <div className={`skeleton-chart-donut ${className}`.trim()} style={{ height }} aria-busy="true" role="status" aria-label={`Loading ${label || "chart"}`}>
        <span
          className="v-skeleton"
          style={{
            width: height * 0.7,
            height: height * 0.7,
            borderRadius: "999px",
            mask: "radial-gradient(circle, transparent 38%, black 40%)",
            WebkitMask: "radial-gradient(circle, transparent 38%, black 40%)",
          }}
          aria-hidden="true"
        />
        {label && <span className="skeleton-chart-label">{label}</span>}
      </div>
    );
  }
  if (variant === "bar") {
    return (
      <div className={`skeleton-chart-bar ${className}`.trim()} style={{ height }} aria-busy="true" role="status" aria-label={`Loading ${label || "chart"}`}>
        {Array.from({ length: 12 }).map((_, i) => (
          <Skeleton
            key={i}
            width="100%"
            height={`${30 + ((i * 13) % 60)}%`}
            style={{ flex: 1 }}
          />
        ))}
      </div>
    );
  }
  return (
    <div className={`skeleton-chart-line ${className}`.trim()} style={{ height }} aria-busy="true" role="status" aria-label={`Loading ${label || "chart"}`}>
      <Skeleton width="100%" height="100%" />
    </div>
  );
}

interface CardSkeletonProps {
  lines?: number;
  title?: boolean;
  className?: string;
  children?: ReactNode;
}

export function CardSkeleton({ lines = 3, title = true, className = "", children }: CardSkeletonProps) {
  return (
    <div className={`skeleton-card ${className}`.trim()} aria-busy="true" role="status" aria-label="Loading content">
      {title && <Skeleton width="40%" height={12} style={{ marginBottom: 8 }} />}
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} style={{ marginBottom: 6 }}>
          <Skeleton width={i === lines - 1 ? "60%" : "90%"} height={9} />
        </div>
      ))}
      {children}
    </div>
  );
}
