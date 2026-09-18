// Shared presentation helpers for the report.

import type { ReportFinding, ReportFindingGroups } from "../types";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

// A `details.references` entry is either a bare string or an object carrying
// some of {title, id, url}. Both shapes reach the report unchanged, so this
// resolves one to the label a reader should see and the link it should point at.
export interface ReferenceLink {
  label: string;
  url: string;
}

export function referenceLink(ref: unknown): ReferenceLink | null {
  if (typeof ref === "string") {
    const text = ref.trim();
    if (!text) return null;
    return { label: text, url: /^https?:\/\//i.test(text) ? text : "" };
  }
  if (ref && typeof ref === "object") {
    const r = ref as { title?: unknown; id?: unknown; url?: unknown };
    const title = String(r.title ?? r.id ?? "").trim();
    const url = String(r.url ?? "").trim();
    if (!title && !url) return null;
    return { label: title || url, url };
  }
  return null;
}

export function formatLabel(value: string | null | undefined): string {
  if (!value) return "—";
  return value.replace(/_/g, " ");
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Flatten the grouped projection into a single severity-ordered list of
// findings for the Findings table and the Full-Report ordering. Each entry
// records whether it is a root, a sibling (with its root slug), or standalone.
export interface FlatFinding {
  finding: ReportFinding;
  role: "root" | "sibling" | "standalone";
  rootSlug?: string;
}

export function flattenFindings(groups: ReportFindingGroups): FlatFinding[] {
  const out: FlatFinding[] = [];
  for (const group of groups.groups) {
    out.push({ finding: group.root, role: "root" });
    for (const sibling of group.siblings) {
      out.push({ finding: sibling, role: "sibling", rootSlug: group.root.slug });
    }
  }
  for (const finding of groups.standalone) {
    out.push({ finding, role: "standalone" });
  }
  out.sort((a, b) => {
    const sevDiff =
      (SEVERITY_RANK[b.finding.severity ?? "info"] ?? 0) -
      (SEVERITY_RANK[a.finding.severity ?? "info"] ?? 0);
    if (sevDiff !== 0) return sevDiff;
    return String(a.finding.report_id ?? "").localeCompare(String(b.finding.report_id ?? ""));
  });
  return out;
}
