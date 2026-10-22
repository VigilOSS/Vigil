import type { SubmissionVersion } from "../../lib/api";
import type { Scope } from "../ui";
import { statusEntry } from "../ui/statusTones";
import type {
  SubmissionDeskDetail,
  SubmissionListingFilter,
  SubmissionPlatform,
  SubmissionQueueState,
} from "../../lib/submissionsApi";

export const PLATFORM_LABELS: Record<SubmissionPlatform, string> = {
  bugcrowd: "Bugcrowd",
  hackerone: "HackerOne",
  direct: "Direct disclosure",
  ghsa: "GitHub private advisory",
};

export function platformLabel(value: string | null | undefined): string {
  if (!value) return "No platform yet";
  return PLATFORM_LABELS[value as SubmissionPlatform] ?? value;
}

/** State chips, in queue order. "To do" and "All" are the scope, not chips. */
export const STATE_FILTER_ORDER: Array<SubmissionQueueState | "incomplete_exports"> = [
  "ready",
  "blocked",
  "needs_draft",
  "exported",
  "filed",
  "not_candidate",
  "incomplete_exports",
];

/** The states the backend's "To do" (`actionable`) listing holds: the Needs attention scope. */
export const ATTENTION_STATES: ReadonlySet<SubmissionListingFilter> = new Set<SubmissionListingFilter>([
  "ready",
  "blocked",
  "needs_draft",
  "exported",
  "incomplete_exports",
]);

/** The backend listing for a scope and an optional state chip. */
export function listingFilterFor(scope: Scope, state: SubmissionListingFilter | null): SubmissionListingFilter {
  return state ?? (scope === "attention" ? "actionable" : "all");
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const RECENCY_OPTIONS: Array<{ hours: number | null; label: string }> = [
  { hours: null, label: "Any time" },
  { hours: 24, label: "Changed 24h" },
  { hours: 168, label: "Changed 7d" },
];

export type DeskView = {
  scope: Scope;
  state: SubmissionListingFilter | null;
  severity: string[];
  platform: string[];
  recency: number | null;
  search: string;
  slug: string;
  tab: string;
  loadedCount?: number;
};

export const DEFAULT_DESK_VIEW: DeskView = {
  scope: "attention",
  state: null,
  severity: [],
  platform: [],
  recency: null,
  search: "",
  slug: "",
  tab: "body",
};

/** Parses the saved desk view; anything unreadable falls back to the defaults. */
export function parseDeskView(text: string | null | undefined): DeskView {
  if (!text) return DEFAULT_DESK_VIEW;
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    const strings = (items: unknown) => Array.isArray(items) ? items.filter((item): item is string => typeof item === "string") : [];
    const state = STATE_FILTER_ORDER.includes(value.state as SubmissionQueueState) ? value.state as SubmissionListingFilter : null;
    return {
      scope: value.scope === "all" ? "all" : "attention",
      state,
      severity: strings(value.severity),
      platform: strings(value.platform),
      recency: RECENCY_OPTIONS.some((option) => option.hours === value.recency) ? value.recency as number | null : null,
      search: typeof value.search === "string" ? value.search : "",
      slug: typeof value.slug === "string" ? value.slug : "",
      tab: typeof value.tab === "string" ? value.tab : "body",
      ...(Number.isSafeInteger(value.loadedCount) && Number(value.loadedCount) > 0 ? { loadedCount: Number(value.loadedCount) } : {}),
    };
  } catch {
    return DEFAULT_DESK_VIEW;
  }
}

export function listingFilterLabel(filter: SubmissionListingFilter): string {
  if (filter === "actionable") return "To do";
  if (filter === "all") return "All findings";
  if (filter === "incomplete_exports") return "Incomplete exports";
  return statusEntry("submission", filter).label;
}

export function listingFilterHint(filter: SubmissionListingFilter): string {
  if (filter === "actionable") {
    return "Ready, blocked, needs-draft, and exported-but-not-filed findings.";
  }
  if (filter === "all") return "Every finding that is not merged or a false positive.";
  if (filter === "incomplete_exports") return "Findings with a staged or failed export reservation.";
  // Each queue state's one-line definition is its shared "submission" status meaning.
  return statusEntry("submission", filter).meaning ?? "";
}

export function shortHash(value: string | null | undefined, length = 12): string {
  return value ? value.slice(0, length) : "—";
}

export function safeExternalHref(value: string): string | null {
  const candidate = value.trim();
  if (!candidate) return null;
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" || url.protocol === "http:" ? candidate : null;
  } catch {
    return null;
  }
}

export function basename(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] || path;
}

export function dirname(path: string): string {
  const index = path.lastIndexOf("/");
  return index > 0 ? path.slice(0, index) : "(engagement root)";
}

export function sameIdSet(a: Iterable<number>, b: Iterable<number>): boolean {
  const left = [...new Set(a)].sort((x, y) => x - y);
  const right = [...new Set(b)].sort((x, y) => x - y);
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function sortedIds(ids: Iterable<number>): number[] {
  return [...new Set(ids)].sort((a, b) => a - b);
}

// The renderer writes one "## OPERATOR DETAILS — NOT FOR SUBMISSION" section
// below the external body in submission.md; it never reaches the export.
const OPERATOR_HEADING = /^#{1,6}\s*OPERATOR DETAILS\b.*$/m;

export function operatorSection(workspaceMarkdown: string): string | null {
  const match = OPERATOR_HEADING.exec(workspaceMarkdown);
  if (!match) return null;
  return workspaceMarkdown.slice(match.index).trim();
}

// The number the next new export reserves: one past every version this
// finding has, complete or still staged/failed.
export function nextVersionNumber(detail: SubmissionDeskDetail): number {
  const numbers = [
    detail.latest_version?.version_number ?? 0,
    ...detail.versions.map((version) => version.version_number),
    ...detail.pending_versions.map((version) => version.version_number),
  ];
  return Math.max(0, ...numbers) + 1;
}

export function versionAttachmentNames(version: SubmissionVersion): string[] {
  const manifest = version.manifest;
  if (manifest && "attachments" in manifest && Array.isArray(manifest.attachments)) {
    return manifest.attachments.map((row) => basename(row.original_relative_path));
  }
  return version.attachment_ids.map((id) => `artifact #${id}`);
}
