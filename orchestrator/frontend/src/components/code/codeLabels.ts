// Plain-language vocabulary for the Code view. Every backend code the view
// renders maps to operator wording here, and only here (result dispositions
// and queue, file and repository statuses are shared statuses in
// components/ui/statusTones.ts, and codes without a label read through its
// humanizeStatus); the raw code stays available (title / details) for
// experts. A backend test parses
// BLOCKER_LABELS and fails when readiness can emit a code without a label.

import { humanizeStatus } from "../ui/statusTones";

export type CodeView = "overview" | "repositories" | "queue" | "files" | "results" | "quality" | "modules";

export const VIEW_LABELS: Record<CodeView, string> = {
  overview: "Overview",
  repositories: "Repositories",
  queue: "Review queue",
  files: "Files",
  results: "Results",
  quality: "Quality",
  modules: "Modules",
};

export type BlockerLabel = {
  label: string;
  // Where the work behind this blocker is shown. `findings` leaves the Code view.
  view?: CodeView | "findings";
  // The backend message leads with the count of outstanding items.
  counted?: boolean;
};

export const BLOCKER_LABELS: Record<string, BlockerLabel> = {
  admitted_files_unaccounted: { label: "Files not yet reviewed", view: "queue", counted: true },
  admitted_files_unqueued: { label: "Files with no review job queued", view: "queue", counted: true },
  analysis_queue_active: { label: "Review jobs still queued or running", view: "queue", counted: true },
  code_leads_unresolved: { label: "Prior-art leads not yet answered", counted: true },
  critical_high_incomplete: { label: "Critical/high files not yet reviewed", view: "files", counted: true },
  draft_code_findings_unresolved: { label: "Draft code findings to promote, merge, or drop", view: "findings", counted: true },
  files_unclassified: { label: "Files not yet risk-ranked", view: "files", counted: true },
  finding_snapshot_stale: { label: "Findings tied to an older code snapshot", view: "findings", counted: true },
  findings_blind_triage_incomplete: { label: "Findings missing a final triage decision", view: "findings", counted: true },
  findings_unverified: { label: "Findings not yet verified", view: "findings", counted: true },
  fuzz_campaign_incomplete: { label: "Fuzzing still owed" },
  fuzz_decision_missing: { label: "Fuzzing decision not recorded" },
  needs_context_unresolved: { label: "Reviews waiting on more context", view: "queue", counted: true },
  no_repositories: { label: "No repository ingested yet", view: "repositories" },
  pending_triggers: { label: "Cross-file leads not yet followed", view: "queue", counted: true },
  source_manifest_missing: { label: "Source fingerprint missing — re-ingest", view: "repositories" },
  source_snapshot_unverified: { label: "Source snapshot unverified — re-ingest", view: "repositories" },
  structural_analysis_debt_unreviewed: { label: "Files needing a direct read", view: "files", counted: true },
  structural_coverage_unresolved: { label: "Critical/high files the review did not cover", view: "files", counted: true },
  structural_index_metadata_incomplete: { label: "Code index missing data for some files — rebuild", view: "repositories", counted: true },
  structural_index_stale: { label: "Code index out of date — re-index", view: "repositories" },
  threat_model_stale: { label: "Threat model out of date", view: "repositories" },
  unbound_draft_code_findings_unresolved: { label: "Draft code findings not tied to a repository", view: "findings", counted: true },
  unresolved_suspicious_analysis: { label: "Suspicious results awaiting a verdict", view: "results", counted: true },
  variant_checks_incomplete: { label: "Variant checks not finished", counted: true },
  variant_parent_verification_incomplete: { label: "Root findings to verify before variant work", view: "findings", counted: true },
};

export function blockerLabel(code: string): BlockerLabel {
  return BLOCKER_LABELS[code] ?? { label: humanizeStatus(code) };
}

/** The outstanding-item count a counted blocker message leads with. */
export function blockerCount(code: string, message: string): number | null {
  if (!blockerLabel(code).counted) return null;
  const match = message.match(/\d[\d,]*/);
  return match ? Number(match[0].replace(/,/g, "")) : null;
}

export const REQUIRED_LABEL = "Required";
export const SKIPPABLE_LABEL = "Can be skipped with a recorded reason";

export function requirementLabel(overrideable: boolean): string {
  return overrideable ? SKIPPABLE_LABEL : REQUIRED_LABEL;
}

// The present-tense state of the persisted code phase ("Hunting · …").
export const PHASE_STATE_LABELS: Record<string, string> = {
  ingest: "Ingesting + indexing",
  "classify-map": "Classifying + mapping",
  hunt: "Hunting",
  "verify-variant": "Verifying + checking variants",
  fuzz: "Fuzzing",
  complete: "Complete",
};

export const DIRECT_READ_TITLE = "Files needing a direct read";
export const DIRECT_READ_SUBTITLE =
  "The code index couldn't fully parse these files, so they must be read directly before Verify.";

/** Why a file needs a direct read, from its structural-index record. */
export function directReadReason(status: string, truncated: boolean): string {
  const reasons: string[] = [];
  if (status === "degraded") reasons.push("partly parsed");
  else if (status === "unsupported") reasons.push("not parsed");
  if (truncated) reasons.push("too large to fully index");
  return reasons.length ? capitalize(reasons.join(", ")) : "Index incomplete";
}

export const QUEUE_MODE_LABELS: Record<string, string> = {
  initial: "First review",
  reanalysis: "Re-review",
  trigger: "Cross-file lead",
  "metadata-refresh": "Changed since last review",
};

export const CLASSIFICATION_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  skip: "Skip tier",
  unclassified: "Not yet risk-ranked",
};

/** How a receipt is anchored when it names no callable or span. */
export function receiptAnchorNote(bindingStatus: string): string {
  if (bindingStatus === "skipped_unbound") return "Skipped — no source anchors";
  if (["legacy_ambiguous", "legacy_missing", "legacy_unbound"].includes(bindingStatus)) {
    return "Historical receipt without source anchors";
  }
  return "No source anchors";
}

const FAMILY_WORDS: Record<string, string> = {
  dos: "DoS",
  ssrf: "SSRF",
  xxe: "XXE",
  ai: "AI",
  ml: "ML",
  app: "app",
  web: "Web",
};

/** "algorithmic-dos" → "Algorithmic DoS". */
export function familyLabel(family: string): string {
  const words = family.split(/[-_]/).filter(Boolean).map((word, index) => {
    const known = FAMILY_WORDS[word];
    if (known) return index === 0 ? capitalize(known) : known;
    return index === 0 ? capitalize(word) : word;
  });
  return words.join(" ").replace(/\bAI ML\b/, "AI/ML");
}

export type QualityWarning =
  | { kind: "effort"; text: string; risk: string; file: string; family: string; effort: number; threshold: number }
  | { kind: "missing_slots" | "no_families" | "missing_effort"; text: string; risk: string; file: string }
  | { kind: "direct_read"; text: string }
  | { kind: "other"; text: string };

export const QUALITY_GROUP_LABELS: Record<Exclude<QualityWarning["kind"], "effort">, string> = {
  missing_slots: "Files with no input types recorded",
  no_families: "Files with no applicable vulnerability types",
  missing_effort: "Reviewed files missing per-type effort data",
  direct_read: DIRECT_READ_TITLE,
  other: "Other review-quality notes",
};

const EFFORT_WARNING = /^(\w+) file (.+): family '([^']+)' effort (\d+) < (\d+)$/;
const FILE_WARNING = /^(\w+) file (.+): (missing slot_types|no applicable vulnerability families|analyzed but missing CWE coverage data)$/;
const FILE_WARNING_KINDS: Record<string, "missing_slots" | "no_families" | "missing_effort"> = {
  "missing slot_types": "missing_slots",
  "no applicable vulnerability families": "no_families",
  "analyzed but missing CWE coverage data": "missing_effort",
};

/** Structure a backend review-quality warning; unknown shapes stay verbatim. */
export function parseQualityWarning(text: string): QualityWarning {
  const effort = text.match(EFFORT_WARNING);
  if (effort) {
    return {
      kind: "effort",
      text,
      risk: effort[1].toLowerCase(),
      file: effort[2],
      family: effort[3],
      effort: Number(effort[4]),
      threshold: Number(effort[5]),
    };
  }
  const fileWarning = text.match(FILE_WARNING);
  if (fileWarning) {
    return { kind: FILE_WARNING_KINDS[fileWarning[3]], text, risk: fileWarning[1].toLowerCase(), file: fileWarning[2] };
  }
  if (/^Repository \d+ structural coverage debt:/.test(text)) return { kind: "direct_read", text };
  return { kind: "other", text };
}

export function underReviewedLabel(family: string, effort: number, threshold: number): string {
  return `Under-reviewed for ${familyLabel(family)} (${effort} of ${threshold})`;
}

function capitalize(value: string): string {
  return value ? value[0].toUpperCase() + value.slice(1) : value;
}
