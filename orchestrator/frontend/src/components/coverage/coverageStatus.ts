// Coverage status helpers for the operator UI. Labels, meanings, tones and
// order come from the shared vocabulary (components/ui/statusTones.ts,
// domain "coverage"); the stored values are owned by the backend
// (`state_manager/coverage.py:CoverageStatus`). lib/railBadges.ts imports
// this module and node's test runner loads it directly, so it imports only
// `.ts` modules, with their extension.

import { compareStatus, statusEntry, statusLabel, statusOrder } from "../ui/statusTones.ts";

/** Every coverage status most urgent first (chip and legend order). */
export const COVERAGE_STATUS_ORDER: readonly string[] = statusOrder("coverage");

/** Statuses that still owe work; the "Open work" view lists these. */
export const OPEN_COVERAGE_STATUSES = ["blocked", "deferred", "pending", "queued"] as const;

export function coverageStatusLabel(status: string): string {
  return statusLabel("coverage", status);
}

export function coverageStatusMeaning(status: string): string {
  return statusEntry("coverage", status).meaning ?? "Recorded status without a defined meaning.";
}

export function compareCoverageStatus(a: string, b: string): number {
  return compareStatus("coverage", a, b);
}

/** Blocked-technique retry states (`app/retry_state.py`) in plain words. */
const RETRY_STATE_LABELS: Record<string, string> = {
  pending: "Retry not yet decided",
  no_retry: "Will not be retried",
  retryable: "Can be retried",
  blocked: "Blocked",
  blocked_on_dependency: "Waiting on a dependency",
  needs_authorization: "Needs authorization",
};

export function retryStateLabel(state: string): string {
  return RETRY_STATE_LABELS[state] ?? state.replace(/_/g, " ");
}

/** A facet value as shown on a chip ("" is the bucket of items without one). */
export function facetValueLabel(dimension: string, value: string): string {
  if (dimension === "status") return coverageStatusLabel(value);
  if (value === "") return dimension === "method" ? "No method (service)" : "None";
  return value;
}
