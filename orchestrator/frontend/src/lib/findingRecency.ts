// Recency for the Findings page: when a finding was recorded, when it last
// changed, and what the operator has not yet looked at.
//
// "Changed" is the newest transition-ledger entry (`last_transition_at` on the
// list row), never `updated_at`: re-recording a finding moves `updated_at` for
// whole batches at once, so it cannot tell an operator what actually changed.
// A finding with no ledger entry falls back to its creation time.
//
// Timestamps are compared through lib/serverTime.ts (zone-less DB text is UTC).

import { serverTimeMs } from "./serverTime.ts";

export type FindingTimes = {
  slug: string;
  created_at?: string | null;
  changed_at?: string | null;
};

export type FindingsSort = "severity" | "newest" | "changed";
export const FINDINGS_SORTS: readonly FindingsSort[] = ["severity", "newest", "changed"];

export type RecencyFilter = "new24h" | "new7d" | "changed24h" | "changed7d" | "sinceVisit";
export const RECENCY_FILTERS: readonly RecencyFilter[] = ["new24h", "new7d", "changed24h", "changed7d", "sinceVisit"];

const HOUR_MS = 60 * 60 * 1000;
const WINDOW_MS: Record<Exclude<RecencyFilter, "sinceVisit">, number> = {
  new24h: 24 * HOUR_MS,
  new7d: 7 * 24 * HOUR_MS,
  changed24h: 24 * HOUR_MS,
  changed7d: 7 * 24 * HOUR_MS,
};

/** Last ledger change, falling back to creation; "" when neither is known. */
export function findingChangedAt(row: {
  last_transition_at?: string | null;
  created_at?: string | null;
}): string {
  return row.last_transition_at || row.created_at || "";
}

/**
 * Where a finding stands relative to a cutoff. "new" = recorded at or after
 * it; "changed" = recorded before it (or at an unknown time) with a ledger
 * change at or after it. The two never overlap, so "N new · M changed" adds
 * up and a Changed filter does not repeat the New list.
 */
export function recencyKind(item: FindingTimes, cutoffMs: number): "new" | "changed" | null {
  const created = serverTimeMs(item.created_at);
  if (created != null && created >= cutoffMs) return "new";
  const changed = serverTimeMs(item.changed_at);
  if (changed != null && changed >= cutoffMs) return "changed";
  return null;
}

/**
 * The cutoff a recency filter applies, or null when it cannot apply. The
 * last-visit mark is a time the operator already saw, so only strictly later
 * entries count as unseen.
 */
export function recencyCutoff(filter: RecencyFilter, nowMs: number, lastVisitMs: number | null): number | null {
  if (filter === "sinceVisit") return lastVisitMs == null ? null : lastVisitMs + 1;
  return nowMs - WINDOW_MS[filter];
}

export function matchesRecency(
  item: FindingTimes,
  filter: RecencyFilter | null,
  nowMs: number,
  lastVisitMs: number | null,
): boolean {
  if (!filter) return true;
  const cutoff = recencyCutoff(filter, nowMs, lastVisitMs);
  if (cutoff == null) return true;
  const kind = recencyKind(item, cutoff);
  if (filter === "sinceVisit") return kind !== null;
  return filter.startsWith("new") ? kind === "new" : kind === "changed";
}

export function countRecency(
  items: readonly FindingTimes[],
  nowMs: number,
  lastVisitMs: number | null,
): Record<RecencyFilter, number> {
  const counts: Record<RecencyFilter, number> = { new24h: 0, new7d: 0, changed24h: 0, changed7d: 0, sinceVisit: 0 };
  for (const filter of RECENCY_FILTERS) {
    if (filter === "sinceVisit" && lastVisitMs == null) continue;
    for (const item of items) if (matchesRecency(item, filter, nowMs, lastVisitMs)) counts[filter] += 1;
  }
  return counts;
}

/**
 * What the "recent changes" summary reports: findings new or changed since
 * the last-visit mark, or within the last 24 hours when this browser has no
 * earlier visit. `filter` is the recency filter that shows exactly those
 * findings, or null when no single filter does (the first-visit window spans
 * both New 24h and Changed 24h).
 */
export function summarizeRecentChanges(
  items: readonly FindingTimes[],
  nowMs: number,
  lastVisitMs: number | null,
): { created: number; changed: number; sinceVisit: boolean; filter: RecencyFilter | null } {
  const sinceVisit = lastVisitMs != null;
  const cutoff = recencyCutoff(sinceVisit ? "sinceVisit" : "changed24h", nowMs, lastVisitMs) as number;
  let created = 0;
  let changed = 0;
  for (const item of items) {
    const kind = recencyKind(item, cutoff);
    if (kind === "new") created += 1;
    else if (kind === "changed") changed += 1;
  }
  return { created, changed, sinceVisit, filter: sinceVisit ? "sinceVisit" : null };
}

/**
 * Date order for the flat views: Newest = creation time, Recently changed =
 * last ledger change, both descending. Missing times sort last; ties fall
 * back to the other timestamp, then slug, so the order is stable.
 */
export function compareByRecency(a: FindingTimes, b: FindingTimes, sort: Exclude<FindingsSort, "severity">): number {
  const primary = sort === "newest" ? "created_at" : "changed_at";
  const secondary = sort === "newest" ? "changed_at" : "created_at";
  return compareDesc(a[primary], b[primary]) || compareDesc(a[secondary], b[secondary]) || a.slug.localeCompare(b.slug);
}

function compareDesc(a: string | null | undefined, b: string | null | undefined): number {
  const ta = serverTimeMs(a);
  const tb = serverTimeMs(b);
  if (ta == null || tb == null) return ta == null ? (tb == null ? 0 : 1) : -1;
  return tb - ta;
}

// ── "Since my last visit" ────────────────────────────────────────────────
//
// The last-visit mark is per engagement and per browser (localStorage). It is
// the newest ledger time — creation or change, in SERVER time, so browser
// clock skew cannot hide anything — that was on screen once the Findings page
// had shown the loaded ledger for LAST_VISIT_DWELL_MS. Leaving sooner leaves
// the mark where it was; findings that arrive later in the same visit stay
// "new" for the next one. The page reads the mark once when it opens, so the
// filter does not shift while the operator works through it. Storage can be
// absent or throw (private windows, blocked site data): reads then report no
// earlier visit and writes are skipped.

export const LAST_VISIT_DWELL_MS = 10_000;

function lastVisitKey(engagementKey: string): string {
  return `findings.lastVisit.${engagementKey}`;
}

export function readLastVisit(engagementKey: string, storage?: Storage | null): number | null {
  try {
    const raw = (storage === undefined ? window.localStorage : storage)?.getItem(lastVisitKey(engagementKey));
    if (!raw) return null;
    const value = Number(raw);
    return Number.isFinite(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

export function writeLastVisit(engagementKey: string, markMs: number, storage?: Storage | null): void {
  if (!Number.isFinite(markMs) || markMs <= 0) return;
  try {
    (storage === undefined ? window.localStorage : storage)?.setItem(lastVisitKey(engagementKey), String(markMs));
  } catch {
    // Storage unavailable: the next visit simply has no earlier mark.
  }
}

/** Newest creation-or-change time across the ledger, or null when none parse. */
export function newestLedgerTime(items: readonly FindingTimes[]): number | null {
  let newest: number | null = null;
  for (const item of items) {
    for (const value of [item.created_at, item.changed_at]) {
      const time = serverTimeMs(value);
      if (time != null && (newest == null || time > newest)) newest = time;
    }
  }
  return newest;
}
