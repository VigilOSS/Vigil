import assert from "node:assert/strict";
import test from "node:test";

import {
  compareByRecency,
  countRecency,
  findingChangedAt,
  matchesRecency,
  newestLedgerTime,
  readLastVisit,
  recencyKind,
  summarizeRecentChanges,
  writeLastVisit,
  type FindingTimes,
} from "./findingRecency.ts";

const NOW = Date.UTC(2026, 9, 20, 12, 0, 0);
const HOUR = 60 * 60 * 1000;

function at(msBeforeNow: number): string {
  // Zone-less database form, which is UTC.
  return new Date(NOW - msBeforeNow).toISOString().replace("T", " ").slice(0, 19);
}

const freshlyRecorded: FindingTimes = { slug: "VA-001", created_at: at(2 * HOUR), changed_at: at(1 * HOUR) };
const recentlyChanged: FindingTimes = { slug: "VA-002", created_at: at(10 * 24 * HOUR), changed_at: at(3 * HOUR) };
const changedThisWeek: FindingTimes = { slug: "VA-003", created_at: at(20 * 24 * HOUR), changed_at: at(3 * 24 * HOUR) };
const quiet: FindingTimes = { slug: "VA-004", created_at: at(30 * 24 * HOUR), changed_at: at(30 * 24 * HOUR) };
const undated: FindingTimes = { slug: "VA-005" };
const ledger = [freshlyRecorded, recentlyChanged, changedThisWeek, quiet, undated];

function matching(filter: Parameters<typeof matchesRecency>[1], lastVisit: number | null = null): string[] {
  return ledger.filter((item) => matchesRecency(item, filter, NOW, lastVisit)).map((item) => item.slug);
}

test("changed time is the last ledger change, falling back to creation, never updated_at", () => {
  assert.equal(findingChangedAt({ last_transition_at: "2026-10-20 10:00:00", created_at: "2026-10-01 10:00:00" }), "2026-10-20 10:00:00");
  assert.equal(findingChangedAt({ last_transition_at: null, created_at: "2026-10-01 10:00:00" }), "2026-10-01 10:00:00");
  assert.equal(findingChangedAt({ updated_at: "2026-10-20 10:00:00" } as never), "");
});

test("new and changed are disjoint so their counts add up", () => {
  assert.equal(recencyKind(freshlyRecorded, NOW - 24 * HOUR), "new");
  assert.equal(recencyKind(recentlyChanged, NOW - 24 * HOUR), "changed");
  assert.equal(recencyKind(quiet, NOW - 24 * HOUR), null);
  assert.equal(recencyKind(undated, NOW - 24 * HOUR), null);
});

test("window filters select by creation or by change within the window", () => {
  assert.deepEqual(matching("new24h"), ["VA-001"]);
  assert.deepEqual(matching("new7d"), ["VA-001"]);
  assert.deepEqual(matching("changed24h"), ["VA-002"]);
  assert.deepEqual(matching("changed7d"), ["VA-002", "VA-003"]);
  assert.deepEqual(matching(null), ledger.map((item) => item.slug));
});

test("since-last-visit covers new and changed entries strictly after the seen mark", () => {
  const mark = NOW - 3 * HOUR;
  assert.deepEqual(matching("sinceVisit", mark), ["VA-001"]);
  // The entry exactly at the mark is the one the operator already saw.
  const seenAtMark: FindingTimes = { slug: "VA-006", created_at: at(40 * HOUR), changed_at: at(3 * HOUR) };
  assert.equal(matchesRecency(seenAtMark, "sinceVisit", NOW, mark), false);
  assert.deepEqual(matching("sinceVisit", NOW - 4 * HOUR), ["VA-001", "VA-002"]);
  // With no earlier visit the filter cannot narrow anything.
  assert.deepEqual(matching("sinceVisit", null), ledger.map((item) => item.slug));
});

test("counts report every chip and leave since-last-visit at zero without a mark", () => {
  assert.deepEqual(countRecency(ledger, NOW, null), { new24h: 1, new7d: 1, changed24h: 1, changed7d: 2, sinceVisit: 0 });
  assert.equal(countRecency(ledger, NOW, NOW - 4 * HOUR).sinceVisit, 2);
});

test("the recent-changes summary uses the visit mark, or the last 24 hours on a first visit", () => {
  assert.deepEqual(summarizeRecentChanges(ledger, NOW, null), { created: 1, changed: 1, sinceVisit: false, filter: null });
  assert.deepEqual(summarizeRecentChanges(ledger, NOW, NOW - 4 * 24 * HOUR), { created: 1, changed: 2, sinceVisit: true, filter: "sinceVisit" });
  // Nothing after the mark: the newest entry is exactly the one already seen.
  assert.deepEqual(summarizeRecentChanges(ledger, NOW, NOW - HOUR), { created: 0, changed: 0, sinceVisit: true, filter: "sinceVisit" });
});

test("date sorts are descending, stable, and put undated findings last", () => {
  const newest = [...ledger].sort((a, b) => compareByRecency(a, b, "newest")).map((item) => item.slug);
  assert.deepEqual(newest, ["VA-001", "VA-002", "VA-003", "VA-004", "VA-005"]);
  const changed = [...ledger].sort((a, b) => compareByRecency(a, b, "changed")).map((item) => item.slug);
  assert.deepEqual(changed, ["VA-001", "VA-002", "VA-003", "VA-004", "VA-005"]);
  const tie = [{ slug: "VA-B", created_at: at(HOUR), changed_at: at(HOUR) }, { slug: "VA-A", created_at: at(HOUR), changed_at: at(HOUR) }];
  assert.deepEqual(tie.sort((a, b) => compareByRecency(a, b, "changed")).map((item) => item.slug), ["VA-A", "VA-B"]);
  // Mixed timestamp shapes order chronologically, not lexically.
  const mixed = [{ slug: "VA-Z", created_at: "2026-10-20 13:00:00" }, { slug: "VA-Y", created_at: "2026-10-20T13:30:00Z" }];
  assert.deepEqual(mixed.sort((a, b) => compareByRecency(a, b, "newest")).map((item) => item.slug), ["VA-Y", "VA-Z"]);
});

test("changed order differs from creation order when an old finding changed recently", () => {
  const old = { slug: "VA-OLD", created_at: at(40 * 24 * HOUR), changed_at: at(HOUR) };
  const fresh = { slug: "VA-NEW", created_at: at(2 * HOUR), changed_at: at(2 * HOUR) };
  assert.deepEqual([fresh, old].sort((a, b) => compareByRecency(a, b, "changed")).map((item) => item.slug), ["VA-OLD", "VA-NEW"]);
  assert.deepEqual([old, fresh].sort((a, b) => compareByRecency(a, b, "newest")).map((item) => item.slug), ["VA-NEW", "VA-OLD"]);
});

test("the newest ledger time is the latest creation or change across findings", () => {
  assert.equal(newestLedgerTime(ledger), NOW - HOUR);
  assert.equal(newestLedgerTime([undated]), null);
});

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, String(value)); },
  };
}

test("the last-visit mark round-trips per engagement", () => {
  const storage = memoryStorage();
  assert.equal(readLastVisit("acme-web", storage), null);
  writeLastVisit("acme-web", NOW, storage);
  assert.equal(readLastVisit("acme-web", storage), NOW);
  assert.equal(readLastVisit("acme-api", storage), null);
});

test("unreadable, corrupt, or absent storage means no earlier visit and never throws", () => {
  const throwing = {
    getItem: () => { throw new Error("SecurityError"); },
    setItem: () => { throw new Error("QuotaExceededError"); },
  } as unknown as Storage;
  assert.equal(readLastVisit("acme-web", throwing), null);
  assert.doesNotThrow(() => writeLastVisit("acme-web", NOW, throwing));
  assert.equal(readLastVisit("acme-web", null), null);
  assert.doesNotThrow(() => writeLastVisit("acme-web", NOW, null));
  const corrupt = memoryStorage();
  corrupt.setItem("findings.lastVisit.acme-web", "yesterday");
  assert.equal(readLastVisit("acme-web", corrupt), null);
  writeLastVisit("acme-web", Number.NaN, corrupt);
  assert.equal(corrupt.getItem("findings.lastVisit.acme-web"), "yesterday");
});
