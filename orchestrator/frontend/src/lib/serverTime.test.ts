import assert from "node:assert/strict";
import test from "node:test";

import {
  compareServerTime,
  formatAbsoluteTime,
  formatAge,
  formatDuration,
  formatRelativeTime,
  gridTimeComparator,
  gridTimeMode,
  parseServerTime,
  serverTimeMs,
} from "./serverTime.ts";

const UTC_14_07_07 = Date.UTC(2026, 9, 20, 14, 7, 7);

test("zone-less database timestamps are UTC, not local wall-clock time", () => {
  assert.equal(parseServerTime("2026-10-20 14:07:07")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20T14:07:07")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20 14:07")?.getTime(), Date.UTC(2026, 9, 20, 14, 7));
  assert.equal(
    parseServerTime("2026-10-20 14:07:07.129343")?.getTime(),
    UTC_14_07_07 + 129,
  );
  assert.equal(parseServerTime("2026-10-20")?.getTime(), Date.UTC(2026, 9, 20));
});

test("explicit UTC and offset timestamps keep their declared zone", () => {
  assert.equal(parseServerTime("2026-10-20T14:07:07Z")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20T14:07:07.129343Z")?.getTime(), UTC_14_07_07 + 129);
  assert.equal(parseServerTime("2026-10-20 14:07:07z")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20T10:07:07-04:00")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20T19:37:07+0530")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("2026-10-20T14:07:07+00:00")?.getTime(), UTC_14_07_07);
  assert.equal(parseServerTime("  2026-10-20T14:07:07Z  ")?.getTime(), UTC_14_07_07);
});

test("missing, garbage, and impossible calendar values are rejected", () => {
  for (const value of [null, undefined, "", "   ", "unknown", "pending", "14:07:07",
    "2026-13-01 00:00:00", "2026-02-30 00:00:00", "2026-10-20 24:00:00",
    "2026-10-20 14:60:00", "2026-10-20T14:07:07+25:00", "Tue, 20 Oct 2026 14:07:07 GMT",
    "1792505227000"]) {
    assert.equal(parseServerTime(value), null, `expected null for ${JSON.stringify(value)}`);
    assert.equal(serverTimeMs(value), null);
  }
});

test("relative time measures true elapsed time and clamps future skew", () => {
  const now = UTC_14_07_07;
  assert.equal(formatRelativeTime("2026-10-20 14:07:07", now), "just now");
  assert.equal(formatRelativeTime("2026-10-20 14:06:40", now), "27s ago");
  assert.equal(formatRelativeTime("2026-10-20 14:05:08", now), "1m ago");
  assert.equal(formatRelativeTime("2026-10-20 13:07:08", now), "59m ago");
  assert.equal(formatRelativeTime("2026-10-20T10:07:07Z", now), "4h ago");
  assert.equal(formatRelativeTime("2026-10-17 14:07:07", now), "3d ago");
  assert.equal(formatRelativeTime("2026-09-21 14:07:08", now), "28d ago");
  assert.equal(formatRelativeTime("2026-08-04 09:00:00", now), "2026-08-04");
  assert.equal(formatRelativeTime("2026-10-20 18:07:07", now), "just now");
  assert.equal(formatRelativeTime("garbage", now), "");
  assert.equal(formatRelativeTime(null, now), "");
});

test("age keeps counting past the relative window instead of switching to a date", () => {
  const now = Date.UTC(2026, 9, 20, 18, 7, 7);
  assert.equal(formatAge("2026-10-20T14:07:07Z", now), "4h ago");
  assert.equal(formatAge("2026-09-21 18:07:08", now), "28d ago");
  assert.equal(formatAge("2026-09-05 23:56:32", now), "1mo ago");
  assert.equal(formatAge("2026-07-16 22:02:42", now), "3mo ago");
  assert.equal(formatAge("2025-10-19 18:07:07", now), "1y ago");
  assert.equal(formatAge("2023-01-01 00:00:00", now), "3y ago");
  assert.equal(formatAge("garbage", now), "");
});

test("absolute time is labelled UTC and preserves unparseable source text", () => {
  assert.equal(formatAbsoluteTime("2026-10-20 14:07:07"), "2026-10-20 14:07 UTC");
  assert.equal(formatAbsoluteTime("2026-10-20T10:07:07-04:00", "second"), "2026-10-20 14:07:07 UTC");
  assert.equal(
    formatAbsoluteTime("2026-10-20T14:07:07.129343Z", "millisecond"),
    "2026-10-20 14:07:07.129 UTC",
  );
  assert.equal(formatAbsoluteTime("not recorded yet"), "not recorded yet");
  assert.equal(formatAbsoluteTime(undefined), "");
});

test("comparison orders mixed formats chronologically with missing values last", () => {
  const values = [
    "2026-10-20T14:07:08Z",
    "",
    "2026-10-20 14:07:07",
    "garbage",
    "2026-10-20T10:07:09-04:00",
  ];
  assert.deepEqual([...values].sort(compareServerTime), [
    "2026-10-20 14:07:07",
    "2026-10-20T14:07:08Z",
    "2026-10-20T10:07:09-04:00",
    "",
    "garbage",
  ]);
  assert.deepEqual([...values].sort((a, b) => compareServerTime(a, b, "desc")), [
    "2026-10-20T10:07:09-04:00",
    "2026-10-20T14:07:08Z",
    "2026-10-20 14:07:07",
    "",
    "garbage",
  ]);
});

test("grid times keep the time of day once a relative age would show only a date", () => {
  const now = Date.parse("2026-10-20T12:00:00Z");
  assert.equal(gridTimeMode("2026-10-20 09:00:00", now), "relative");
  assert.equal(gridTimeMode("2026-07-16 22:02:42", now), "absolute");
});

test("durations read compactly and show a dash when nothing was measured", () => {
  assert.equal(formatDuration(0), "—");
  assert.equal(formatDuration(null), "—");
  assert.equal(formatDuration(412), "412ms");
  assert.equal(formatDuration(7287), "7.3s");
  assert.equal(formatDuration(33_000), "33s");
  assert.equal(formatDuration(33_500), "33.5s");
  assert.equal(formatDuration(125_000), "2m 5s");
  assert.equal(formatDuration(7_260_000), "2h 1m");
});

test("durations carry rounding into the next unit", () => {
  assert.equal(formatDuration(119_600), "2m 0s");
  assert.equal(formatDuration(59_960), "1m 0s");
  assert.equal(formatDuration(59_940), "59.9s");
  assert.equal(formatDuration(3_599_700), "1h 0m");
  assert.equal(formatDuration(7_385_000), "2h 3m");
});

test("grid date columns sort missing times last in both directions", () => {
  const values = ["2026-10-20 09:00:00", null, "2026-10-21T08:00:00Z", "", "garbage", "2026-10-19 23:00:00"];
  // ag-grid passes isDescending and negates the comparator's result for a descending sort.
  const sorted = (descending: boolean) => [...values].sort((a, b) => {
    const result = gridTimeComparator(a, b, undefined, undefined, descending);
    return descending ? -result : result;
  });
  assert.deepEqual(sorted(false).slice(0, 3), ["2026-10-19 23:00:00", "2026-10-20 09:00:00", "2026-10-21T08:00:00Z"]);
  assert.deepEqual(sorted(true).slice(0, 3), ["2026-10-21T08:00:00Z", "2026-10-20 09:00:00", "2026-10-19 23:00:00"]);
  assert.deepEqual(new Set(sorted(false).slice(3)), new Set([null, "", "garbage"]));
  assert.deepEqual(new Set(sorted(true).slice(3)), new Set([null, "", "garbage"]));
});
