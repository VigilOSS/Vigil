import assert from "node:assert/strict";
import test from "node:test";

import type { OobInteraction } from "./api.ts";
import {
  callbackHistogram,
  canRecordVerdict,
  countCallbacksToReview,
  groupCallbacks,
  isPrivateAddress,
  linkedToParts,
  sortByLastHit,
} from "./oastApi.ts";

function hit(id: number, protocol: string, query_type: string, observed_at: string): OobInteraction {
  return {
    id,
    engagement_id: 1,
    probe_id: 1,
    protocol,
    remote_address: "198.51.100.7",
    query_type,
    raw_request: "",
    interaction_hash: `h${id}`,
    observed_at,
    created_at: observed_at,
  };
}

test("counts only fired probes as callbacks to review", () => {
  assert.equal(countCallbacksToReview([
    { status: "fired" }, { status: "FIRED" }, { status: "pending" }, { status: "expired" }, { status: "" },
  ]), 2);
});

test("orders by last callback across mixed timestamp formats, missing last", () => {
  const rows = sortByLastHit([
    { last_interaction_at: "", created_at: "2026-09-12 09:00:00" },
    { last_interaction_at: "2026-09-12 05:00:00", created_at: "2026-09-12 01:00:00" },
    { last_interaction_at: "2026-09-12T06:00:00Z", created_at: "2026-09-12 01:00:00" },
  ]);
  assert.deepEqual(rows.map((row) => row.last_interaction_at), ["2026-09-12T06:00:00Z", "2026-09-12 05:00:00", ""]);
});

test("links a probe to target, parameter, and technique, skipping blanks", () => {
  assert.deepEqual(linkedToParts({ target_url: "https://acme.example/hook", param: " url ", technique: "ssrf" }),
    ["https://acme.example/hook", "url", "ssrf"]);
  assert.deepEqual(linkedToParts({ target_url: "", param: "", technique: "xxe" }), ["xxe"]);
  assert.deepEqual(linkedToParts({ target_url: "", param: " ", technique: "" }), []);
});

test("classifies private and public callback addresses", () => {
  const cases: Array<[string, boolean]> = [
    ["172.17.0.2", true],
    ["10.0.0.5", true],
    ["192.168.1.20:5353", true],
    ["127.0.0.1", true],
    ["100.64.3.1", true],
    ["169.254.1.1", true],
    ["fd12:3456::1", true],
    ["[fe80::1]:53", true],
    ["::1", true],
    ["172.32.0.1", false],
    ["198.51.100.7", false],
    ["2001:db8::5", false],
    ["", false],
  ];
  for (const [address, expected] of cases) {
    assert.equal(isPrivateAddress(address), expected, address);
  }
});

test("groups callbacks by protocol and query type, largest first", () => {
  const groups = groupCallbacks([
    hit(1, "dns", "A", "2026-09-12 05:00:00"),
    hit(2, "DNS", "a", "2026-09-12 05:01:00"),
    hit(3, "dns", "AAAA", "2026-09-12 05:02:00"),
    hit(4, "http", "", "2026-09-12 05:03:00"),
  ]);
  assert.deepEqual(groups.map(({ protocol, queryType, count }) => [protocol, queryType, count]), [
    ["dns", "A", 2], ["dns", "AAAA", 1], ["http", "", 1],
  ]);
});

test("buckets callbacks evenly between the first and last one", () => {
  const buckets = callbackHistogram([
    hit(1, "dns", "A", "2026-09-12 05:00:00"),
    hit(2, "dns", "A", "2026-09-12T05:00:30Z"),
    hit(3, "dns", "A", "2026-09-12 05:10:00"),
  ], 10);
  assert.equal(buckets.length, 10);
  assert.equal(buckets[0].count, 2);
  assert.equal(buckets[9].count, 1);
  assert.equal(buckets.reduce((sum, bucket) => sum + bucket.count, 0), 3);
});

test("only a probe that called back takes an operator verdict", () => {
  assert.deepEqual(
    ["fired", "confirmed", "ignored", "pending", "expired", ""].map((status) => canRecordVerdict({ status })),
    [true, true, true, false, false, false],
  );
});
