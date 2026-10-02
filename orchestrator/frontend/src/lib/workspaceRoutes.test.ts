import assert from "node:assert/strict";
import test from "node:test";
import { engagementHref, parseWorkspaceRoute, positiveRouteId, remediationHref } from "./workspaceRoutes.ts";

test("canonical links round-trip encoded record identities without query ambiguity", () => {
  const key = "repo /?# Ω";
  const slug = "claim&other=2";
  const route = parseWorkspaceRoute(engagementHref(key, { tab: "findings", finding: slug, dtab: "history" }));
  assert.equal(route.kind, "engagement");
  if (route.kind !== "engagement") assert.fail("Expected engagement");
  assert.equal(route.key, key);
  assert.equal(route.params.get("finding"), slug);
  assert.equal(route.params.get("dtab"), "history");
  assert.equal(engagementHref(key, { tab: "overview", finding: undefined }), `#/engagements/${encodeURIComponent(key)}`);
  const caseRoute = parseWorkspaceRoute(remediationHref(key, 7));
  assert.equal(caseRoute.kind, "remediation");
  if (caseRoute.kind !== "remediation") assert.fail("Expected remediation");
  assert.equal(positiveRouteId(caseRoute.params, "case"), 7);
});

test("malformed routes and noncanonical numeric identities cannot select a rounded record", () => {
  for (const hash of ["#/engagements/%E0%A4%A", "#/unknown/workspace", "#/remediation/", "#/engagements/%20"]) {
    assert.deepEqual(parseWorkspaceRoute(hash), { kind: "invalid" });
  }
  for (const value of ["", "-1", "1.5", "NaN", "9007199254740993"]) {
    assert.equal(positiveRouteId(new URLSearchParams({ id: value }), "id"), undefined);
  }
});
