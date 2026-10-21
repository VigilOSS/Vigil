import assert from "node:assert/strict";
import test from "node:test";

import { ALL_LIVE_SCOPES, INITIAL_SCOPE_VERSIONS, bumpScopes, scopeVersion, scopesForMessage } from "./liveScopes.ts";

test("an activity note refreshes only the activity record", () => {
  assert.deepEqual(scopesForMessage({ type: "activity.updated", record_type: "activity_entry" }), ["activity"]);
});

test("a finding change refreshes the finding views and badges but not the execution ledgers", () => {
  const scopes = scopesForMessage({ type: "assessment.updated", record_type: "finding_patch" });
  for (const scope of ["findings", "submissions", "proof", "readiness", "summary", "activity"] as const) {
    assert.ok(scopes.includes(scope), scope);
  }
  for (const scope of ["commands", "oast", "http", "intel", "code", "files"] as const) {
    assert.ok(!scopes.includes(scope), scope);
  }
});

test("high-volume execution records stay in their own views", () => {
  assert.deepEqual(scopesForMessage({ type: "assessment.updated", record_type: "command_run" }), ["commands", "activity"]);
  assert.deepEqual(scopesForMessage({ type: "assessment.updated", record_type: "oob_probe" }), ["oast", "activity"]);
  assert.deepEqual(scopesForMessage({ type: "code_analysis.updated", record_type: "queue_heartbeat" }), ["code", "activity"]);
  assert.ok(!scopesForMessage({ type: "assessment.updated", record_type: "request_observation_bulk" }).includes("findings"));
});

test("bulk and import announcements refresh what their single-record forms do", () => {
  const scopes = (record_type: string) => scopesForMessage({ type: "assessment.updated", record_type });
  assert.deepEqual(scopes("artifact_bulk"), scopes("artifact"));
  assert.deepEqual(scopes("http_flow_import"), scopes("http_flow"));
});

test("credential, access, capture-policy and checkpoint records refresh only the views that read them", () => {
  const scopes = (record_type: string) => scopesForMessage({ type: "assessment.updated", record_type });
  assert.deepEqual(scopes("credential"), ["intel", "summary", "activity"]);
  assert.deepEqual(scopes("access_record"), ["summary", "activity"]);
  // No view re-reads credential tests, operator checkpoints or the capture policy; the audit log records them.
  assert.deepEqual(scopes("capture_policy"), ["activity"]);
  assert.deepEqual(scopes("credential_test"), ["activity"]);
  assert.deepEqual(scopes("operator_checkpoint"), ["activity"]);
});

test("an unknown message refreshes everything rather than leaving a view stale", () => {
  assert.deepEqual(scopesForMessage({ type: "assessment.updated", record_type: "unannounced_record" }), [...ALL_LIVE_SCOPES]);
  assert.deepEqual(scopesForMessage({ type: "engagement.archived" }), [...ALL_LIVE_SCOPES]);
  assert.deepEqual(scopesForMessage(null), [...ALL_LIVE_SCOPES]);
});

test("a reader's counter moves exactly when one of its scopes is refreshed", () => {
  const before = INITIAL_SCOPE_VERSIONS;
  const afterNote = bumpScopes(before, ["activity"]);
  assert.equal(scopeVersion(afterNote, ["findings", "proof"]), scopeVersion(before, ["findings", "proof"]));
  assert.equal(scopeVersion(afterNote, ["activity"]), 1);
  const afterFinding = bumpScopes(afterNote, ["findings", "proof"]);
  assert.equal(scopeVersion(afterFinding, ["findings", "proof"]), 2);
  assert.equal(scopeVersion(afterFinding, ["activity"]), 1);
  const afterEverything = bumpScopes(afterFinding, ALL_LIVE_SCOPES);
  for (const scope of ALL_LIVE_SCOPES) assert.equal(afterEverything[scope], 3);
});
