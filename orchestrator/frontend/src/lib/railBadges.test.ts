import assert from "node:assert/strict";
import test from "node:test";

import { railBadges } from "./railBadges.ts";

const summary = {
  finding_count: 42,
  open_surface_count: 17,
  coverage_statuses: { blocked: 1200, covered: 300, deferred: 25, not_applicable: 4, pending: 210, queued: 6 },
};

test("counts only what needs action, with the unit in the text", () => {
  const badges = railBadges({
    summary,
    proofNeedsAttention: 17,
    submissionsToDo: 8,
    openIntelLeads: 12,
    codeQueue: { pending: 40, processing: 2, error: 1, needs_context: 2 },
    runHealth: { attention: 4, failed: 2 },
    oastCallbacksToReview: 3,
  });
  assert.deepEqual(Object.fromEntries(Object.entries(badges).map(([key, badge]) => [key, badge?.text])), {
    findings: "42 current",
    proof: "17 attention",
    submissions: "8 attention",
    intel: "12 open",
    surfaces: "17 open",
    coverage: "1,441 open",
    code: "45 open",
    runs: "6 attention",
    oast: "3 attention",
  });
  for (const badge of Object.values(badges)) {
    assert.ok(badge && badge.label.length > badge.text.length, "every badge carries a full accessible sentence");
  }
  assert.match(badges.coverage?.label ?? "", /blocked, deferred, pending, or queued/);
});

test("shows no badge for zero, missing, or inapplicable inputs", () => {
  const badges = railBadges({
    summary: { finding_count: 0, open_surface_count: 0, coverage_statuses: { covered: 10, not_applicable: 2 } },
    proofNeedsAttention: 0,
    submissionsToDo: 0,
    openIntelLeads: null,
    codeQueue: { pending: 0, processing: 0, error: 0, needs_context: 0 },
    runHealth: null,
    oastCallbacksToReview: 0,
  });
  assert.deepEqual(badges, {});
});

test("labels loaded counts as loaded while the summary is unavailable", () => {
  const badges = railBadges({ summary: null, loadedFindingCount: 1, loadedSurfaceCount: 4 });
  assert.equal(badges.findings?.text, "1 loaded");
  assert.match(badges.findings?.label ?? "", /current count unavailable/);
  assert.equal(badges.surfaces?.text, "4 loaded");
  assert.equal(badges.coverage, undefined);
});

test("uses singular wording for one item", () => {
  const badges = railBadges({ summary: null, oastCallbacksToReview: 1, openIntelLeads: 1 });
  assert.equal(badges.oast?.label, "1 OAST probe has callbacks to review");
  assert.equal(badges.intel?.label, "1 open intel lead");
});

test("proof and run badges follow the same attention rules as their pages", () => {
  const badges = railBadges({
    summary: null,
    proofNeedsAttention: 3,
    runHealth: { healthy: 9, running: 2, attention: 1, failed: 3 },
  });
  assert.equal(badges.proof?.text, "3 attention");
  assert.match(badges.proof?.label ?? "", /^3 findings need attention: .*stale/);
  assert.equal(badges.runs?.text, "4 attention");
});

test("action queues read \"attention\", open-work views \"open\", and Findings \"current\"", () => {
  const badges = railBadges({
    summary: { finding_count: 4, open_surface_count: 2, coverage_statuses: { pending: 6 } },
    proofNeedsAttention: 1,
    submissionsToDo: 2,
    openIntelLeads: 3,
    codeQueue: { pending: 1, processing: 0, error: 0, needs_context: 0 },
    runHealth: { failed: 1 },
    commandsNeedingAttention: 2,
    oastCallbacksToReview: 1,
  });
  const words = Object.fromEntries(Object.entries(badges).map(([key, badge]) => [key, badge?.text.replace(/^[\d,]+ /, "")]));
  assert.deepEqual(words, {
    findings: "current",
    proof: "attention",
    submissions: "attention",
    intel: "open",
    surfaces: "open",
    coverage: "open",
    code: "open",
    runs: "attention",
    commands: "attention",
    oast: "attention",
  });
});

test("badges command runs that need attention", () => {
  const badges = railBadges({ summary: null, commandsNeedingAttention: 4321 });
  assert.equal(badges.commands?.text, "4,321 attention");
  assert.equal(badges.commands?.label, "4,321 command runs need attention");
  assert.equal(railBadges({ summary: null, commandsNeedingAttention: 1 }).commands?.label, "1 command run needs attention");
  assert.equal(railBadges({ summary: null, commandsNeedingAttention: 0 }).commands, undefined);
});
