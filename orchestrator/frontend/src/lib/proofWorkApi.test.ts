import assert from "node:assert/strict";
import test from "node:test";

import type { ProofOwedEntry, ProofReverification, ProofWorkQueueState } from "./api.ts";
import { proofNeedsAttentionCount } from "./proofWorkApi.ts";

const owed = (slug: string, queue_state: ProofWorkQueueState, work_ids: number[] = []): ProofOwedEntry => ({
  finding_slug: slug,
  finding_id: work_ids[0] ?? 0,
  title: `Acme ${slug}`,
  canonical_location: "https://app.example.com/",
  work_ids,
  queue_state,
  next_test: null,
});

const reverify = (slug: string): ProofReverification => ({
  finding_slug: slug,
  finding_id: 99,
  invalidating_transition_id: 7,
  next_action: "Re-verify the finding.",
  work_ids: [],
});

test("counts each parked finding that needs the operator once, however many work items it holds", () => {
  const count = proofNeedsAttentionCount({
    owed: [
      owed("VA-001", "needs_approval", [11, 12, 13]),
      owed("VA-002", "blocked", [21]),
      owed("VA-003", "stale", [31, 32]),
      owed("VA-004", "unprepared"),
      owed("VA-005", "ready", [51]),
      owed("VA-006", "in_progress", [61]),
    ],
    reverification_required: [reverify("VA-007"), reverify("VA-008")],
  });

  assert.equal(count, 6);
});

test("is zero when every parked finding waits on a verifier", () => {
  assert.equal(proofNeedsAttentionCount({ owed: [owed("VA-001", "ready", [1]), owed("VA-002", "in_progress", [2])], reverification_required: [] }), 0);
});
