import assert from "node:assert/strict";
import test from "node:test";

import {
  appendAuditPage,
  auditUiReducer,
  blockerDestination,
  chooseRunSelection,
  collectBarePages,
  dispatchProvenance,
  initialAuditUiState,
  lifecyclePresentation,
  normalizedComparison,
  parseRunAuditQuery,
} from "./runAudit.ts";

test("drill-down selection is an explicit reducer transition", () => {
  const selected = auditUiReducer(initialAuditUiState, {
    type: "select-section",
    section: "dispatches",
  });
  assert.equal(selected.section, "dispatches");

  assert.deepEqual(
    parseRunAuditQuery(new URLSearchParams("run=7&section=dispatches&object=12")),
    { runId: 7, section: "dispatches", object: "12" },
  );
  assert.deepEqual(
    parseRunAuditQuery(new URLSearchParams("run=7&section=observed-events")),
    { runId: 7, section: "observed-events", object: undefined },
  );
  for (const section of ["tool-signals", "discovery-passes", "code-receipts"]) {
    assert.deepEqual(
      parseRunAuditQuery(new URLSearchParams(`run=7&section=${section}&object=12`)),
      { runId: 7, section, object: "12" },
    );
  }
});

test("paged drill-down rows append exactly once and preserve server continuation", () => {
  const first = appendAuditPage([], {
    items: [{ id: 1 }, { id: 2 }],
    total: 3,
    offset: 0,
    limit: 2,
    has_more: true,
  });
  assert.deepEqual(first.items.map((row) => row.id), [1, 2]);
  assert.equal(first.nextOffset, 2);
  assert.equal(first.hasMore, true);

  const complete = appendAuditPage(first.items, {
    items: [{ id: 2 }, { id: 3 }],
    total: 3,
    offset: 2,
    limit: 2,
    has_more: false,
  });
  assert.deepEqual(complete.items.map((row) => row.id), [1, 2, 3]);
  assert.equal(complete.nextOffset, 4);
  assert.equal(complete.hasMore, false);

  const inconsistent = appendAuditPage(complete.items, {
    items: [],
    total: 4,
    offset: 3,
    limit: 2,
    has_more: true,
  });
  assert.equal(inconsistent.hasMore, false);
});

test("bounded run-list traversal advances to EOF", async () => {
  const offsets: number[] = [];
  const items = await collectBarePages(async (offset, limit) => {
    offsets.push(offset);
    return [0, 1, 2, 3, 4].slice(offset, offset + limit).map((id) => ({ id }));
  }, 2);

  assert.deepEqual(offsets, [0, 2, 4]);
  assert.deepEqual(items.map((item) => item.id), [0, 1, 2, 3, 4]);

  await assert.rejects(
    () => collectBarePages(async () => [{ id: 1 }, { id: 2 }], 2, 2),
    /did not reach EOF after 2 pages/,
  );
});

test("a current user selection survives refresh over the initial deep link", () => {
  assert.equal(chooseRunSelection([41, 42, 43], 42, 41), 42);
  assert.equal(chooseRunSelection([41, 42, 43], 99, 41), 41);
  assert.equal(chooseRunSelection([42, 43], 99, 41), 42);
  assert.equal(chooseRunSelection([], 99, 41), null);
});

test("blockers deep-link to findings and run-owned corrective objects", () => {
  assert.equal(
    blockerDestination("engagement / one", 41, {
      object_type: "finding",
      object_id: "VA-019",
      code: "finding_unverified",
      message: "Finding requires independent verification",
      action: "verify finding",
    }),
    "#/engagements/engagement%20%2F%20one?tab=findings&finding=VA-019",
  );
  assert.equal(
    blockerDestination("engagement", 41, {
      object_type: "command-run",
      object_id: 22,
      code: "command_evidence_missing",
      message: "Command evidence is missing",
      action: "inspect the recorded execution",
    }),
    "#/engagements/engagement?tab=runs&run=41&section=commands",
  );
  assert.equal(
    blockerDestination("engagement", 41, {
      object_type: "obligation",
      object_id: 9,
      code: "open_hard_obligation",
      message: "Repository source review remains open",
      action: "close obligation",
    }),
    "#/engagements/engagement?tab=runs&run=41&section=obligations&object=9",
  );
  assert.equal(
    blockerDestination("engagement", 41, {
      object_type: "proof_receipts",
      object_id: 41,
      code: "proof_stale",
      message: "One proof receipt is stale",
      action: "restore or replace the proof",
    }),
    "#/engagements/engagement?tab=runs&run=41&section=proof-receipts",
  );
  assert.equal(
    blockerDestination("engagement", 41, {
      object_type: "sources",
      object_id: 41,
      code: "inventory_missing",
      message: "Scan has no source inventory",
      action: "publish source inventory",
    }),
    "#/engagements/engagement?tab=runs&run=41&section=sources",
  );

  const destination = blockerDestination("engagement", 41, {
    object_type: "candidate",
    object_id: 12,
    code: "unresolved_candidate",
    message: "Candidate remains open",
    action: "record a supported disposition",
  });
  assert.deepEqual(
    parseRunAuditQuery(new URLSearchParams(destination.split("?")[1])),
    { runId: 41, section: "candidates", object: "12" },
  );
  for (const objectType of ["discovery_pass", "discovery_passes"]) {
    const discoveryDestination = blockerDestination("engagement", 41, {
      object_type: objectType,
      object_id: 17,
      code: "discovery_terminal_missing",
      message: "Discovery has not reached a supported terminal outcome",
      action: "record the next attributed discovery pass",
    });
    assert.deepEqual(
      parseRunAuditQuery(new URLSearchParams(discoveryDestination.split("?")[1])),
      { runId: 41, section: "discovery-passes", object: "17" },
      objectType,
    );
  }
});

test("comparison presentation retains all deterministic classifications", () => {
  const groups = normalizedComparison({
    run_id: 8,
    baseline_run_id: 3,
    target_compatible: true,
    source_compatible: false,
    deterministic: true,
    classifications: {
      new: ["new-a"],
      persisting: ["same-a"],
      resolved: [],
      unknown: ["old-a", "old-b"],
    },
  });

  assert.deepEqual(groups.map((group) => [group.key, group.items.length]), [
    ["new", 1],
    ["persisting", 1],
    ["resolved", 0],
    ["unknown", 2],
  ]);
  assert.equal(groups.at(-1)?.items[1], "old-b");
});

test("lifecycle presentation preserves every recorded transition in order", () => {
  const rows = lifecyclePresentation([
    { id: 3, from_status: null, to_status: "queued", created_at: "2026-09-09T10:00:00Z" },
    { id: 8, from_status: "queued", to_status: "running", created_at: "2026-09-09T10:01:00Z" },
    { id: 13, from_status: "running", to_status: "partial", reason: "open obligation" },
  ]);

  assert.deepEqual(rows.map((row) => row.transition), [
    "created → queued",
    "queued → running",
    "running → partial",
  ]);
  assert.deepEqual(rows.map((row) => row.key), ["event-3", "event-8", "event-13"]);
  assert.equal(rows[2].event.reason, "open obligation");
});

test("dispatch provenance presents requested and observed identities separately", () => {
  assert.deepEqual(dispatchProvenance({
    producer_dispatch_id: 17,
    producer_dispatch_agent_id: "VERIFY-1",
    producer_dispatch_agent_role: "code-vuln-verifier",
    requested_model: "gpt-5.6-sol",
    actual_model: "unknown",
    requested_reasoning: "xhigh",
    actual_reasoning: "unknown",
    client_name: "codex",
    requested_client: "claude",
    launcher_effective_client: "codex",
    provider_observed_client: "unknown",
    launcher_effective_model: "gpt-launcher-effective",
    launcher_effective_reasoning: "high",
    launcher_effective_source: "verified-test-launcher/v1",
    source_revision: "revision-123",
    operator_instruction_path: "AGENTS.md",
    operator_instruction_sha256: "a".repeat(64),
    specialist_instruction_path: ".codex/agents/code-vuln-verifier.toml",
    specialist_instruction_sha256: "b".repeat(64),
    instruction_identity_status: "stale",
    instructions_stale: true,
  }), {
    dispatch_id: 17,
    agent_id: "VERIFY-1",
    agent_role: "code-vuln-verifier",
    requested_model: "gpt-5.6-sol",
    observed_model: "unknown",
    requested_reasoning: "xhigh",
    observed_reasoning: "unknown",
    requested_client: "claude",
    launcher_effective_client: "codex",
    provider_observed_client: "unknown",
    launcher_effective_model: "gpt-launcher-effective",
    launcher_effective_reasoning: "high",
    launcher_effective_source: "verified-test-launcher/v1",
    client_name_compatibility_projection: "codex",
    source_revision: "revision-123",
    operator_instruction: { path: "AGENTS.md", sha256: "a".repeat(64) },
    specialist_instruction: {
      path: ".codex/agents/code-vuln-verifier.toml",
      sha256: "b".repeat(64),
    },
    instruction_identity_status: "stale",
    instructions_stale: true,
  });
});

test("terminal dispatch provenance comes from the immutable seal", () => {
  assert.deepEqual(dispatchProvenance({
    producer_dispatch_id: 17,
    producer_dispatch_agent_id: "MUTATED",
    actual_model: "later-model",
    seal: {
      dispatch_provenance: {
        dispatch_id: 17,
        agent_id: "VERIFY-1",
        agent_role: "code-vuln-verifier",
        requested_model: "gpt-5.6-sol",
        actual_model: "observed-at-seal",
        requested_reasoning: "xhigh",
        actual_reasoning: "high",
        client_name: "codex",
        requested_client: "claude",
        launcher_effective_client: "codex",
        provider_observed_client: "unknown",
        launcher_effective_model: "gpt-launcher-effective",
        launcher_effective_reasoning: "high",
        launcher_effective_source: "verified-test-launcher/v1",
        source_revision: "revision-123",
        operator_instruction_path: "AGENTS.md",
        operator_instruction_sha256: "a".repeat(64),
        specialist_instruction_path: ".codex/agents/code-vuln-verifier.toml",
        specialist_instruction_sha256: "b".repeat(64),
        instruction_identity_status: "verified",
        instructions_stale: false,
      },
    },
  }), {
    dispatch_id: 17,
    agent_id: "VERIFY-1",
    agent_role: "code-vuln-verifier",
    requested_model: "gpt-5.6-sol",
    observed_model: "observed-at-seal",
    requested_reasoning: "xhigh",
    observed_reasoning: "high",
    requested_client: "claude",
    launcher_effective_client: "codex",
    provider_observed_client: "unknown",
    launcher_effective_model: "gpt-launcher-effective",
    launcher_effective_reasoning: "high",
    launcher_effective_source: "verified-test-launcher/v1",
    client_name_compatibility_projection: "codex",
    source_revision: "revision-123",
    operator_instruction: { path: "AGENTS.md", sha256: "a".repeat(64) },
    specialist_instruction: {
      path: ".codex/agents/code-vuln-verifier.toml",
      sha256: "b".repeat(64),
    },
    instruction_identity_status: "verified",
    instructions_stale: false,
  });
});

test("legacy sealed client name remains an explicit effective-client projection", () => {
  const provenance = dispatchProvenance({
    seal: {
      dispatch_provenance: {
        dispatch_id: 19,
        agent_id: "LEGACY-1",
        agent_role: "recon-specialist",
        client_name: "codex",
      },
    },
  });

  assert.equal(provenance.requested_client, "unknown");
  assert.equal(provenance.launcher_effective_client, "codex");
  assert.equal(provenance.provider_observed_client, "unknown");
  assert.equal(provenance.launcher_effective_model, null);
  assert.equal(provenance.launcher_effective_reasoning, null);
  assert.equal(provenance.launcher_effective_source, null);
  assert.equal(provenance.client_name_compatibility_projection, "codex");
});
