import assert from "node:assert/strict";
import test from "node:test";

import {
  appendAuditPage,
  blockerDestination,
  collectBarePages,
  currentBlockers,
  defaultSectionForRun,
  deriveRunRow,
  dispatchProvenance,
  elapsedLabel,
  EMPTY_RUN_FILTERS,
  evidenceMixLabel,
  facetCounts,
  filterRuns,
  isRunAuditSection,
  lifecyclePresentation,
  normalizedComparison,
  parseRunAuditQuery,
  runClientModel,
  runFindingLinks,
  invalidRunLink,
  parseRunsView,
  runFacetCounts,
  runHealth,
  serializeRunsView,
} from "./runAudit.ts";
import type { AssessmentRun } from "./api.ts";

test("run deep links parse every record section and default by run purpose", () => {
  assert.equal(defaultSectionForRun("proof"), "proof-receipts");
  assert.equal(defaultSectionForRun(undefined), "proof-receipts");
  assert.equal(defaultSectionForRun("scan"), "sources");
  assert.equal(isRunAuditSection("commands"), true);
  assert.equal(isRunAuditSection("Sources"), false);
  assert.deepEqual(parseRunAuditQuery(new URLSearchParams("run=7&section=unknown&object=12")), {
    runId: 7,
    section: undefined,
    object: undefined,
  });

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

test("an unsafe run ID cannot round into another audit identity", () => {
  assert.deepEqual(parseRunAuditQuery(new URLSearchParams("run=9007199254740993&section=proof-receipts&object=99")), {});
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

test("elapsed time treats zone-less database timestamps as UTC in any local zone", () => {
  const previousTz = process.env.TZ;
  process.env.TZ = "America/New_York";
  try {
    assert.equal(elapsedLabel("2026-10-20 14:00:00", "2026-10-20T14:04:12Z"), "4m 12s");
    assert.equal(elapsedLabel("2026-10-20 14:00:00", "2026-10-20 16:30:00"), "2h 30m");
    assert.equal(elapsedLabel("not recorded", "2026-10-20T14:04:12Z"), "Not observed");
  } finally {
    if (previousTz === undefined) delete process.env.TZ;
    else process.env.TZ = previousTz;
  }
});

function acmeRun(overrides: Partial<AssessmentRun> = {}): AssessmentRun {
  return {
    id: 7,
    run_uuid: "acme-export-replay",
    run_kind: "web",
    run_purpose: "proof",
    status: "completed",
    created_at: "2026-10-10 22:26:22",
    started_at: "2026-10-10 22:26:22",
    finished_at: "2026-10-10 22:27:10",
    elapsed_seconds: 48,
    producer_dispatch_agent_id: "acme-va-1",
    producer_dispatch_agent_role: "vulnerability-analyst",
    producer_dispatch_task: "Replay the Acme export across tenants",
    counts: { proof_receipts: 3 },
    proof_health: { healthy: 3, missing: 0, stale: 0, tombstoned: 0 },
    blockers: [],
    evidence_kind_counts: { artifact: 1, http_exchange: 2 },
    ...overrides,
  };
}

test("a completed run is green only when every receipt is healthy and nothing blocks it", () => {
  assert.deepEqual(runHealth(acmeRun()), { key: "healthy", status: "completed", reason: "" });

  const stale = runHealth(acmeRun({
    proof_health: { healthy: 2, missing: 0, stale: 1, tombstoned: 0 },
    blockers: [{ code: "proof_stale", message: "1 proof receipt(s) are stale.", object_type: "proof_receipts", object_id: 7, action: "restore" }],
  }));
  assert.equal(stale.key, "attention");
  assert.equal(stale.status, "completed");
  assert.equal(stale.reason, "1 stale receipt");

  const obligations = runHealth(acmeRun({
    blockers: [
      { code: "unresolved_obligation", message: "a", object_type: "obligation", object_id: 1, action: "x" },
      { code: "unresolved_obligation", message: "b", object_type: "obligation", object_id: 2, action: "x" },
    ],
  }));
  assert.deepEqual([obligations.key, obligations.reason], ["attention", "2 open obligations"]);

  const empty = runHealth(acmeRun({
    status: "partial",
    counts: { proof_receipts: 0 },
    proof_health: { healthy: 0, missing: 0, stale: 0, tombstoned: 0 },
    blockers: [{ code: "proof_missing", message: "Proof run has no recorded evidence receipt.", object_type: "proof_receipts", object_id: 7, action: "record" }],
  }));
  assert.deepEqual([empty.key, empty.reason], ["attention", "no evidence recorded"]);

  assert.equal(runHealth(acmeRun({ status: "running", blockers: [{ code: "proof_missing", message: "", object_type: "", object_id: null, action: "" }] })).key, "running");
  assert.equal(runHealth(acmeRun({ status: "interrupted" })).key, "failed");
  assert.deepEqual(runHealth(acmeRun({ status: "partial" })), { key: "attention", status: "partial", reason: "finished with open work" });
  assert.equal(runHealth(acmeRun({ status: "partial", seal: { requested_status: "partial", blockers: [] } })).reason, "its agent ended it as partial");
});

test("live blockers win over the seal; the seal speaks only when no live list was sent", () => {
  const sealed = { blockers: [{ code: "proof_stale", message: "", object_type: "", object_id: null, action: "" }] };
  assert.equal(currentBlockers({ blockers: [], seal: sealed }).length, 0);
  assert.equal(currentBlockers({ seal: sealed }).length, 1);
});

test("run findings union cited, associated, and dispatch-targeted slugs with their relation", () => {
  assert.deepEqual(runFindingLinks({
    finding_slugs: ["VA-002"],
    associated_finding_slugs: ["VA-001", "VA-002"],
    dispatch_finding_slugs: ["VA-001", "VA-003"],
  }), [
    { slug: "VA-002", relations: ["cited", "associated"] },
    { slug: "VA-001", relations: ["associated", "dispatched"] },
    { slug: "VA-003", relations: ["dispatched"] },
  ]);
});

test("evidence mix lists every kind in a stable order", () => {
  assert.equal(evidenceMixLabel({ artifact: 1, command: 1, http_exchange: 2 }), "2 HTTP · 1 cmd · 1 artifact");
  assert.equal(evidenceMixLabel({}), "None");
  assert.equal(evidenceMixLabel({ future_kind: 2 }), "2 future kind");
});

test("client and model prefer observed identity and mark requested-only values", () => {
  assert.deepEqual(runClientModel({
    provider_observed_client: "unknown",
    launcher_effective_client: "codex",
    actual_model: "unknown",
    requested_model: "gpt-acme",
  }), { client: "codex", model: "gpt-acme (requested)" });
  assert.deepEqual(runClientModel({ requested_client: "claude" }), { client: "claude (requested)", model: "" });
});

test("run filters combine and the time range is measured from the start", () => {
  const now = Date.parse("2026-10-20T12:00:00Z");
  const rows = [
    deriveRunRow(acmeRun({ id: 1, started_at: "2026-10-20 06:00:00" }), now),
    deriveRunRow(acmeRun({
      id: 2,
      started_at: "2026-10-01 06:00:00",
      producer_dispatch_agent_role: "exploit-developer",
      evidence_kind_counts: { command: 1 },
      proof_health: { healthy: 0, missing: 0, stale: 1, tombstoned: 0 },
      blockers: [{ code: "proof_stale", message: "", object_type: "", object_id: null, action: "" }],
      dispatch_finding_slugs: ["VA-009"],
      launcher_effective_client: "codex",
    }), now),
  ];
  const ids = (filters: Partial<typeof EMPTY_RUN_FILTERS>) =>
    filterRuns(rows, { ...EMPTY_RUN_FILTERS, ...filters }, now).map((row) => row.id);
  assert.deepEqual(ids({}), [1, 2]);
  assert.deepEqual(ids({ range: "24h" }), [1]);
  assert.deepEqual(ids({ range: "30d" }), [1, 2]);
  assert.deepEqual(ids({ liveOnly: true }), [1]);
  assert.deepEqual(ids({ blockersOnly: true }), [2]);
  assert.deepEqual(ids({ health: new Set(["attention"]) }), [2]);
  assert.deepEqual(ids({ roles: new Set(["exploit-developer"]) }), [2]);
  assert.deepEqual(ids({ finding: "VA-009" }), [2]);
  assert.deepEqual(ids({ client: "codex" }), [2]);
  assert.deepEqual(ids({ query: "acme TENANTS" }), [1, 2]);
  assert.deepEqual(ids({ query: "va-009" }), [2]);
  assert.deepEqual(ids({ query: "acme", tracks: new Set(["code"]) }), []);
  assert.deepEqual(facetCounts(["web", "code", "web", ""]), [["web", 2], ["code", 1]]);
});

test("run facets count what choosing each value would show, scope included", () => {
  const now = Date.parse("2026-10-20T12:00:00Z");
  const rows = [
    deriveRunRow(acmeRun({ id: 1, started_at: "2026-10-20 06:00:00" }), now),
    deriveRunRow(acmeRun({
      id: 2,
      started_at: "2026-10-01 06:00:00",
      run_kind: "code",
      proof_health: { healthy: 0, missing: 0, stale: 1, tombstoned: 0 },
      blockers: [{ code: "proof_stale", message: "", object_type: "", object_id: null, action: "" }],
    }), now),
    deriveRunRow(acmeRun({ id: 3, status: "failed", started_at: "2026-10-19 06:00:00" }), now),
  ];
  const all = runFacetCounts(rows, EMPTY_RUN_FILTERS, "all", now);
  assert.deepEqual(all.scope, { all: 3, attention: 2 });
  assert.deepEqual(all.health, { healthy: 1, attention: 1, failed: 1, running: 0 });
  assert.deepEqual(all.ranges, { all: 3, "24h": 1, "7d": 2, "30d": 3 });
  // A track facet ignores its own selection but honours the scope.
  const narrowed = runFacetCounts(rows, { ...EMPTY_RUN_FILTERS, tracks: new Set(["code"]) }, "attention", now);
  assert.deepEqual(narrowed.tracks, [["code", 1], ["web", 1]]);
  assert.deepEqual(narrowed.scope, { all: 1, attention: 1 });
  assert.deepEqual(narrowed.health, { healthy: 0, attention: 1, failed: 0, running: 0 });
  assert.deepEqual(filterRuns(rows, EMPTY_RUN_FILTERS, now, "attention").map((row) => row.id), [2, 3]);
  // A selected value with no matches stays listed so it can be cleared.
  assert.deepEqual(runFacetCounts(rows, { ...EMPTY_RUN_FILTERS, roles: new Set(["gone-role"]) }, "all", now).roles.at(-1), ["gone-role", 0]);
});

test("the saved Runs view round-trips and rejects anything it does not know", () => {
  const view = {
    filters: { ...EMPTY_RUN_FILTERS, query: "acme", health: new Set(["failed" as const]), tracks: new Set(["web"]), range: "7d" as const },
    scope: "attention" as const,
    sort: { colId: "duration", sort: "asc" as const },
  };
  const parsed = parseRunsView(serializeRunsView(view));
  assert.equal(parsed.filters.query, "acme");
  assert.deepEqual([...parsed.filters.health], ["failed"]);
  assert.deepEqual([...parsed.filters.tracks], ["web"]);
  assert.equal(parsed.filters.range, "7d");
  assert.equal(parsed.scope, "attention");
  assert.deepEqual(parsed.sort, { colId: "duration", sort: "asc" });
  const junk = parseRunsView('{"health":["nope"],"range":"1y","scope":"x","sort":{"colId":"bogus","sort":"asc"}}');
  assert.deepEqual([...junk.filters.health], []);
  assert.equal(junk.filters.range, "all");
  assert.equal(junk.scope, "all");
  assert.deepEqual(junk.sort, { colId: "started", sort: "desc" });
  assert.equal(parseRunsView("{not json").scope, "all");
});

test("a run link that names no run is reported, a valid or absent one is not", () => {
  assert.equal(invalidRunLink(new URLSearchParams("tab=runs&run=abc")), "abc");
  assert.equal(invalidRunLink(new URLSearchParams("tab=runs&run=0")), "0");
  assert.equal(invalidRunLink(new URLSearchParams("tab=runs&run=")), "");
  assert.equal(invalidRunLink(new URLSearchParams("tab=runs&run=12")), null);
  assert.equal(invalidRunLink(new URLSearchParams("tab=runs")), null);
});
