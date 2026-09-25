// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type {
  CodeAnalysisResult,
  CodeCoverage,
  CodeQueueItem,
  CodeQueueStats,
  CodeReadiness,
  CodeRepo,
} from "../lib/api";
import { CodeAnalysisTab } from "./CodeAnalysisTab";

function result(
  id: number,
  receiptBindingStatus: string,
  overrides: Partial<CodeAnalysisResult> = {},
): CodeAnalysisResult {
  return {
    id,
    queue_item_id: id,
    file_id: 1,
    file_path: "src/parser.py",
    agent_name: "code-vuln-hunter",
    receipt_kind: "file",
    receipt_binding_status: receiptBindingStatus,
    callable_refs: [],
    reviewed_spans: [],
    function_name: "",
    hypothesis: "",
    evidence: "",
    disposition: "skipped",
    confidence: "low",
    finding_slug: "",
    cwe_id: "",
    slot_type: "",
    notes: "fixture intentionally skipped",
    audit_metadata: {},
    created_at: "2026-09-12T12:00:00Z",
    ...overrides,
  };
}

function repo(overrides: Partial<CodeRepo> = {}): CodeRepo {
  return {
    id: 7,
    repo_key: "api-service",
    name: "API service",
    language: "python",
    repo_path: "/work/repos/api-service",
    total_files: 12,
    analyzable_files: 10,
    total_loc: 900,
    commit_hash: "0123456789abcdef0123456789abcdef01234567",
    branch: "release/security-review",
    active_generation: 3,
    source_origin_path: "/operator/source/api-service",
    source_kind: "git",
    snapshot_manifest_path: "evidence/code/api-service/source-manifest.json",
    snapshot_digest: "snapshot-digest-full-value",
    source_manifest_version: "2",
    source_manifest_digest: "manifest-digest-full-value",
    source_snapshot_quality: "verified",
    repo_role: "analysis",
    worktree_dirty: false,
    lsp_config: {},
    structural_index_schema: "v1",
    structural_index_generation: 3,
    structural_index_manifest_path: "evidence/code/api-service/structural-index.json",
    structural_degraded_files: 0,
    structural_degraded_file_paths: [],
    structural_artifact_truncated_files: 0,
    structural_artifact_truncated_file_paths: [],
    structural_analysis_status_counts: { complete: 10 },
    threat_model_generation: 3,
    analysis_status: "in_progress",
    threat_model: {},
    git_churn: {},
    created_at: "2026-09-12T12:00:00Z",
    updated_at: "2026-09-12T12:00:00Z",
    ...overrides,
  };
}

function readiness(overrides: Partial<CodeReadiness> = {}): CodeReadiness {
  return {
    target_phase: "verify-variant",
    transition_ready: false,
    blockers: [],
    quality_gate: { passed: true, warnings: [] },
    ...overrides,
  };
}

const queueStats: CodeQueueStats = {
  pending: 2,
  processing: 1,
  done: 2,
  error: 1,
  needs_context: 1,
  total: 7,
  historical_total: 14,
  superseded_history: 7,
  invalid_active_identity: 2,
  invalid_active_history: 1,
  reference_repo_items: [],
};

function queueItem(overrides: Partial<CodeQueueItem> = {}): CodeQueueItem {
  return {
    id: 41,
    file_id: 9,
    file_path: "src/auth/session.py",
    classification: "critical",
    analysis_priority: 100,
    repo_id: 7,
    repo_key: "api-service",
    repo_role: "analysis",
    status: "pending",
    queue_mode: "initial",
    priority: 100,
    batch_theme: "authentication",
    slot_types: ["AUTHZ"],
    guidance_hypotheses: ["Trace session ownership checks."],
    cross_file_triggers: [],
    agent_name: "",
    lease_token: "",
    repo_generation: 3,
    disposition: "",
    skip_reason: "",
    reanalysis_of_queue_item_id: null,
    consumed_at: null,
    last_heartbeat_at: null,
    lease_activity_at: null,
    heartbeat_age_seconds: null,
    current_result_count: 0,
    adopted_leases: [],
    completed_at: null,
    created_at: "2026-09-12T12:00:00Z",
    updated_at: "2026-09-12T12:00:00Z",
    ...overrides,
  };
}

afterEach(cleanup);

describe("CodeAnalysisTab receipt identity", () => {
  it("distinguishes a current skipped receipt from legacy unbound history", () => {
    render(
      <CodeAnalysisTab
        engagementKey="demo"
        persistedPhase="hunt"
        loadError={null}
        repos={[]}
        modules={[]}
        queueStats={null}
        coverage={null}
        readiness={null}
        completionReadiness={null}
        queueItems={[]}
        results={[
          result(1, "skipped_unbound"),
          result(2, "legacy_unbound"),
          result(3, "legacy_ambiguous"),
          result(4, "legacy_missing"),
          result(5, "source_span"),
        ]}
      />,
    );

    expect(screen.getByText("file receipt (skipped/no source anchors)")).toBeTruthy();
    expect(screen.getAllByText("file receipt (historical unbound identity)")).toHaveLength(3);
    expect(screen.getByText("file receipt (no source anchors)")).toBeTruthy();
  });
});

describe("CodeAnalysisTab operator readiness", () => {
  it("leads with the next transition and keeps completion readiness secondary", () => {
    render(
      <CodeAnalysisTab
        engagementKey="demo"
        persistedPhase="hunt"
        loadError={null}
        repos={[repo()]}
        modules={[]}
        queueStats={queueStats}
        queueItems={[]}
        coverage={null}
        readiness={readiness({
          blockers: [{
            code: "analysis_queue_active",
            message: "Repository has active queue work.",
            overrideable: true,
            repo_id: 7,
          }],
        })}
        completionReadiness={readiness({ target_phase: "complete", transition_ready: true })}
        results={[]}
      />,
    );

    expect(screen.getByText("Next transition: Verify + Variant")).toBeTruthy();
    expect(screen.getByText("BLOCKED")).toBeTruthy();
    expect(screen.getByText("Completion readiness: READY")).toBeTruthy();
    expect(screen.getByRole("link", { name: "API service" }).getAttribute("href")).toBe("#code-repo-7");
  });

  it("exposes full repository identity and stale, legacy, dirty, and generation mismatch truth", () => {
    render(
      <CodeAnalysisTab
        engagementKey="demo"
        persistedPhase="classify-map"
        loadError={null}
        repos={[repo({
          source_snapshot_quality: "legacy-unverified",
          worktree_dirty: true,
          structural_index_generation: 2,
          threat_model_generation: 1,
        })]}
        modules={[]}
        queueStats={null}
        queueItems={[]}
        coverage={null}
        readiness={null}
        completionReadiness={null}
        results={[]}
      />,
    );

    expect(screen.getByText("api-service")).toBeTruthy();
    expect(screen.getByText("/work/repos/api-service")).toBeTruthy();
    expect(screen.getByText("/operator/source/api-service")).toBeTruthy();
    expect(screen.getByText("0123456789abcdef0123456789abcdef01234567")).toBeTruthy();
    expect(screen.getByText("Legacy-unverified source snapshot")).toBeTruthy();
    expect(screen.getByText("Dirty worktree at ingestion")).toBeTruthy();
    expect(screen.getByText("Structural index generation 2 does not match active generation 3")).toBeTruthy();
    expect(screen.getByText("Threat model generation 1 does not match active generation 3")).toBeTruthy();
  });

  it("lists unsupported structural-debt paths returned by readiness", () => {
    render(
      <CodeAnalysisTab
        engagementKey="demo"
        persistedPhase="hunt"
        loadError={null}
        repos={[repo({
          structural_analysis_status_counts: { complete: 10, unsupported: 1 },
        })]}
        modules={[]}
        queueStats={null}
        queueItems={[]}
        coverage={null}
        readiness={readiness({
          structural_debt_count: 1,
          structural_debt: [{ repo_id: 7, file_path: "src/legacy/unsupported.cbl" }],
        } as CodeReadiness & {
          structural_debt_count: number;
          structural_debt: Array<{ repo_id: number; file_path: string }>;
        })}
        completionReadiness={null}
        results={[]}
      />,
    );

    expect(screen.getByText("src/legacy/unsupported.cbl")).toBeTruthy();
  });

  it("shows queue integrity and a compact actionable next-work list", () => {
    render(
      <CodeAnalysisTab
        engagementKey="demo"
        persistedPhase="hunt"
        loadError={null}
        repos={[repo()]}
        modules={[]}
        queueStats={queueStats}
        queueItems={[
          queueItem(),
          queueItem({ id: 42, file_path: "src/auth/policy.py", status: "error", priority: 90 }),
        ]}
        coverage={null}
        readiness={null}
        completionReadiness={null}
        results={[]}
      />,
    );

    expect(screen.getByText("14 historical rows")).toBeTruthy();
    expect(screen.getByText("7 superseded")).toBeTruthy();
    expect(screen.getByText("2 invalid active identities")).toBeTruthy();
    expect(screen.getByText("1 invalid active history")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Next work" })).toBeTruthy();
    expect(screen.getByText("src/auth/session.py")).toBeTruthy();
    expect(screen.getByText("src/auth/policy.py")).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "api-service" })[0].getAttribute("href")).toBe("#code-repo-7");
  });

  it("deep-links findings and exposes long evidence through an explicit keyboard control", () => {
    const longEvidence = `raw-token=${"x".repeat(240)}`;
    render(
      <CodeAnalysisTab
        engagementKey="demo key"
        persistedPhase="verify-variant"
        loadError={null}
        repos={[]}
        modules={[]}
        queueStats={null}
        queueItems={[]}
        coverage={null}
        readiness={null}
        completionReadiness={null}
        results={[result(9, "source_span", {
          disposition: "finding",
          confidence: "high",
          evidence: longEvidence,
          finding_slug: "VIGIL-204",
          finding_workflow_status: "confirmed",
        })]}
      />,
    );

    expect(screen.getByRole("searchbox", { name: "Search analysis results" })).toBeTruthy();
    const disposition = screen.getByRole("button", { name: "Filter disposition finding" });
    expect(disposition.getAttribute("aria-pressed")).toBe("false");
    const finding = screen.getByRole("link", { name: "VIGIL-204" });
    expect(finding.getAttribute("href")).toBe("#/engagements/demo%20key?tab=findings&finding=VIGIL-204");

    const expand = screen.getByRole("button", { name: "Show full evidence for result 9" });
    expect(expand.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(expand);
    expect(expand.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText(longEvidence)).toBeTruthy();
  });
});
