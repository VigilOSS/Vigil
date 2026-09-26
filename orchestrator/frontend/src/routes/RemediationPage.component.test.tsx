// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  approveRemediationCase,
  getRemediationCase,
  getRemediationDiff,
  listRemediationCases,
  recordRemediationHumanVerification,
  updateRemediationReleasePlan,
  updateRemediationBaseline,
  type RemediationCase,
  updateRemediationVerificationPlan,
} from "../lib/api";
import { RemediationPage } from "./RemediationPage";

vi.mock("../lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) { super(message); this.status = status; }
  },
  approveRemediationCase: vi.fn(),
  getRemediationCase: vi.fn(),
  getRemediationDiff: vi.fn(),
  listRemediationCases: vi.fn(),
  recordRemediationHumanVerification: vi.fn(),
  updateRemediationReleasePlan: vi.fn(),
  updateRemediationBaseline: vi.fn(),
  updateRemediationVerificationPlan: vi.fn(),
  remediationEvidenceFileUrl: vi.fn((_key: string, caseId: number, evidenceId: number) =>
    `/evidence/${caseId}/${evidenceId}`),
}));

const digest = "a".repeat(64);
const reviewedCase: RemediationCase = {
  id: 7,
  source_type: "jira",
  source_key: "SEC-42",
  title: "Manage profile authorization",
  status: "review",
  snapshot: { description: "Report says a profile can be edited by another account." },
  linked_finding_slug: null,
  duplicate_hints: [9],
  worktree_path: "/worktrees/sec-42",
  worktree_revision: "abc123",
  verification_plan: "Open Manage as owner; update display name; confirm saved.",
  approval_current: false,
  review_evidence_ready: true,
  review_evidence_missing: [],
  review_digest: digest,
  baseline: { outcome: "runtime_reproduced", method: "Laravel HTTP test", proved: "Unauthorized update rejected" },
  release_plan: { production_canary_decision: "not_required", production_canary_rationale: "Local and development coverage sufficient", safe_procedure: "", coralogix_monitoring: "Watch authorization failures" },
  approvals: [],
  human_verifications: [],
  evidence: [
    { id: 3, kind: "stagehand_screenshot", method: "stagehand", environment: "local", command: "", observed: "Saved", proved: "Owner can save", artifact_path: "cases/7/happy-path.png", artifact_sha256: "abc", created_at: "2026-09-25T10:00:00Z" },
    { id: 4, kind: "laravel_test", method: "phpunit", environment: "development", command: "php artisan test --filter=ProfileAuthorization", observed: "Passed", proved: "Authorization regression", artifact_path: "cases/7/test-output.txt", artifact_sha256: "def", created_at: "2026-09-25T10:01:00Z" },
  ],
  transitions: [],
  deployment: { environment: "development", workflow: "Deploy", run_id: "42", expected_revision: "abc123", observed_revision: "abc123" },
};

beforeEach(() => {
  vi.mocked(listRemediationCases).mockResolvedValue([reviewedCase]);
  vi.mocked(getRemediationCase).mockResolvedValue(reviewedCase);
  vi.mocked(getRemediationDiff).mockResolvedValue({ text: "diff --git a/auth.php b/auth.php\n+deny other users", truncated: false, bytes_total: 64, base_revision: "main123", head_revision: "abc123", review_digest: digest });
  vi.mocked(updateRemediationVerificationPlan).mockImplementation(async (_key, _id, plan) => ({ ...reviewedCase, verification_plan: plan }));
  vi.mocked(approveRemediationCase).mockResolvedValue({ id: 5, reviewer: "owner", review_digest: digest });
  vi.mocked(updateRemediationReleasePlan).mockImplementation(async (_key, _id, plan) => ({ ...reviewedCase, release_plan: plan }));
  vi.mocked(updateRemediationBaseline).mockImplementation(async (_key, _id, baseline) => ({ ...reviewedCase, baseline }));
  vi.mocked(recordRemediationHumanVerification).mockResolvedValue({ id: 8, actor: "owner", result: "passed", observed_revision: "abc123", notes: "UI matched plan" });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("remediation workspace", () => {
  it("clears the previous case when switching engagements", async () => {
    vi.mocked(listRemediationCases).mockImplementation((key) => key === "first"
      ? Promise.resolve([reviewedCase])
      : new Promise(() => {}));
    const { rerender } = render(<RemediationPage engagementKey="first" onBack={() => {}} />);
    expect(await screen.findByText(/Report says a profile can be edited/)).toBeTruthy();

    rerender(<RemediationPage engagementKey="second" onBack={() => {}} />);

    expect(screen.queryByText(/Report says a profile can be edited/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Save plan" })).toBeNull();
  });

  it("shows the queue, source snapshot, duplicate hint, worktree and deployment identity", async () => {
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);

    expect(await screen.findByText("Manage profile authorization")).toBeTruthy();
    expect(screen.getByText("SEC-42")).toBeTruthy();
    expect(await screen.findByText(/Report says a profile can be edited/)).toBeTruthy();
    expect(screen.getByText(/Case #9/)).toBeTruthy();
    expect(screen.getByText("/worktrees/sec-42")).toBeTruthy();
    expect(screen.getAllByText("abc123").length).toBeGreaterThan(0);
    expect(screen.getByAltText("happy-path.png").getAttribute("src")).toBe("/evidence/7/3");
    expect(screen.getByText("Authorization regression")).toBeTruthy();
    expect(screen.getByText("Environment: development")).toBeTruthy();
    expect(screen.getByText(/php artisan test --filter=ProfileAuthorization/)).toBeTruthy();
    expect(screen.getByText(/deny other users/)).toBeTruthy();
  });

  it("saves a changed human plan and requires an explicit approval action", async () => {
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    const plan = await screen.findByLabelText("Human verification plan");
    fireEvent.change(plan, { target: { value: "Open Manage as owner; save the verified fixture." } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await waitFor(() => expect(updateRemediationVerificationPlan).toHaveBeenCalledWith("Acme", 7,
      "Open Manage as owner; save the verified fixture."));
    expect(approveRemediationCase).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve reviewed snapshot" }));
    await waitFor(() => expect(approveRemediationCase).toHaveBeenCalledWith("Acme", 7, "owner", digest, "ui"));
  });

  it("never submits approval while plan edits are unsaved", async () => {
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    const plan = await screen.findByLabelText("Human verification plan");
    fireEvent.change(plan, { target: { value: "A changed procedure" } });
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("blocks approval when the review diff is truncated", async () => {
    vi.mocked(getRemediationDiff).mockResolvedValue({ text: "partial diff", truncated: true, bytes_total: 2000000, base_revision: "main123", head_revision: "abc123", review_digest: digest });
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    await screen.findByText("partial diff");
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    expect(screen.getByText(/Diff truncated/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows missing red/green and Stagehand evidence and prevents approval", async () => {
    vi.mocked(getRemediationCase).mockResolvedValue({
      ...reviewedCase,
      review_evidence_ready: false,
      review_evidence_missing: ["Red Laravel test output", "Green Laravel test output", "Stagehand happy-path result, script, and screenshot"],
    });
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    expect(await screen.findByText("Red Laravel test output")).toBeTruthy();
    expect(screen.getByText("Green Laravel test output")).toBeTruthy();
    expect(screen.getByText("Stagehand happy-path result, script, and screenshot")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
    expect(approveRemediationCase).not.toHaveBeenCalled();
  });

  it("blocks approval when the diff digest differs from the case", async () => {
    vi.mocked(getRemediationDiff).mockResolvedValue({ text: "changed diff", truncated: false, bytes_total: 12, base_revision: "main123", head_revision: "abc123", review_digest: "b".repeat(64) });
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    await screen.findByText("changed diff");
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    expect(screen.getByText(/diff no longer matches/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("refreshes the reviewed package after a stale approval rejection", async () => {
    const nextDigest = "b".repeat(64);
    vi.mocked(approveRemediationCase).mockRejectedValue(new ApiError("Review package changed", 409, {}));
    vi.mocked(getRemediationCase).mockResolvedValueOnce(reviewedCase).mockResolvedValueOnce({ ...reviewedCase, review_digest: nextDigest });
    vi.mocked(getRemediationDiff).mockResolvedValueOnce({ text: "original diff", truncated: false, bytes_total: 12, base_revision: "main123", head_revision: "abc123", review_digest: digest }).mockResolvedValueOnce({ text: "new diff", truncated: false, bytes_total: 12, base_revision: "main123", head_revision: "abc123", review_digest: nextDigest });
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    await screen.findByText("original diff");
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve reviewed snapshot" }));
    expect(await screen.findByText("new diff")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("Review package changed");
  });

  it("saves the production canary decision and monitoring plan before approval", async () => {
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    const decision = await screen.findByLabelText("Production canary decision");
    fireEvent.change(decision, { target: { value: "required" } });
    fireEvent.change(screen.getByLabelText("Canary rationale"), { target: { value: "Needs human production proof" } });
    fireEvent.change(screen.getByLabelText("Safe canary procedure"), { target: { value: "Use owner account and harmless fixture" } });
    fireEvent.change(screen.getByLabelText("Coralogix monitoring"), { target: { value: "Watch profile authorization errors" } });
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Save release plan" }));
    await waitFor(() => expect(updateRemediationReleasePlan).toHaveBeenCalledWith("Acme", 7, {
      production_canary_decision: "required", production_canary_rationale: "Needs human production proof", safe_procedure: "Use owner account and harmless fixture", coralogix_monitoring: "Watch profile authorization errors",
    }));
  });

  it("records the owner's decision when baseline reproduction was unavailable", async () => {
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    await screen.findByLabelText("Baseline outcome");
    fireEvent.change(screen.getByLabelText("Baseline outcome"), { target: { value: "code_test_confirmed" } });
    fireEvent.change(screen.getByLabelText("Baseline method"), { target: { value: "Laravel failing test" } });
    fireEvent.change(screen.getByLabelText("Baseline proved"), { target: { value: "Code and failing test support report" } });
    fireEvent.change(screen.getByLabelText("Owner decision"), { target: { value: "proceed" } });
    fireEvent.change(screen.getByLabelText("Owner actor"), { target: { value: "owner" } });
    fireEvent.change(screen.getByLabelText("Owner reason"), { target: { value: "Safe local replay unavailable" } });
    fireEvent.click(screen.getByRole("button", { name: "Save baseline" }));
    await waitFor(() => expect(updateRemediationBaseline).toHaveBeenCalledWith("Acme", 7, {
      outcome: "code_test_confirmed", method: "Laravel failing test", proved: "Code and failing test support report", owner_decision: "proceed", owner_actor: "owner", owner_reason: "Safe local replay unavailable",
    }));
  });

  it("records a human development result against the confirmed deployed revision", async () => {
    vi.mocked(listRemediationCases).mockResolvedValue([{ ...reviewedCase, status: "development" }]);
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, status: "development" });
    render(<RemediationPage engagementKey="Acme" onBack={() => {}} />);
    await screen.findByLabelText("Human verification result");
    fireEvent.change(screen.getByLabelText("Human verification actor"), { target: { value: "owner" } });
    fireEvent.change(screen.getByLabelText("Human verification notes"), { target: { value: "Followed the saved steps; owner could save." } });
    fireEvent.change(screen.getByLabelText("Human verification result"), { target: { value: "passed" } });
    fireEvent.click(screen.getByRole("button", { name: "Record human verification" }));
    await waitFor(() => expect(recordRemediationHumanVerification).toHaveBeenCalledWith("Acme", 7, {
      actor: "owner", result: "passed", observed_revision: "abc123", notes: "Followed the saved steps; owner could save.",
    }));
  });
});
