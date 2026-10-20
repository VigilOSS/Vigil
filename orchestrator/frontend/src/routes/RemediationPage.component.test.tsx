// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  approveRemediationCase,
  getRemediationCase,
  getBackendReadiness,
  getRemediationEvidencePage,
  getRemediationEvidence,
  getRemediationHistoryPage,
  readRemediationEvidenceText,
  getRemediationDiff,
  listRemediationCases,
  recordRemediationHumanVerification,
  updateRemediationReleasePlan,
  updateRemediationBaseline,
  type RemediationCase,
  updateRemediationVerificationPlan,
  getAssessmentFinding,
  listEngagements,
  updateRemediationFindings,
} from "../lib/api";
import { RemediationPage } from "./RemediationPage";

vi.mock("../lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) { super(message); this.status = status; }
  },
  approveRemediationCase: vi.fn(),
  getRemediationCase: vi.fn(),
  getBackendReadiness: vi.fn(),
  getRemediationEvidencePage: vi.fn(),
  getRemediationEvidence: vi.fn(),
  getRemediationHistoryPage: vi.fn(),
  readRemediationEvidenceText: vi.fn(),
  getRemediationDiff: vi.fn(),
  listRemediationCases: vi.fn(),
  recordRemediationHumanVerification: vi.fn(),
  updateRemediationReleasePlan: vi.fn(),
  updateRemediationBaseline: vi.fn(),
  updateRemediationVerificationPlan: vi.fn(),
  getAssessmentFinding: vi.fn(),
  listEngagements: vi.fn(),
  updateRemediationFindings: vi.fn(),
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
  linked_findings: [{ id: 11, engagement_key: "assessment", slug: "SEC-001", title: "Current finding title", severity: "high", verification_status: "confirmed", root_cause_key: "authorization" }],
  duplicate_hints: [9],
  worktree_path: "/worktrees/sec-42",
  worktree_revision: "abc123",
  verification_plan: "Open Manage as owner; update display name; confirm saved.",
  approval_current: false,
  review_evidence_ready: true,
  review_evidence_missing: [],
  review_digest: digest,
  baseline: { outcome: "runtime_reproduced", method: "Laravel HTTP test", proved: "Unauthorized update rejected" },
  release_plan: { production_canary_decision: "not_required", production_canary_rationale: "Local and development coverage sufficient", safe_procedure: "", monitoring: "Watch authorization failures" },
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
  window.sessionStorage.clear();
  vi.mocked(getBackendReadiness).mockResolvedValue({ backend_runtime: { restart_required: false, changed_inputs: [] } });
  vi.mocked(listEngagements).mockResolvedValue([{ id: 1, key: "assessment", target: "Assessment", engagement_type: "offensive" } as Awaited<ReturnType<typeof listEngagements>>[number]]);
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
  vi.restoreAllMocks();
});

async function openSection(name: "Review" | "Evidence" | "Delivery") {
  fireEvent.click(await screen.findByRole("button", { name: name === "Evidence" ? /^Evidence/ : name }));
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

it("finds a direct report by its attached external key", async () => {
  const item = { ...reviewedCase, source_type: "manual", source_key: "case-7",
    external_provider: "tracker", external_key: "ACME-103" };
  vi.mocked(listRemediationCases).mockResolvedValue([item]);
  vi.mocked(getRemediationCase).mockResolvedValue(item);
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  expect(await screen.findByText("ACME-103")).toBeTruthy();
});

it("previews evidence on demand as literal text and displays integrity failures", async () => {
  vi.mocked(readRemediationEvidenceText).mockResolvedValue({ text: "<script>target text</script>\nPassed", truncated: true });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Evidence");
  expect(readRemediationEvidenceText).toHaveBeenCalledTimes(0);
  fireEvent.click(screen.getByRole("button", { name: "Preview test-output.txt" }));
  expect(await screen.findByText(/<script>target text/)).toBeTruthy();
  expect(screen.getByText(/Preview limited to/)).toBeTruthy();
});

it("shows artifact integrity failures and can retry a preview", async () => {
  vi.mocked(readRemediationEvidenceText).mockRejectedValueOnce(new Error("Evidence file changed since registration")).mockResolvedValueOnce({ text: "Registered output", truncated: false });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Evidence");
  fireEvent.click(screen.getByRole("button", { name: "Preview test-output.txt" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Evidence file changed since registration");
  fireEvent.click(screen.getByRole("button", { name: "Hide test-output.txt" }));
  fireEvent.click(screen.getByRole("button", { name: "Preview test-output.txt" }));
  expect(await screen.findByText("Registered output")).toBeTruthy();
});

it("makes backend restart-required state visible", async () => {
  vi.mocked(getBackendReadiness).mockResolvedValue({ backend_runtime: { restart_required: true, changed_inputs: ["app/services/remediation.py"] } });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  expect(await screen.findByText(/Backend restart required/)).toBeTruthy();
});

it("shows backend requirement matches and follows them to evidence", async () => {
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase,
    verification_requirements: { alternatives_reason: "", requirements: [{ kind: "laravel_test", methods: ["phpunit"], outcome: "passed", revision: "current", execution: "executed", rationale: "Authorization coverage" }] },
    verification_matches: [{ requirement_index: 0, evidence_ids: [4], missing: null }],
    environment_leases: [{ token: "lease-1", environment: "development", actor: "Acme owner", revision: "abc123", observed_revision: "abc123", acquired_at: "2026-10-14", released_at: null, released_by: null }],
  });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Review");
  fireEvent.click(screen.getByRole("button", { name: "View evidence #4" }));
  expect(screen.getByText("Authorization regression")).toBeTruthy();
  await openSection("Delivery");
  expect(screen.getByText(/Acme owner/)).toBeTruthy();
});

it("opens matching evidence beyond the initial page without reading intervening pages", async () => {
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase,
    verification_requirements: { alternatives_reason: "", requirements: [{ kind: "laravel_test", methods: ["phpunit"], outcome: "passed", revision: "current", execution: "executed", rationale: "Authorization coverage" }] },
    verification_matches: [{ requirement_index: 0, evidence_ids: [99], missing: null }],
  });
  vi.mocked(getRemediationEvidence).mockResolvedValue({ ...reviewedCase.evidence[1], id: 99, proved: "Matched later proof" });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Review");
  fireEvent.click(screen.getByRole("button", { name: "View evidence #99" }));
  expect(await screen.findByText("Matched later proof")).toBeTruthy();
  expect(getRemediationEvidence).toHaveBeenCalledWith("acme", 7, 99);
  expect(getRemediationEvidencePage).toHaveBeenCalledTimes(0);
});

it("keeps the latest out-of-page evidence selection when earlier reads finish late", async () => {
  const earlier = deferred<Awaited<ReturnType<typeof getRemediationEvidence>>>();
  const latest = deferred<Awaited<ReturnType<typeof getRemediationEvidence>>>();
  vi.mocked(getRemediationEvidence).mockReturnValueOnce(earlier.promise).mockReturnValueOnce(latest.promise);
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase,
    verification_requirements: { alternatives_reason: "", requirements: [99, 100].map(() => ({ kind: "laravel_test", methods: ["phpunit"], outcome: "passed", revision: "current" as const, execution: "executed" as const, rationale: "Authorization coverage" })) },
    verification_matches: [99, 100].map((id, index) => ({ requirement_index: index, evidence_ids: [id], missing: null })),
  });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Review");
  fireEvent.click(screen.getByRole("button", { name: "View evidence #99" }));
  await openSection("Review");
  fireEvent.click(screen.getByRole("button", { name: "View evidence #100" }));
  await act(async () => { latest.resolve({ ...reviewedCase.evidence[1], id: 100, proved: "Latest selected proof" }); });
  expect(screen.getByText("Latest selected proof")).toBeTruthy();
  await act(async () => { earlier.resolve({ ...reviewedCase.evidence[1], id: 99, proved: "Earlier selected proof" }); });
  expect(screen.getByText("Latest selected proof")).toBeTruthy();
  expect(screen.queryByText("Earlier selected proof")).toBeNull();
});

it("allows pagination in another case and ignores an earlier case's pending page", async () => {
  const earlier = deferred<Awaited<ReturnType<typeof getRemediationEvidencePage>>>();
  const latest = deferred<Awaited<ReturnType<typeof getRemediationEvidencePage>>>();
  const secondCase = { ...reviewedCase, id: 8, source_key: "SEC-43", title: "Second case", evidence_total: 3 };
  vi.mocked(listRemediationCases).mockResolvedValue([reviewedCase, secondCase]);
  vi.mocked(getRemediationCase).mockImplementation(async (_key, id) => id === 8 ? secondCase : { ...reviewedCase, evidence_total: 3 });
  vi.mocked(getRemediationEvidencePage).mockReturnValueOnce(earlier.promise).mockReturnValueOnce(latest.promise);
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Evidence");
  fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
  fireEvent.click(screen.getByRole("button", { name: /^SEC-43/ }));
  await screen.findByRole("heading", { name: "Second case" });
  await openSection("Evidence");
  fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
  expect(getRemediationEvidencePage).toHaveBeenCalledWith("acme", 8, 2);
  await act(async () => { earlier.resolve({ items: [{ ...reviewedCase.evidence[1], id: 99, proved: "Stale page proof" }], total: 3, limit: 20, offset: 2 }); });
  expect((screen.getByRole("button", { name: "Loading evidence…" }) as HTMLButtonElement).disabled).toBe(true);
  await act(async () => { latest.resolve({ items: [{ ...reviewedCase.evidence[1], id: 100, proved: "Second case proof" }], total: 3, limit: 20, offset: 2 }); });
  expect(screen.getByText("Second case proof")).toBeTruthy();
  expect(screen.queryByText("Stale page proof")).toBeNull();
});

it("shows configured checks and the recorded PR with its reviewed revision", async () => {
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase,
    checks: [{ name: "Authorization", command: "npm test", evidence_ids: [4], missing: null }, { name: "Build", command: "npm run build", evidence_ids: [], missing: "Build proof missing" }],
    pull_request: { url: "https://github.example/acme/project/pull/42", revision: "abc123", branch: "fix/acme-42", base_branch: "main", review_digest: digest, body_sha256: "abc", evidence_id: 99, current: true },
  });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Review");
  expect(screen.getByText("Build proof missing")).toBeTruthy();
  expect(screen.getByText("Authorization")).toBeTruthy();
  await openSection("Delivery");
  expect(screen.getByRole("link", { name: "Open recorded PR ↗" }).getAttribute("href")).toBe("https://github.example/acme/project/pull/42");
  expect(screen.getByText(/fix\/acme-42 → main/)).toBeTruthy();
});

it("loads subsequent evidence and history pages on demand", async () => {
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, evidence_total: 3, history_total: 1 });
  vi.mocked(getRemediationEvidencePage).mockResolvedValue({ items: [{ ...reviewedCase.evidence[1], id: 8, proved: "Additional proof" }], total: 3, limit: 20, offset: 2 });
  vi.mocked(getRemediationHistoryPage).mockResolvedValue({ items: [{ id: 1, from_status: "new", to_status: "review", actor: "Acme owner", reason: "Ready for review" }], total: 1, limit: 20, offset: 0 });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Evidence");
  fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
  expect(await screen.findByText("Additional proof")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "History" }));
  fireEvent.click(screen.getByRole("button", { name: "Load more history" }));
  expect((await screen.findAllByText(/Ready for review/)).length).toBeGreaterThan(0);
});

it("loads the diff only when Review opens and reuses it across tabs", async () => {
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await screen.findByRole("heading", { name: reviewedCase.title });
  expect(getRemediationDiff).toHaveBeenCalledTimes(0);
  await openSection("Review");
  await screen.findByText(/deny other users/);
  await openSection("Evidence");
  await openSection("Review");
  expect(getRemediationDiff).toHaveBeenCalledTimes(1);
});

it("keeps initial plan setup with the case developer before enabling text-only updates", async () => {
  vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, verification_plan: "" });
  render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
  await openSection("Review");
  fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Proposed test steps" } });
  expect((screen.getByRole("button", { name: "Save plan" }) as HTMLButtonElement).disabled).toBe(true);
});

async function findSibling() {
  vi.mocked(getAssessmentFinding).mockResolvedValue({ id: 22, slug: "SEC-002", title: "Same root cause", severity: "medium", verification_status: "unreviewed", root_cause_key: "authorization" } as Awaited<ReturnType<typeof getAssessmentFinding>>);
  fireEvent.click(await screen.findByRole("button", { name: "Link finding" }));
  await screen.findByRole("option", { name: /assessment · Assessment/ });
  fireEvent.change(screen.getByLabelText("Source engagement"), { target: { value: "assessment" } });
  fireEvent.change(screen.getByLabelText("Finding slug"), { target: { value: "SEC-002" } });
  fireEvent.click(screen.getByRole("button", { name: "Find finding" }));
  await screen.findByText("Same root cause");
}

describe("remediation workspace", () => {
  it("shows verification alternatives and distinguishes reasoned evidence", async () => {
    vi.mocked(getRemediationCase).mockResolvedValue({
      ...reviewedCase,
      verification_requirements: {
        alternatives_reason: "Caller analysis covers a deletion without a mirrored regression test",
        requirements: [{ kind: "caller-analysis", methods: ["code-review"], execution: "reasoned", outcome: "passed", revision: "current", rationale: "" }],
      },
      evidence: [{ ...reviewedCase.evidence[0], execution: "reasoned" }],
    });
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Evidence");
    expect(screen.getByText("Reasoned evidence")).toBeTruthy();
    await openSection("Review");
    expect(screen.getByText("Caller analysis covers a deletion without a mirrored regression test")).toBeTruthy();
  });
  it("keeps edits and tells the truth when discarding stored drafts fails", async () => {
    const view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Stored draft must remain" } });
    const stored = window.sessionStorage.getItem("vigil.remediation.drafts.acme:7");
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("Removal denied"); });
    fireEvent.click(screen.getByRole("button", { name: "Discard local drafts" }));
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Stored draft must remain");
    expect(screen.getByText(/Could not discard stored drafts/)).toBeTruthy();
    expect(screen.queryByText(/Unsaved edits remain only in this page/)).toBeNull();
    expect(window.sessionStorage.getItem("vigil.remediation.drafts.acme:7")).toBe(stored);
    view.unmount();
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Stored draft must remain");
  });
  it("retains other page-local drafts after a successful save when session writes fail", async () => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage denied"); });
    fireEvent.change(screen.getByLabelText("Baseline method"), { target: { value: "Page-local baseline" } });
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Saved plan" } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await screen.findByText(/Verification plan saved/);
    expect(screen.getByText(/Draft storage unavailable/)).toBeTruthy();
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, verification_plan: "Saved plan" });
    fireEvent.click(screen.getByRole("button", { name: "Refresh case" }));
    await waitFor(() => expect(getRemediationCase).toHaveBeenCalledTimes(2));
    expect((screen.getByLabelText("Baseline method") as HTMLInputElement).value).toBe("Page-local baseline");
  });
  it.each([
    "{invalid json",
    JSON.stringify({ baseline: { value: { method: 123, outcome: "runtime_reproduced", proved: "x" }, base_value: {}, review_digest: digest, worktree_revision: "abc123" } }),
    JSON.stringify({ releasePlan: { value: { production_canary_rationale: 123 }, base_value: {}, review_digest: digest, worktree_revision: "abc123" } }),
    JSON.stringify({ baseline: { value: { outcome: "unknown" }, base_value: {}, review_digest: digest, worktree_revision: "abc123" } }),
    JSON.stringify({ releasePlan: { value: { production_canary_decision: "unknown" }, base_value: {}, review_digest: digest, worktree_revision: "abc123" } }),
  ])("preserves malformed draft text without crashing and offers explicit discard (%s)", async (stored) => {
    const key = "vigil.remediation.drafts.acme:7";
    window.sessionStorage.setItem(key, stored);
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect(screen.getByText(/Draft storage unavailable/)).toBeTruthy();
    expect(window.sessionStorage.getItem(key)).toBe(stored);
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    const raw = screen.getByText("Unreadable local draft record").closest("details");
    expect(raw?.querySelector("pre")?.textContent).toBe(stored);
    fireEvent.click(screen.getByRole("button", { name: "Discard local drafts" }));
    expect(window.sessionStorage.getItem(key)).toBeNull();
    expect(screen.queryByText(/Draft storage unavailable/)).toBeNull();
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe(reviewedCase.verification_plan);
  });
  it("retains verbatim edits through Back navigation and engagement changes without leaking case identity", async () => {
    const onBack = vi.fn();
    const value = "Authorization: Bearer full-token\nCookie: exact-cookie\nRun the operator's recorded command.";
    let view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={onBack} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "← Engagements" }));
    expect(onBack).toHaveBeenCalledOnce();
    view.unmount();
    view = render(<RemediationPage engagementKey="another-engagement" initialCaseId={7} onBack={onBack} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe(reviewedCase.verification_plan);
    view.unmount();
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={onBack} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe(value);
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    const raw = screen.getByText("Local unsaved drafts").closest("details");
    expect(JSON.parse(raw?.querySelector("pre")?.textContent || "{}").plan.value).toBe(value);
  });

  it("preserves drafts through an explicit refresh of changed backend state", async () => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Retained edits" } });
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, verification_plan: "Latest server plan", worktree_revision: "latest-commit" });
    fireEvent.click(screen.getByRole("button", { name: "Refresh case" }));
    await screen.findByText("latest-commit");
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Retained edits");
    expect(screen.getByText(/Server snapshot changed since these drafts began/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Discard local drafts" }));
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Latest server plan");
  });

  it("does not clear a newer local draft when an older routed save succeeds late", async () => {
    const pending = deferred<RemediationCase>();
    vi.mocked(updateRemediationVerificationPlan).mockReturnValue(pending.promise);
    const second = { ...reviewedCase, id: 8, title: "Second case", source_key: "SEC-43" };
    vi.mocked(getRemediationCase).mockImplementation(async (_key, id) => id === 8 ? second : reviewedCase);
    const view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Submitted older edits" } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    view.rerender(<RemediationPage engagementKey="acme" initialCaseId={8} onBack={() => {}} />);
    await screen.findByRole("heading", { name: "Second case" });
    view.rerender(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Newer unsubmitted edits" } });
    await act(async () => pending.resolve({ ...reviewedCase, verification_plan: "Submitted older edits" }));
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Newer unsubmitted edits");
    const stored = JSON.parse(window.sessionStorage.getItem("vigil.remediation.drafts.acme:7") || "{}");
    expect(stored.plan.value).toBe("Newer unsubmitted edits");
  });

  it.each(["baseline", "releasePlan"] as const)("clears a successfully saved %s draft without removing the plan draft", async (field) => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Retained unsaved plan" } });
    fireEvent.click(screen.getByRole("button", { name: field === "baseline" ? "Overview" : "Delivery" }));
    fireEvent.change(screen.getByLabelText(field === "baseline" ? "Baseline method" : "Canary rationale"), { target: { value: "Updated decision" } });
    fireEvent.click(screen.getByRole("button", { name: field === "baseline" ? "Save baseline" : "Save release plan" }));
    await screen.findByText(field === "baseline" ? /Baseline saved\./ : /Release plan saved\./);
    const stored = JSON.parse(window.sessionStorage.getItem("vigil.remediation.drafts.acme:7") || "{}");
    expect(stored[field]).toBeUndefined();
    expect(stored.plan.value).toBe("Retained unsaved plan");
  });
  it("restores each case's unsaved plan, baseline and release drafts after route changes", async () => {
    const second = { ...reviewedCase, id: 8, title: "Second case", source_key: "SEC-43" };
    vi.mocked(listRemediationCases).mockResolvedValue([reviewedCase, second]);
    vi.mocked(getRemediationCase).mockImplementation(async (_key, id) => id === 8 ? second : reviewedCase);
    const view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    fireEvent.change(screen.getByLabelText("Baseline method"), { target: { value: "Unsaved baseline method" } });
    await openSection("Delivery");
    fireEvent.change(screen.getByLabelText("Canary rationale"), { target: { value: "Unsaved release rationale" } });
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Unsaved human plan" } });
    view.rerender(<RemediationPage engagementKey="acme" initialCaseId={8} onBack={() => {}} />);
    await screen.findByRole("heading", { name: "Second case" });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe(reviewedCase.verification_plan);
    view.rerender(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Baseline method") as HTMLInputElement).value).toBe("Unsaved baseline method");
    expect((screen.getByLabelText("Canary rationale") as HTMLTextAreaElement).value).toBe("Unsaved release rationale");
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Unsaved human plan");
    expect(updateRemediationVerificationPlan).not.toHaveBeenCalled();
    expect(updateRemediationBaseline).not.toHaveBeenCalled();
    expect(updateRemediationReleasePlan).not.toHaveBeenCalled();
  });

  it("retains failed-save drafts and clears only the successfully saved field", async () => {
    vi.mocked(updateRemediationVerificationPlan).mockRejectedValueOnce(new Error("Save unavailable"));
    let view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    fireEvent.change(screen.getByLabelText("Baseline method"), { target: { value: "Retained baseline" } });
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Retained plan" } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await screen.findByText("Save unavailable");
    view.unmount();
    view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Retained plan");
    expect((screen.getByLabelText("Baseline method") as HTMLInputElement).value).toBe("Retained baseline");
    await openSection("Review");
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await screen.findByText(/Verification plan saved/);
    const stored = JSON.parse(window.sessionStorage.getItem("vigil.remediation.drafts.acme:7") || "{}");
    expect(stored.plan).toBeUndefined();
    expect(stored.baseline.value.method).toBe("Retained baseline");
  });

  it("restores drafts without silently rebasing them onto changed server state", async () => {
    let view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Unsaved original draft" } });
    view.unmount();
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, verification_plan: "Changed server plan", worktree_revision: "new-commit", review_digest: "b".repeat(64) });
    view = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Unsaved original draft");
    expect(screen.getByText(/Server snapshot changed since these drafts began/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Discard local drafts" }));
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Changed server plan");
    expect(window.sessionStorage.getItem("vigil.remediation.drafts.acme:7")).toBeNull();
  });

  it("does not promise navigation-safe persistence when session storage fails", async () => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage denied"); });
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Page-local draft" } });
    expect((screen.getByLabelText("Human verification plan") as HTMLTextAreaElement).value).toBe("Page-local draft");
    expect(screen.getByText(/Draft storage unavailable/)).toBeTruthy();
    expect(screen.queryByText(/Drafts retained for this browser session/)).toBeNull();
    expect(updateRemediationVerificationPlan).not.toHaveBeenCalled();
  });
  it("does not let an older initial diff overwrite a newly saved plan's review package", async () => {
    const initialDiff = deferred<Awaited<ReturnType<typeof getRemediationDiff>>>();
    const nextDigest = "b".repeat(64);
    vi.mocked(getRemediationDiff).mockReturnValueOnce(initialDiff.promise).mockResolvedValue({ text: "Current saved package", truncated: false, bytes_total: 21, base_revision: "main123", head_revision: "abc123", review_digest: nextDigest });
    vi.mocked(updateRemediationVerificationPlan).mockImplementation(async (_key, _id, plan) => ({ ...reviewedCase, verification_plan: plan, review_digest: nextDigest }));
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await openSection("Review");
    fireEvent.change(screen.getByLabelText("Human verification plan"), { target: { value: "Updated rehearsed plan" } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await screen.findByText("Current saved package");
    await act(async () => initialDiff.resolve({ text: "Older initial package", truncated: false, bytes_total: 20, base_revision: "main123", head_revision: "abc123", review_digest: digest }));
    expect(screen.getByText("Current saved package")).toBeTruthy();
    expect(screen.queryByText("Older initial package")).toBeNull();
  });
  it("keeps a closed case inspectable while preventing edits to its plans", async () => {
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, status: "closed" });
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    expect(within(screen.getByRole("complementary", { name: "Case queue" })).getByText(/closed · 1 finding/)).toBeTruthy();
    expect(screen.getByLabelText("Baseline method").matches(":disabled")).toBe(true);
    expect(screen.getByLabelText("Human verification plan").matches(":disabled")).toBe(true);
    expect(screen.getByLabelText("Canary rationale").matches(":disabled")).toBe(true);
    await openSection("Evidence");
    expect(screen.getAllByRole("link", { name: /Open evidence/ }).length).toBe(2);
    expect(updateRemediationBaseline).not.toHaveBeenCalled();
    expect(updateRemediationVerificationPlan).not.toHaveBeenCalled();
    expect(updateRemediationReleasePlan).not.toHaveBeenCalled();
  });

  it("keeps intake prose prominent and exact administrative records in secondary disclosures", async () => {
    const approval = { id: 1, reviewer: "owner", approved_revision: "abc123", review_digest: digest };
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, approvals: [approval] });
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    expect(await screen.findByText(reviewedCase.snapshot.description as string)).toBeTruthy();
    const intake = screen.getByText("Original intake record").closest("details");
    expect(intake?.hasAttribute("open")).toBe(false);
    expect(intake?.querySelector("pre")?.textContent).toBe(JSON.stringify(reviewedCase.snapshot, null, 2));
    await openSection("Review");
    expect(screen.queryByText(/^Review snapshot:/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "History" }));
    const history = screen.getByRole("region", { name: "Case history" });
    expect(within(history).getByText(/Approved by owner/)).toBeTruthy();
    const raw = within(history).getByText("Raw case record").closest("details");
    raw!.open = true;
    fireEvent(raw!, new Event("toggle"));
    await waitFor(() => expect(raw?.querySelector("pre")).toBeTruthy());
    const record = JSON.parse(raw?.querySelector("pre")?.textContent || "{}");
    expect(record.review_digest).toBe(digest);
    expect(record.approvals).toEqual([approval]);
    expect(record.snapshot).toEqual(reviewedCase.snapshot);
    expect(record.deployment).toEqual(reviewedCase.deployment);
  });
  it("keeps the loaded detail when the current queue case is selected again", async () => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    const queue = screen.getByRole("complementary", { name: "Case queue" });
    fireEvent.click(within(queue).getByRole("button", { name: /Manage profile authorization/ }));
    expect(screen.getByRole("heading", { name: reviewedCase.title })).toBeTruthy();
    expect(screen.queryByText("Loading case…")).toBeNull();
    expect(getRemediationCase).toHaveBeenCalledTimes(1);
  });

  it("refreshes authoritative case state even when the code diff refresh fails", async () => {
    render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await screen.findByRole("heading", { name: reviewedCase.title });
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, title: "Updated case from backend" });
    vi.mocked(getRemediationDiff).mockRejectedValue(new Error("Worktree unavailable"));
    fireEvent.click(screen.getByRole("button", { name: "Refresh case" }));
    expect(await screen.findByRole("heading", { name: "Updated case from backend" })).toBeTruthy();
    await openSection("Review");
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Diff unavailable: Worktree unavailable");
    expect(screen.getByRole("button", { name: "Approve reviewed snapshot" }).hasAttribute("disabled")).toBe(true);
  });
  it("shows current severity, verification and causal identity in queue and linked detail", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    const queue = screen.getByRole("complementary", { name: "Case queue" });
    expect(await within(queue).findByText(/SEC-001 · high · confirmed/)).toBeTruthy();
    expect(within(queue).getByText("Current finding title")).toBeTruthy();
    expect(within(queue).getByText(/Root cause: authorization/)).toBeTruthy();
    const links = await screen.findByRole("region", { name: "Linked findings" });
    expect(within(links).getByText(/Root cause: authorization/)).toBeTruthy();
  });

  it("locks lookup, conflicting edits and navigation for a pending link replacement", async () => {
    const pending = deferred<RemediationCase>();
    vi.mocked(updateRemediationFindings).mockReturnValue(pending.promise);
    const second = { ...reviewedCase, id: 8, title: "Second case", source_key: "SEC-43" };
    vi.mocked(listRemediationCases).mockResolvedValue([reviewedCase, second]);
    const onBack = vi.fn();
    render(<RemediationPage engagementKey="acme" onBack={onBack} />);
    await findSibling();
    fireEvent.click(screen.getByRole("button", { name: "Add to case" }));
    expect((screen.getByLabelText("Source engagement") as HTMLSelectElement).disabled).toBe(true);
    expect((screen.getByLabelText("Finding slug") as HTMLInputElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Finding slug"), { target: { value: "SEC-003" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlink SEC-001" }));
    expect(updateRemediationFindings).toHaveBeenCalledTimes(1);
    for (const name of ["Review", "Refresh case", "← Engagements", /Second case/]) {
      const button = screen.getByRole("button", { name });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(button);
    }
    expect(onBack).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Baseline method").matches(":disabled")).toBe(true);
    expect(screen.getByLabelText("Human verification plan").matches(":disabled")).toBe(true);
    expect(screen.getByLabelText("Canary rationale").matches(":disabled")).toBe(true);
    await act(async () => pending.resolve({ ...reviewedCase, linked_findings: [] }));
    await waitFor(() => expect((screen.getByRole("button", { name: "Review" }) as HTMLButtonElement).disabled).toBe(false));
  });

  it("does not apply a late successful link mutation to a different routed case", async () => {
    const pending = deferred<RemediationCase>();
    vi.mocked(updateRemediationFindings).mockReturnValue(pending.promise);
    const second = { ...reviewedCase, id: 8, title: "Second case", source_key: "SEC-43" };
    vi.mocked(listRemediationCases).mockResolvedValue([reviewedCase, second]);
    vi.mocked(getRemediationCase).mockImplementation(async (_key, id) => id === 8 ? second : reviewedCase);
    const { rerender } = render(<RemediationPage engagementKey="acme" initialCaseId={7} onBack={() => {}} />);
    await findSibling();
    fireEvent.click(screen.getByRole("button", { name: "Add to case" }));
    rerender(<RemediationPage engagementKey="acme" initialCaseId={8} onBack={() => {}} />);
    await screen.findByRole("heading", { name: "Second case" });
    await act(async () => pending.resolve({ ...reviewedCase, title: "Old mutation result", linked_findings: [] }));
    expect(screen.getByRole("heading", { name: "Second case" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Old mutation result" })).toBeNull();
    expect(updateRemediationFindings).toHaveBeenCalledWith("acme", 7, [11, 22]);
  });
  it("keeps finding intake identity independent of current linked findings", async () => {
    const movedLinks = { ...reviewedCase, source_type: "finding", source_key: "11", linked_findings: [{ id: 22, engagement_key: "assessment", slug: "SEC-002", title: "Shared fix sibling", severity: "medium", verification_status: "confirmed", root_cause_key: "authorization" }] };
    vi.mocked(listRemediationCases).mockResolvedValue([movedLinks]);
    vi.mocked(getRemediationCase).mockResolvedValue(movedLinks);
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    expect(await screen.findByText("Finding #11")).toBeTruthy();
    expect(await screen.findByRole("link", { name: /Shared fix sibling/ })).toBeTruthy();
    expect(screen.getByText(/Original proof receipts were not captured/)).toBeTruthy();
  });
  it("separates current linked finding state from immutable intake and links exactly", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    const link = await screen.findByRole("link", { name: /Current finding title/ });
    expect(link.getAttribute("href")).toBe("#/engagements/assessment?tab=findings&finding=SEC-001");
    expect(screen.getByText("confirmed")).toBeTruthy();
    expect(screen.getByText("high")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Intake snapshot" })).toBeTruthy();
  });

  it("resolves a finding in the selected source before adding its canonical identity", async () => {
    vi.mocked(getAssessmentFinding).mockResolvedValue({ id: 22, slug: "SEC-002", title: "Same root cause", severity: "medium", verification_status: "unreviewed", root_cause_key: "authorization" } as Awaited<ReturnType<typeof getAssessmentFinding>>);
    vi.mocked(updateRemediationFindings).mockResolvedValue({ ...reviewedCase, linked_findings: [...reviewedCase.linked_findings, { id: 22, engagement_key: "assessment", slug: "SEC-002", title: "Same root cause", severity: "medium", verification_status: "unreviewed", root_cause_key: "authorization" }] });
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Link finding" }));
    fireEvent.change(await screen.findByLabelText("Source engagement"), { target: { value: "assessment" } });
    fireEvent.change(screen.getByLabelText("Finding slug"), { target: { value: "SEC-002" } });
    fireEvent.click(screen.getByRole("button", { name: "Find finding" }));
    await screen.findByText("Same root cause");
    expect(updateRemediationFindings).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Add to case" }));
    await waitFor(() => expect(updateRemediationFindings).toHaveBeenCalledWith("acme", 7, [11, 22]));
    expect(await screen.findByRole("link", { name: /Same root cause/ })).toBeTruthy();
  });
  it("shows a failed queue load instead of an empty queue and retries", async () => {
    vi.mocked(listRemediationCases).mockRejectedValueOnce(new Error("Queue unavailable"));
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Queue unavailable");
    expect(screen.queryByText("No remediation cases imported yet.")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry loading cases" }));
    expect(await screen.findByLabelText("Human verification plan")).toBeTruthy();
    expect(listRemediationCases).toHaveBeenCalledTimes(2);
    expect(screen.queryByText("Queue unavailable")).toBeNull();
  });

  it("shows a failed case load instead of perpetual loading and retries", async () => {
    vi.mocked(getRemediationCase).mockRejectedValueOnce(new Error("Case unavailable"));
    render(<RemediationPage engagementKey="acme" onBack={() => {}} initialCaseId={7} />);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Case unavailable");
    expect(screen.queryByText("Loading case…")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry loading case" }));
    expect(await screen.findByLabelText("Human verification plan")).toBeTruthy();
    expect(getRemediationCase).toHaveBeenCalledTimes(2);
    expect(screen.queryByText("Case unavailable")).toBeNull();
  });

  it("clears the previous case when switching engagements", async () => {
    vi.mocked(listRemediationCases).mockImplementation((key) => key === "first"
      ? Promise.resolve([reviewedCase])
      : new Promise(() => {}));
    const { rerender } = render(<RemediationPage engagementKey="first" onBack={() => {}} />);
    expect(await screen.findByText(reviewedCase.snapshot.description as string)).toBeTruthy();

    rerender(<RemediationPage engagementKey="second" onBack={() => {}} />);

    expect(screen.queryByText(reviewedCase.snapshot.description as string)).toBeNull();
    expect(screen.queryByRole("button", { name: "Save plan" })).toBeNull();
  });

  it("shows the queue, source snapshot, duplicate hint, worktree and deployment identity", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);

    expect(await screen.findByText("Manage profile authorization")).toBeTruthy();
    expect(screen.getByText("SEC-42")).toBeTruthy();
    expect(await screen.findByText(reviewedCase.snapshot.description as string)).toBeTruthy();
    expect(screen.getByText(/Case #9/)).toBeTruthy();
    expect(screen.getByText("/worktrees/sec-42")).toBeTruthy();
    expect(screen.getAllByText("abc123").length).toBeGreaterThan(0);
    await openSection("Evidence");
    expect(screen.getByAltText("happy-path.png").getAttribute("src")).toBe("/evidence/7/3");
    expect(screen.getByText("Authorization regression")).toBeTruthy();
    expect(screen.getByText("Environment: development")).toBeTruthy();
    expect(screen.getByText(/php artisan test --filter=ProfileAuthorization/)).toBeTruthy();
    await openSection("Review");
    expect(await screen.findByText(/deny other users/)).toBeTruthy();
  });

  it("saves a changed human plan and requires an explicit approval action", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
    const plan = await screen.findByLabelText("Human verification plan");
    fireEvent.change(plan, { target: { value: "Open Manage as owner; save the verified fixture." } });
    fireEvent.click(screen.getByRole("button", { name: "Save plan" }));
    await waitFor(() => expect(updateRemediationVerificationPlan).toHaveBeenCalledWith("acme", 7,
      "Open Manage as owner; save the verified fixture."));
    expect(approveRemediationCase).not.toHaveBeenCalled();
    await waitFor(() => expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true));
    await screen.findByText(/deny other users/);
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve reviewed snapshot" }));
    await waitFor(() => expect(approveRemediationCase).toHaveBeenCalledWith("acme", 7, "owner", digest, "ui"));
  });

  it("never submits approval while plan edits are unsaved", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
    const plan = await screen.findByLabelText("Human verification plan");
    fireEvent.change(plan, { target: { value: "A changed procedure" } });
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("blocks approval when the review diff is truncated", async () => {
    vi.mocked(getRemediationDiff).mockResolvedValue({ text: "partial diff", truncated: true, bytes_total: 2000000, base_revision: "main123", head_revision: "abc123", review_digest: digest });
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
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
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
    expect(await screen.findByText("Red Laravel test output")).toBeTruthy();
    expect(screen.getByText("Green Laravel test output")).toBeTruthy();
    expect(screen.getByText("Stagehand happy-path result, script, and screenshot")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
    expect(approveRemediationCase).not.toHaveBeenCalled();
  });

  it("blocks approval when the diff digest differs from the case", async () => {
    vi.mocked(getRemediationDiff).mockResolvedValue({ text: "changed diff", truncated: false, bytes_total: 12, base_revision: "main123", head_revision: "abc123", review_digest: "b".repeat(64) });
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
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
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Review");
    await screen.findByText("original diff");
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "owner" } });
    fireEvent.click(screen.getByRole("button", { name: "Approve reviewed snapshot" }));
    expect(await screen.findByText("new diff")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("Review package changed");
  });

  it("saves the production canary decision and monitoring plan before approval", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Delivery");
    const decision = await screen.findByLabelText("Production canary decision");
    fireEvent.change(decision, { target: { value: "required" } });
    fireEvent.change(screen.getByLabelText("Canary rationale"), { target: { value: "Needs human production proof" } });
    fireEvent.change(screen.getByLabelText("Safe canary procedure"), { target: { value: "Use owner account and harmless fixture" } });
    fireEvent.change(screen.getByLabelText("Monitoring plan"), { target: { value: "Watch profile authorization errors" } });
    await openSection("Review");
    expect((screen.getByRole("button", { name: "Approve reviewed snapshot" }) as HTMLButtonElement).disabled).toBe(true);
    await openSection("Delivery");
    fireEvent.click(screen.getByRole("button", { name: "Save release plan" }));
    await waitFor(() => expect(updateRemediationReleasePlan).toHaveBeenCalledWith("acme", 7, {
      production_canary_decision: "required", production_canary_rationale: "Needs human production proof", safe_procedure: "Use owner account and harmless fixture", monitoring: "Watch profile authorization errors",
    }));
  });

  it("records the owner's decision when baseline reproduction was unavailable", async () => {
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await screen.findByLabelText("Baseline outcome");
    fireEvent.change(screen.getByLabelText("Baseline outcome"), { target: { value: "code_test_confirmed" } });
    fireEvent.change(screen.getByLabelText("Baseline method"), { target: { value: "Laravel failing test" } });
    fireEvent.change(screen.getByLabelText("Baseline proved"), { target: { value: "Code and failing test support report" } });
    fireEvent.change(screen.getByLabelText("Owner decision"), { target: { value: "proceed" } });
    fireEvent.change(screen.getByLabelText("Owner actor"), { target: { value: "owner" } });
    fireEvent.change(screen.getByLabelText("Owner reason"), { target: { value: "Safe local replay unavailable" } });
    fireEvent.click(screen.getByRole("button", { name: "Save baseline" }));
    await waitFor(() => expect(updateRemediationBaseline).toHaveBeenCalledWith("acme", 7, {
      outcome: "code_test_confirmed", method: "Laravel failing test", proved: "Code and failing test support report", owner_decision: "proceed", owner_actor: "owner", owner_reason: "Safe local replay unavailable",
    }));
  });

  it("records a human development result against the confirmed deployed revision", async () => {
    vi.mocked(listRemediationCases).mockResolvedValue([{ ...reviewedCase, status: "development" }]);
    vi.mocked(getRemediationCase).mockResolvedValue({ ...reviewedCase, status: "development" });
    render(<RemediationPage engagementKey="acme" onBack={() => {}} />);
    await openSection("Delivery");
    await screen.findByLabelText("Human verification result");
    fireEvent.change(screen.getByLabelText("Human verification actor"), { target: { value: "owner" } });
    fireEvent.change(screen.getByLabelText("Human verification notes"), { target: { value: "Followed the saved steps; owner could save." } });
    fireEvent.change(screen.getByLabelText("Human verification result"), { target: { value: "passed" } });
    fireEvent.click(screen.getByRole("button", { name: "Record human verification" }));
    await waitFor(() => expect(recordRemediationHumanVerification).toHaveBeenCalledWith("acme", 7, {
      actor: "owner", result: "passed", observed_revision: "abc123", notes: "Followed the saved steps; owner could save.",
    }));
  });
});
