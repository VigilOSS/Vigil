// @vitest-environment jsdom

// The Submission pane renders the operator's own captures. Two properties are pinned
// here and neither is styling: the page shows the recorded bytes, and the copy
// chip beside them hands back the same bytes. A capture that the pane rewrites
// is a capture the reader cannot check against the target, and it puts the page
// out of step with lib/findingMarkdown.ts — which fences these same fields
// verbatim (AGENTS.md: never degrade the operator's own data; ADR 0019).

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Profiler } from "react";

import { ToastProvider, ToastViewport } from "../contexts/ToastContext";
import {
  getAssessmentFinding,
  getAssessmentFindingTransition,
  listAssessmentFindingGroups,
  listAssessmentFindingLinks,
  listAssessmentFindingTransitions,
  resolveIntelIds,
  getFindingRemediationCases,
  createRemediationFromFinding,
  listEngagements,
} from "../lib/api";
import { FindingsTab, HistoryPane, RelatedIntelSection, SubmissionPane } from "./FindingsTab";
import type { Derived } from "./FindingsTab";

vi.mock("./FindingsGrid", () => ({ default: ({ rows, onOpen, onOrderChange }: { rows: Derived[]; onOpen: (slug: string) => void; onOrderChange?: (slugs: string[]) => void }) => (
  <div><button onClick={() => onOrderChange?.(rows.map((row) => row.slug).reverse())}>Sort descending</button>{rows.map((row) => <button key={row.slug} onClick={() => onOpen(row.slug)}>Grid {row.title}</button>)}</div>
) }));

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getAssessmentFinding: vi.fn(),
    getAssessmentFindingTransition: vi.fn(),
    listAssessmentFindingGroups: vi.fn(),
    listAssessmentFindingLinks: vi.fn(),
    listAssessmentFindingTransitions: vi.fn(),
    resolveIntelIds: vi.fn(),
    getFindingRemediationCases: vi.fn(),
    createRemediationFromFinding: vi.fn(),
    listEngagements: vi.fn(),
  };
});

const writeText = vi.fn();

function derived(over: Partial<Derived>): Derived {
  return { slug: "VA-001", title: "T", references: [], links: [], ...over } as unknown as Derived;
}

function renderPane(over: Partial<Derived>) {
  return render(<SubmissionPane d={derived(over)} proseMode="rendered" toast={() => {}} />);
}

beforeEach(() => {
  writeText.mockReset();
  Object.defineProperty(window.navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
  vi.mocked(resolveIntelIds).mockReset();
  vi.mocked(getAssessmentFindingTransition).mockReset();
  vi.mocked(getAssessmentFinding).mockReset();
  vi.mocked(listAssessmentFindingGroups).mockReset().mockResolvedValue([]);
  vi.mocked(listAssessmentFindingLinks).mockReset().mockResolvedValue([]);
  vi.mocked(listAssessmentFindingTransitions).mockReset().mockResolvedValue([]);
  vi.mocked(getFindingRemediationCases).mockReset().mockResolvedValue([]);
  vi.mocked(createRemediationFromFinding).mockReset();
  vi.mocked(listEngagements).mockReset().mockResolvedValue([]);
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/demo?tab=findings");
});

afterEach(cleanup);

describe("SubmissionPane evidence", () => {
  it("renders authored Markdown in steps and evidence", () => {
    const { container } = renderPane({
      steps_to_reproduce: ["1. Run `curl https://target.example`\n2. Observe **admin access**."],
      evidence: "#### Authorization bypass\n\nThe response returned `role: admin`.",
    });

    expect(container.querySelector("ol li code")?.textContent).toBe("curl https://target.example");
    expect(container.querySelector("ol li strong")?.textContent).toBe("admin access");
    expect(screen.getByRole("heading", { name: "Authorization bypass" })).toBeTruthy();
    expect(container.querySelector("p code")?.textContent).toBe("role: admin");
  });

  it("renders and copies a capture byte for byte", () => {
    // Leading and trailing whitespace is the finding on a padding or
    // header-stripping bug, and the clipboard has to carry it.
    const capture = "\n  leading and trailing whitespace is the finding   \n\n";
    renderPane({ evidence: capture });

    const copy = screen.getByRole("button", { name: /copy evidence/i });
    copy.click();
    expect(writeText).toHaveBeenCalledWith(capture);
    expect(screen.getByText(capture.trim()).textContent).toBe(capture);
  });

  it("shows a capture that is nothing but whitespace", () => {
    // The Submission tab badge counts `d.evidence` on plain truthiness, so a
    // whitespace-only capture was counted and then rendered as nothing at all —
    // the section, its heading and its copy chip all disappeared. A blank or
    // padded response body IS the proof on a whitespace-sensitive finding.
    const { container } = renderPane({ evidence: "   " });

    expect(screen.getByText("Evidence")).toBeTruthy();
    const pre = container.querySelector("pre.pre.resp");
    expect(pre?.textContent).toBe("   ");
    screen.getByRole("button", { name: /copy evidence/i }).click();
    expect(writeText).toHaveBeenCalledWith("   ");
  });
});

describe("SubmissionPane request", () => {
  it("shows the recorded method in the case it was recorded", () => {
    // A case-sensitive-routing probe records `get` on purpose. Upper-casing it
    // showed a request the finding never made, and disagreed with this
    // component's own Copy-as-Markdown, which keeps the case (see
    // lib/findingMarkdown.test.ts).
    const { container } = renderPane({
      poc_request: { method: "get", url: "https://t.example/x" },
    });

    const pre = container.querySelector("pre.pre.req");
    expect(pre?.textContent).toContain("get https://t.example/x");
    expect(pre?.textContent).not.toContain("GET https://t.example/x");
  });
});

describe("SubmissionPane structure", () => {
  it("renders the submission contract in canonical order", () => {
    const { container } = renderPane({
      summary: "Summary",
      steps_to_reproduce: ["1. Reproduce"],
      evidence: "Evidence",
      attack_scenario: "Attack scenario",
      impact: "Impact",
      remediation: "Remediation",
    });

    const text = container.textContent || "";
    const headings = [
      "Summary",
      "Steps to reproduce",
      "Evidence",
      "Attack scenario",
      "Impact",
      "Remediation",
    ];
    for (let i = 1; i < headings.length; i += 1) {
      expect(text.indexOf(headings[i - 1])).toBeLessThan(text.indexOf(headings[i]));
    }
  });

  it("keeps payload and HTTP captures under one supporting-captures disclosure", () => {
    renderPane({
      poc_code: "curl https://target.example",
      poc_request: "GET / HTTP/1.1",
      poc_response: "HTTP/1.1 200 OK",
    });

    expect(screen.getByText("Supporting captures")).toBeTruthy();
  });
});

describe("HistoryPane", () => {
  it("previews only the first 100 words and reveals the complete Markdown reason", () => {
    const reason = Array.from({ length: 105 }, (_, i) => `word${i + 1}`).join(" ");
    const { container } = render(
      <HistoryPane
        loading={false}
        error={null}
        transitions={[{
          id: 1,
          actor: "operator",
          action: "updated",
          from_workflow_status: "active",
          to_workflow_status: "active",
          from_verification_status: "unreviewed",
          to_verification_status: "unreviewed",
          verification_event_version: 1,
          from_severity: "medium",
          to_severity: "medium",
          reason_code: "review",
          reason_text: reason,
          artifact_ref: "",
          metadata_json: "{}",
          created_at: new Date().toISOString(),
          verification_audit: {
            proof_receipt_ids: [],
            proof_receipt_total: 0,
            counter_checks: [],
            counter_check_total: 0,
            severity_variances: [],
            severity_variance_total: 0,
            record_limit: 20,
            truncated: false,
          },
        }]}
      />,
    );

    const summary = container.querySelector(".history-reason > summary");
    expect(summary?.textContent).toContain("word100");
    expect(summary?.textContent).not.toContain("word101");
    expect(screen.getByText("Read full reason")).toBeTruthy();
    fireEvent.click(summary!);
    expect(screen.getByText(/word101 word102 word103/)).toBeTruthy();
  });

  it("loads the lossless transition only when a summary row is opened", async () => {
    vi.mocked(getAssessmentFindingTransition).mockResolvedValue({
      id: 7,
      actor: "operator",
      action: "updated",
      from_workflow_status: "active",
      to_workflow_status: "active",
      from_verification_status: "unreviewed",
      to_verification_status: "confirmed",
      verification_event_version: 1,
      from_severity: "medium",
      to_severity: "medium",
      reason_code: "review",
      reason_text: "Full **Markdown** reason",
      artifact_ref: "",
      metadata_json: "{}",
      details_before_json: "{\"summary\":\"before\"}",
      details_after_json: "{\"summary\":\"after\"}",
      notes_before_json: "before notes",
      notes_after_json: "after notes",
      created_at: new Date().toISOString(),
      verification_audit: {
        proof_receipt_ids: [], proof_receipt_total: 0, counter_checks: [],
        counter_check_total: 0, severity_variances: [], severity_variance_total: 0,
        record_limit: 20, truncated: false,
      },
    });
    const { container } = render(
      <HistoryPane
        engagementKey="demo"
        findingSlug="VA-001"
        loading={false}
        error={null}
        transitions={[{
          id: 7,
          actor: "operator",
          action: "updated",
          from_workflow_status: "active",
          to_workflow_status: "active",
          from_verification_status: "unreviewed",
          to_verification_status: "confirmed",
          verification_event_version: 1,
          from_severity: "medium",
          to_severity: "medium",
          reason_code: "review",
          artifact_ref: "",
          created_at: new Date().toISOString(),
          reason_preview: "Preview reason",
          reason_word_count: 2,
          reason_truncated: false,
          has_snapshot: true,
        }]}
      />,
    );

    expect(getAssessmentFindingTransition).not.toHaveBeenCalled();
    fireEvent.click(container.querySelector(".history-reason > summary")!);
    expect(await screen.findByText("Markdown")).toBeTruthy();
    expect(getAssessmentFindingTransition).toHaveBeenCalledWith("demo", "VA-001", 7);
    fireEvent.click(screen.getByText("Changed content"));
    expect(screen.getByText("Details before")).toBeTruthy();
    expect(screen.getByText("Notes after")).toBeTruthy();
  });

  it("keeps an empty-reason audit row openable even without a snapshot", async () => {
    vi.mocked(getAssessmentFindingTransition).mockResolvedValue({
      id: 8, actor: "system", action: "updated",
      from_workflow_status: "active", to_workflow_status: "active",
      from_verification_status: "unreviewed", to_verification_status: "unreviewed",
      verification_event_version: 1, from_severity: "low", to_severity: "low",
      reason_code: "sync", reason_text: "", artifact_ref: "", metadata_json: "{}",
      details_before_json: "{\"state\":\"before\"}", details_after_json: "{\"state\":\"after\"}",
      created_at: new Date().toISOString(),
      verification_audit: {
        proof_receipt_ids: [], proof_receipt_total: 0, counter_checks: [],
        counter_check_total: 0, severity_variances: [], severity_variance_total: 0,
        record_limit: 20, truncated: false,
      },
    });
    render(
      <HistoryPane engagementKey="demo" findingSlug="VA-001" loading={false} error={null}
        transitions={[{
          id: 8, actor: "system", action: "updated",
          from_workflow_status: "active", to_workflow_status: "active",
          from_verification_status: "unreviewed", to_verification_status: "unreviewed",
          verification_event_version: 1, from_severity: "low", to_severity: "low",
          reason_code: "sync", artifact_ref: "", created_at: new Date().toISOString(),
          reason_preview: "", reason_word_count: 0, reason_truncated: false, has_snapshot: false,
        }]}
      />,
    );

    fireEvent.click(screen.getByText("View details"));
    expect(await screen.findByText("Changed content")).toBeTruthy();
    expect(getAssessmentFindingTransition).toHaveBeenCalledWith("demo", "VA-001", 8);
  });

  it("renders the structured confirmation falsification check from transition metadata", async () => {
    vi.mocked(getAssessmentFindingTransition).mockResolvedValue({
      id: 12, actor: "verifier", action: "verified_confirmed",
      from_workflow_status: "active", to_workflow_status: "active",
      from_verification_status: "unreviewed", to_verification_status: "confirmed",
      verification_event_version: 2, from_severity: "high", to_severity: "high",
      reason_code: "verified", reason_text: "", artifact_ref: "",
      metadata_json: JSON.stringify({ confirm_check: {
        method: "Replay as a non-admin",
        attempted_falsification: "Try the same request without the privileged role",
        expected_result: "Access denied",
        observed_result: "The endpoint still returned the protected record",
        completed: true,
        proof_receipt_ids: [41, 42],
      } }),
      created_at: new Date().toISOString(),
      verification_audit: {
        proof_receipt_ids: [], proof_receipt_total: 0, counter_checks: [],
        counter_check_total: 0, severity_variances: [], severity_variance_total: 0,
        record_limit: 20, truncated: false,
      },
    });
    const { container } = render(
      <HistoryPane engagementKey="demo" findingSlug="VA-001" loading={false} error={null}
        transitions={[{
          id: 12, actor: "verifier", action: "verified_confirmed",
          from_workflow_status: "active", to_workflow_status: "active",
          from_verification_status: "unreviewed", to_verification_status: "confirmed",
          verification_event_version: 2, from_severity: "high", to_severity: "high",
          reason_code: "verified", artifact_ref: "", created_at: new Date().toISOString(),
          reason_preview: "", reason_word_count: 0, reason_truncated: false, has_snapshot: false,
        }]}
      />,
    );

    fireEvent.click(screen.getByText("View details"));
    expect(await screen.findByText("Structured confirmation check")).toBeTruthy();
    expect(screen.getByText("Try the same request without the privileged role")).toBeTruthy();
    expect(screen.getByText("The endpoint still returned the protected record")).toBeTruthy();
    expect(screen.getByText("41, 42")).toBeTruthy();
    expect(container.textContent).not.toContain("[object Object]");
  });
});

describe("finding claim review state", () => {
  it("shows the pending independent review transition and current claim digest", async () => {
    const finding = {
      id: 4,
      slug: "VA-004",
      title: "Authorization bypass",
      severity: "high",
      workflow_status: "active",
      submission_status: "none",
      verification_status: "confirmed",
      canonical_location: "/admin",
      summary: "Ordinary users can access administrator data.",
      source_name: "vulnerability-analyst",
      updated_at: "2026-09-25T12:00:00Z",
      row_version: 8,
      evidence_ref: "",
      notes: "",
      defect_family: "web-app-auth",
      root_cause_key: "authz-check",
      auth_context: "ordinary user",
      details: {},
      provenance: {},
      verification_audit: undefined,
    };
    vi.mocked(getAssessmentFinding).mockResolvedValue({
      ...finding,
      verification_audit: {
        proof_receipt_ids: [31], proof_receipt_total: 1,
        counter_checks: [], counter_check_total: 0,
        severity_variances: [], severity_variance_total: 0,
        claim_review_pending: true,
        claim_transition_id: 77,
        current_claim_sha256: "a".repeat(64),
        record_limit: 20, truncated: false,
      },
    } as never);
    render(<ToastProvider><FindingsTab
      engagementKey="demo"
      findings={[finding] as never[]}
      fallbackFindings={[]}
      chains={[]}
      chainLinks={[]}
      assessmentRefreshVersion={0}
    /></ToastProvider>);

    fireEvent.click(await screen.findByText("Authorization bypass"));
    expect(await screen.findByText("Claim review pending")).toBeTruthy();
    const notice = screen.getByRole("status", { name: "Claim review pending" });
    expect(notice.querySelector("details")?.open).toBe(false);
    const disclosure = screen.getByText("Claim review details").closest("details")!;
    fireEvent.click(screen.getByText("Claim review details"));
    expect(disclosure.textContent).toContain("claim transition 77");
    expect(disclosure.textContent).toContain("a".repeat(64));
  });
});

describe("finding investigation workspace", () => {
  const finding = {
    id: 12, slug: "VA-012", title: "Shared claim", severity: "high",
    workflow_status: "active", submission_status: "none", verification_status: "confirmed",
    canonical_location: "https://target.example/account", summary: "One claim with runtime and source evidence.",
    source_name: "vulnerability-analyst", updated_at: "2026-10-01T12:00:00Z", row_version: 1,
    evidence_ref: "proof/account.txt", notes: "", defect_family: "authorization",
    root_cause_key: "missing-owner-check", auth_context: "ordinary user", evidence_type: "network-confirmed",
    details: { entry_point: "AccountController.show", sink: "Account.find", taint_path: ["request.account_id", "Account.find"], poc_request: "GET /account HTTP/1.1\nAuthorization: Bearer operator-token" },
    provenance: { code_snapshot: { repo_id: 3, repo_generation: 2, source_manifest_digest: "a".repeat(64) } },
    proof_receipts: [{ id: 41, run_id: 7, evidence_kind: "http_exchange", evidence_health: "missing", created_at: "2026-10-01T12:00:00Z" }],
    verification_audit: { proof_receipt_ids: [40, 41], proof_receipt_total: 2, counter_checks: [], counter_check_total: 0, severity_variances: [], severity_variance_total: 0, record_limit: 100, truncated: false },
  };

  function workspace(over = {}) {
    const current = { ...finding, ...over };
    vi.mocked(getAssessmentFinding).mockResolvedValue(current as never);
    return render(<ToastProvider><FindingsTab engagementKey="demo" findings={[current] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" /><ToastViewport /></ToastProvider>);
  }

  it("resolves a routed finding outside the loaded queue with one exact lookup", async () => {
    vi.mocked(getAssessmentFinding).mockResolvedValue({ ...finding, slug: "VA-888", title: "Outside queue" } as never);
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-888" /></ToastProvider>);
    expect(await screen.findByRole("heading", { name: "Outside queue" })).toBeTruthy();
    expect(getAssessmentFinding).toHaveBeenCalledWith("demo", "VA-888");
    expect(getAssessmentFinding).toHaveBeenCalledOnce();
  });

  it.each(["VA012", "FINDING-VA-012"])("opens a backend-resolved %s alias and replaces the route with its canonical identity", async (alias) => {
    window.history.replaceState({}, "", `#/engagements/demo?tab=findings&finding=${alias}&dtab=history`);
    const replace = vi.spyOn(window.history, "replaceState");
    vi.mocked(getAssessmentFinding).mockResolvedValue(finding as never);
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug={alias} initialDrawerTab="history" /></ToastProvider>);
    expect(await screen.findByRole("heading", { name: "Shared claim" })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=findings&finding=VA-012&dtab=history");
    expect(replace).toHaveBeenCalledOnce();
    expect(getAssessmentFinding).toHaveBeenCalledWith("demo", alias);
    expect(listAssessmentFindingTransitions).toHaveBeenCalledWith("demo", "VA-012");
    expect(screen.queryByRole("alert")).toBeNull();
    replace.mockRestore();
  });

  it("reopens the same canonical finding when a second alias arrives without remounting", async () => {
    vi.mocked(getAssessmentFinding).mockResolvedValue(finding as never);
    const props = { engagementKey: "demo", findings: [], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0 };
    const view = render(<ToastProvider><FindingsTab {...props} initialFindingSlug="VA012" /></ToastProvider>);
    await screen.findByRole("region", { name: "Finding investigation" });
    view.rerender(<ToastProvider><FindingsTab {...props} initialFindingSlug="FINDING-VA-012" /></ToastProvider>);
    await act(async () => {});
    expect(getAssessmentFinding).toHaveBeenCalledWith("demo", "FINDING-VA-012");
    expect(screen.getByRole("region", { name: "Finding investigation" })).toBeTruthy();
  });

  it("shows an unavailable routed finding with a bounded retry instead of dropping the association", async () => {
    vi.mocked(getAssessmentFinding).mockRejectedValueOnce(new Error("Finding does not exist")).mockResolvedValueOnce({ ...finding, slug: "VA-888", title: "Restored association" } as never);
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-888" /></ToastProvider>);
    expect((await screen.findByRole("alert")).textContent).toContain("Finding VA-888 unavailable: Finding does not exist");
    expect(screen.queryByRole("region", { name: "Finding investigation" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry finding lookup" }));
    expect(await screen.findByRole("heading", { name: "Restored association" })).toBeTruthy();
  });

  it("focuses the dock without allowing native focus scrolling to hide its heading", async () => {
    const focus = vi.spyOn(HTMLElement.prototype, "focus");
    workspace();
    await screen.findByRole("region", { name: "Finding investigation" });
    expect(focus).toHaveBeenCalledWith({ preventScroll: true });
    focus.mockRestore();
  });

  it.each([
    ["Copy submission as Markdown", "Copied submission as Markdown"],
    ["Copy link to this finding", "Link copied"],
  ])("waits for %s clipboard writes and exposes a rejected-write fallback", async (label, message) => {
    let resolve!: () => void;
    writeText.mockReturnValueOnce(new Promise<void>((done) => { resolve = done; }));
    workspace();
    fireEvent.click(await screen.findByRole("button", { name: label }));
    expect(screen.queryByText(message)).toBeNull();
    resolve();
    await screen.findByText(message);
    const failure = Promise.reject(new Error("denied"));
    void failure.catch(() => {});
    writeText.mockReturnValueOnce(failure);
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/Could not copy/);
  });

  it.each(["Copy submission as Markdown", "Copy link to this finding"])("does not mark finding B copied when a pending %s write from A finishes", async (label) => {
    let resolve!: () => void;
    const pending = new Promise<void>((done) => { resolve = done; });
    writeText.mockReturnValueOnce(pending);
    const records = [finding, { ...finding, id: 13, slug: "VA-013", title: "Second finding" }];
    const view = render(<ToastProvider><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: label }));
    view.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-013" /></ToastProvider>);
    await screen.findByRole("heading", { name: "Second finding" });
    await act(async () => { resolve(); await pending; });
    expect(screen.getByRole("button", { name: label }).querySelector(".lucide-check")).toBeNull();
  });

  it("focuses the selected finding and offers an explicit return to the preserved results", async () => {
    workspace();
    expect(await screen.findByRole("region", { name: "Finding investigation" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
    expect(screen.queryByRole("region", { name: "Finding queue" })).toBeNull();
    expect(screen.queryByRole("textbox", { name: "Search findings" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    expect(screen.getByRole("region", { name: "Finding queue" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Finding investigation" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=findings");
  });

  it("preserves filters, results page, and review section through previous/next and return", async () => {
    const records = Array.from({ length: 28 }, (_, index) => ({ ...finding, id: index + 1, slug: `VA-${index + 1}`, title: `Claim ${String(index + 1).padStart(2, "0")}` }));
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    fireEvent.change(screen.getByPlaceholderText(/Search any field/), { target: { value: "Claim" } });
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText(/Page 2 of 2/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Claim 26/ }));
    await screen.findByRole("region", { name: "Finding investigation" });
    fireEvent.click(screen.getByRole("button", { name: /^History/ }));
    fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
    await screen.findByRole("heading", { name: "Claim 27" });
    expect(window.location.hash).toContain("finding=VA-27");
    expect(window.location.hash).toContain("dtab=history");
    expect(screen.getByRole("button", { name: /^History/ }).getAttribute("aria-current")).toBe("page");
    fireEvent.click(screen.getByRole("button", { name: "Previous finding" }));
    await screen.findByRole("heading", { name: "Claim 26" });
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    expect((screen.getByPlaceholderText(/Search any field/) as HTMLInputElement).value).toBe("Claim");
    expect(screen.getByText(/Page 2 of 2/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Claim 26/ }));
    expect(screen.getByRole("button", { name: /^History/ }).getAttribute("aria-current")).toBe("page");
  });

  it("does not reset the current result page when the same ledger refreshes", async () => {
    const records = Array.from({ length: 28 }, (_, index) => ({ ...finding, id: index + 1, slug: `VA-${index + 1}`, title: `Claim ${String(index + 1).padStart(2, "0")}` }));
    const view = render(<ToastProvider><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText(/Page 2 of 2/)).toBeTruthy();
    view.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={records.map((item) => ({ ...item })) as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={1} /></ToastProvider>);
    expect(screen.getByText(/Page 2 of 2/)).toBeTruthy();
  });
  it("commits a filter change directly to its first result page without a transient old page", async () => {
    const records = Array.from({ length: 56 }, (_, index) => ({ ...finding, id: index + 1, slug: `VA-${index + 1}`, title: `Claim ${String(index + 1).padStart(2, "0")}`, workflow_status: index < 28 ? "active" : "blocked" }));
    const committedPages: string[] = [];
    render(<ToastProvider><Profiler id="filter-page" onRender={() => {
      if (document.querySelector(".filter-chip.is-active")) committedPages.push(document.querySelector(".pager")?.textContent ?? "");
    }}><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></Profiler></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: /^Active/ }));
    expect(committedPages.length).toBeGreaterThan(0);
    expect(committedPages.every((page) => page.includes("Page 1 of 2"))).toBe(true);
  });

  it("keeps its reset control mounted and exposes the selected filter to assistive technology", async () => {
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    const clear = screen.getByRole("button", { name: /^Clear all/ }) as HTMLButtonElement;
    expect(clear.disabled).toBe(true);
    const high = within(screen.getByRole("group", { name: "Severity filters" })).getByRole("button", { name: /^high/ });
    high.focus();
    fireEvent.click(high);
    expect(high.getAttribute("aria-pressed")).toBe("true");
    expect(document.activeElement).toBe(high);
    expect(screen.getByRole("button", { name: /^Clear all/ })).toBe(clear);
    expect(clear.disabled).toBe(false);
  });

  it.each([{ group: "Severity filters", name: /^low/ }, { group: "Workflow filters", name: /^Blocked/ }, { group: "Verification filters", name: /^Verified/ }])("keeps an active zero-count $group option removable after refresh", async ({ name }) => {
    const first = { ...finding, verification_status: "unreviewed" };
    const second = { ...finding, id: 13, slug: "VA-013", title: "Z second claim", severity: "low", workflow_status: "blocked" };
    const props = { engagementKey: "demo", findings: [first, second] as never[], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0 };
    const view = render(<ToastProvider><FindingsTab {...props} /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name }));
    view.rerender(<ToastProvider><FindingsTab {...props} findings={[first] as never[]} assessmentRefreshVersion={1} /></ToastProvider>);
    const active = screen.getByRole("button", { name });
    expect(active.getAttribute("aria-pressed")).toBe("true");
    expect(active.textContent).toContain("0");
    fireEvent.click(active);
    expect(screen.getByRole("button", { name: /Shared claim/ })).toBeTruthy();
  });
  it("distinguishes a genuinely empty ledger from filtered results", async () => {
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    expect(screen.getByText("No findings recorded yet.")).toBeTruthy();
    expect(screen.queryByText("No findings match.")).toBeNull();
  });
  it("labels engagement-wide root group counts separately from the current filtered results", async () => {
    vi.mocked(listAssessmentFindingGroups).mockResolvedValue([{ root: finding, siblings: [], sibling_count: 0, residual_path_count: 0 }] as never);
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByText("Loading groups")).toBeNull());
    fireEvent.change(screen.getByRole("textbox", { name: "Search findings" }), { target: { value: "does-not-match" } });
    expect(screen.getByText("1 engagement root-cause groups")).toBeTruthy();
    expect(screen.getByText("No findings match.")).toBeTruthy();
  });
  it("keeps a filtered sibling's root available but explicitly identifies it as nonmatching context", async () => {
    const sibling = { ...finding, id: 13, slug: "VA-013", title: "Sibling claim", severity: "low" };
    vi.mocked(listAssessmentFindingGroups).mockResolvedValue([{ root: finding, siblings: [sibling], sibling_count: 1, residual_path_count: 0 }] as never);
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding, sibling] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByText("Loading groups")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: /^low/ }));
    const queue = screen.getByRole("region", { name: "Finding queue" });
    expect(within(queue).getByRole("button", { name: "Shared claim" })).toBeTruthy();
    expect(within(queue).getByText("Root context outside current filters")).toBeTruthy();
    expect(queue.textContent).toContain("1 of 2 findings match");
  });
  it("contains finding-palette focus, closes on Escape and restores its opener", async () => {
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    screen.getByRole("button", { name: "Table" }).focus();
    expect(document.querySelector(".cmd-box")?.contains(document.activeElement)).toBe(true);
    const dialog = screen.getByRole("dialog", { name: "Jump to finding" });
    const input = within(dialog).getByRole("textbox", { name: "Search findings to jump to" });
    expect(document.activeElement).toBe(input);
    expect(document.body.classList.contains("detail-modal-open")).toBe(true);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    const result = within(dialog).getByRole("button", { name: /Shared claim/ });
    expect(document.activeElement).toBe(result);
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(input);
    screen.getByRole("button", { name: "Table" }).focus();
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Jump to finding" })).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
  });
  it("opens the arrow-selected finding on Enter and returns from review to the palette opener", async () => {
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding, { ...finding, slug: "VA-013", title: "Z second claim" }] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    const input = screen.getByPlaceholderText("Jump to finding · try 'severity:critical xss' or a slug");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("heading", { name: "Z second claim" })).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Jump to finding" })).toBeNull();
    expect(window.location.hash).toContain("finding=VA-013");
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(document.activeElement).toBe(opener));
  });

  it("traverses the current table sort order and retains it when returning", async () => {
    const records = ["Alpha", "Bravo", "Charlie"].map((title, index) => ({ ...finding, id: index + 1, slug: `VA-${index}`, title }));
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    fireEvent.click(await screen.findByRole("button", { name: "Sort descending" }));
    fireEvent.click(screen.getByRole("button", { name: "Grid Bravo" }));
    fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
    expect(await screen.findByRole("heading", { name: "Alpha" })).toBeTruthy();
    expect((screen.getByRole("button", { name: "Next finding" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    fireEvent.click(screen.getByRole("button", { name: "Grid Bravo" }));
    fireEvent.keyDown(window, { key: "j" });
    expect(await screen.findByRole("heading", { name: "Alpha" })).toBeTruthy();
  });

  it("returns to the preserved results search with the slash shortcut", async () => {
    workspace();
    await screen.findByRole("region", { name: "Finding investigation" });
    fireEvent.keyDown(window, { key: "/" });
    expect(screen.getByRole("textbox", { name: "Search findings" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "Search findings" })));
    expect(window.location.hash).toBe("#/engagements/demo?tab=findings");
  });

  it("does not announce absent evidence while a fallback finding detail is pending", async () => {
    let resolve!: (value: unknown) => void;
    vi.mocked(getAssessmentFinding).mockImplementation(() => new Promise((done) => { resolve = done; }) as never);
    const fallback = { slug: finding.slug, title: finding.title, severity: finding.severity, workflow_status: finding.workflow_status, verification_status: finding.verification_status, canonical_location: finding.canonical_location, summary: finding.summary, source_name: finding.source_name, updated_at: finding.updated_at };
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[]} fallbackFindings={[fallback] as never[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug={finding.slug} /></ToastProvider>);
    await screen.findByRole("region", { name: "Finding investigation" });
    expect(screen.getByText("Loading finding detail…")).toBeTruthy();
    expect(screen.queryByText("No source contribution recorded.")).toBeNull();
    expect(screen.queryByText("Current proof receipts unavailable.")).toBeNull();
    expect(screen.queryByText("Evidence mode unrecorded")).toBeNull();
    expect((screen.getByRole("button", { name: "Copy submission as Markdown" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => { resolve(finding); });
    expect(await screen.findByText("AccountController.show")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Receipt #41/ })).toBeTruthy();
  });

  it("distinguishes the unavailable or pending finding ledger from an empty result", async () => {
    const props = { engagementKey: "demo", findings: [], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0 };
    const view = render(<ToastProvider><FindingsTab {...props} ledgerLoading /></ToastProvider>);
    expect(screen.getByText("Loading finding ledger…")).toBeTruthy();
    expect(screen.queryByText("No findings match.")).toBeNull();
    view.rerender(<ToastProvider><FindingsTab {...props} ledgerError="Backend offline" /></ToastProvider>);
    expect(screen.getByRole("alert").textContent).toContain("Backend offline");
    expect(screen.queryByText("No findings match.")).toBeNull();
  });

  it("shows runtime and source contributions with exact current receipt navigation", async () => {
    workspace();
    expect(await screen.findByRole("heading", { name: "Runtime observation" })).toBeTruthy();
    expect(screen.getByText("AccountController.show")).toBeTruthy();
    const receipt = screen.getByRole("link", { name: /Receipt #41/ });
    expect(receipt.getAttribute("href")).toContain("run=7");
    expect(receipt.getAttribute("href")).toContain("object=41");
    expect(receipt.textContent).toContain("missing");
    expect(screen.queryByRole("link", { name: /Receipt #40/ })).toBeNull();
    expect(screen.getByText(/Authorization: Bearer operator-token/)).toBeTruthy();
  });
  it("places the authored impact beside the claim without replacing its submission record", async () => {
    workspace({ details: { ...finding.details, impact: "Other users can read **private account data**." } });
    await screen.findByRole("region", { name: "Finding investigation" });
    expect(screen.getByRole("heading", { name: "Impact" })).toBeTruthy();
    expect(screen.getByText("private account data").tagName).toBe("STRONG");
    fireEvent.click(screen.getByRole("button", { name: /Submission/ }));
    expect(screen.getByText("private account data").tagName).toBe("STRONG");
  });
  it("retains same-version current evidence on refresh failure but discards it after a claim change", async () => {
    const listed = { ...finding, verification_audit: undefined, proof_receipts: undefined };
    vi.mocked(getAssessmentFinding).mockResolvedValueOnce(finding as never).mockRejectedValue(new Error("Detail offline"));
    const props = { engagementKey: "demo", findings: [listed] as never[], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0, initialFindingSlug: finding.slug };
    const view = render(<ToastProvider><FindingsTab {...props} /></ToastProvider>);
    await screen.findByRole("link", { name: /Receipt #41/ });
    view.rerender(<ToastProvider><FindingsTab {...props} findings={[{ ...listed }] as never[]} assessmentRefreshVersion={1} /></ToastProvider>);
    expect(await screen.findByText("Claim review refresh unavailable; showing previously loaded evidence for this unchanged claim.")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Receipt #41/ })).toBeTruthy();
    view.rerender(<ToastProvider><FindingsTab {...props} findings={[{ ...listed, row_version: 2, verification_status: "pending_runtime_proof" }] as never[]} assessmentRefreshVersion={2} /></ToastProvider>);
    await screen.findByText("Claim review status unavailable");
    expect(screen.queryByRole("link", { name: /Receipt #41/ })).toBeNull();
  });
  it("ignores a late detail response after moving to a different fallback finding", async () => {
    let finishA!: (value: unknown) => void;
    let finishB!: (value: unknown) => void;
    vi.mocked(getAssessmentFinding).mockImplementation((_key, slug) => new Promise((done) => { if (slug === "VA-012") finishA = done; else finishB = done; }) as never);
    const records = [{ slug: "VA-012", title: "First claim" }, { slug: "VA-013", title: "Second claim" }].map((item) => ({ ...item, severity: "high", workflow_status: "active", verification_status: "confirmed", summary: item.title, source_name: "analyst", updated_at: finding.updated_at, canonical_location: "" }));
    const props = { engagementKey: "demo", findings: [], fallbackFindings: records as never[], chains: [], chainLinks: [], assessmentRefreshVersion: 0 };
    const view = render(<ToastProvider><FindingsTab {...props} initialFindingSlug="VA-012" /></ToastProvider>);
    await screen.findByRole("heading", { name: "First claim" });
    view.rerender(<ToastProvider><FindingsTab {...props} initialFindingSlug="VA-013" /></ToastProvider>);
    await screen.findByRole("heading", { name: "Second claim" });
    await act(async () => { finishB({ ...finding, slug: "VA-013", title: "Second claim", details: { impact: "Second impact" }, proof_receipts: [] }); });
    await screen.findByText("Second impact");
    await act(async () => { finishA({ ...finding, title: "First claim", details: { impact: "First impact" } }); });
    expect(screen.getByRole("heading", { name: "Second claim" })).toBeTruthy();
    expect(screen.queryByText("First impact")).toBeNull();
    expect(screen.queryByRole("link", { name: /Receipt #41/ })).toBeNull();
  });
  it("never commits one finding's history under the next finding's title", async () => {
    vi.mocked(listAssessmentFindingTransitions).mockImplementation((_key, slug) => slug === "VA-012" ? Promise.resolve([{ id: 201, actor: "reviewer", action: "verified", from_workflow_status: "active", to_workflow_status: "active", from_verification_status: "unreviewed", to_verification_status: "confirmed", verification_event_version: 1, from_severity: "high", to_severity: "high", reason_code: "review", reason_text: "First recorded decision", artifact_ref: "", metadata_json: "{}", created_at: finding.updated_at }]) as never : new Promise(() => {}) as never);
    const mismatched: string[] = [];
    const records = [finding, { ...finding, id: 13, slug: "VA-013", title: "Z second claim" }];
    render(<ToastProvider><Profiler id="history-identity" onRender={() => {
      const investigation = document.querySelector(".finding-investigation");
      if (investigation?.querySelector("h2")?.textContent === "Z second claim" && investigation.textContent?.includes("First recorded decision")) mismatched.push(investigation.textContent);
    }}><FindingsTab engagementKey="demo" findings={records as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" /></Profiler></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "History 1" }));
    await screen.findAllByText("First recorded decision");
    fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
    await screen.findByRole("heading", { name: "Z second claim" });
    expect(mismatched).toEqual([]);
  });
  it.each(["Copy link to this finding", "Copy submission as Markdown"])("does not show a late copy failure for the previous finding: %s", async (label) => {
    let reject!: (reason: unknown) => void;
    writeText.mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail; }));
    render(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding, { ...finding, slug: "VA-013", title: "Z second claim" }] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" /><ToastViewport /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: label }));
    fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
    await screen.findByRole("heading", { name: "Z second claim" });
    await act(async () => { reject(new Error("Clipboard denied")); });
    expect(screen.queryByText(/Could not copy (link|submission)\./)).toBeNull();
  });
  it.each(["Copy link to this finding", "Copy submission as Markdown"])("keeps the newest copy result when an older request fails: %s", async (label) => {
    let reject!: (reason: unknown) => void;
    writeText.mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail; })).mockResolvedValueOnce(undefined);
    workspace();
    const copy = await screen.findByRole("button", { name: label });
    fireEvent.click(copy);
    fireEvent.click(copy);
    await screen.findByText(label.includes("Markdown") ? "Copied submission as Markdown" : "Link copied");
    await act(async () => { reject(new Error("Older request denied")); });
    expect(screen.queryByText(/Could not copy (link|submission)\./)).toBeNull();
  });

  it("makes absent runtime proof explicit for a source-only claim", async () => {
    workspace({ verification_status: "pending_runtime_proof", canonical_location: "file:src/account.ts:42", evidence_type: "code-inferred", details: { entry_point: "AccountController.show" }, proof_receipts: [] });
    expect(await screen.findByText("Runtime proof outstanding")).toBeTruthy();
    expect(screen.getByText("No runtime observation recorded.")).toBeTruthy();
    expect(screen.getByText("No proof receipts support the current verification state.")).toBeTruthy();
  });

  it("restores the engagement queue search after following evidence and returning", async () => {
    const first = workspace();
    fireEvent.change(screen.getByPlaceholderText(/Search any field/), { target: { value: "authorization" } });
    first.unmount();
    workspace();
    expect((screen.getByPlaceholderText(/Search any field/) as HTMLInputElement).value).toBe("authorization");
  });

  it("keeps the selected claim when keyboard traversal has no matching queue rows", async () => {
    workspace();
    await screen.findByRole("region", { name: "Finding investigation" });
    fireEvent.change(screen.getByPlaceholderText(/Search any field/), { target: { value: "no queue match" } });
    fireEvent.keyDown(window, { key: "j" });
    expect(screen.getByRole("region", { name: "Finding investigation" })).toBeTruthy();
  });

  it("keeps linked remediation visible and marks it stale after a failed refresh", async () => {
    vi.mocked(getFindingRemediationCases).mockResolvedValueOnce([{
      id: 9, engagement_key: "repair", title: "Fix shared cause", status: "approved",
      worktree_revision: "patch-commit", worktree_path: null, worktree_branch: null,
      latest_deployment: null, linked_findings: [],
    }]).mockRejectedValueOnce(new Error("Backend offline"));
    const rendered = workspace();
    expect(await screen.findByRole("link", { name: /Fix shared cause/ })).toBeTruthy();
    rendered.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={1} initialFindingSlug="VA-012" /></ToastProvider>);
    expect(await screen.findByText(/Remediation relationships are stale/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /Fix shared cause/ }).getAttribute("href")).toBe("#/remediation/repair?case=9");
    expect(screen.queryByText("No remediation case linked.")).toBeNull();
  });

  it("does not let a pending remediation creation navigate after leaving its finding", async () => {
    let resolveCreated!: (value: never) => void;
    vi.mocked(createRemediationFromFinding).mockReturnValue(new Promise((resolve) => { resolveCreated = resolve; }));
    vi.mocked(listEngagements).mockResolvedValue([{ key: "repair", target: "Repair workspace", engagement_type: "remediation" }] as never);
    const view = workspace();
    fireEvent.click(await screen.findByRole("button", { name: "Create remediation case" }));
    fireEvent.change(await screen.findByRole("combobox", { name: "Remediation workspace" }), { target: { value: "repair" } });
    fireEvent.click(screen.getByRole("button", { name: "Create & open case" }));
    await waitFor(() => expect(createRemediationFromFinding).toHaveBeenCalledOnce());
    view.unmount();
    window.history.replaceState(null, "", "#/engagements/demo?tab=http");
    resolveCreated({ id: 9, engagement_key: "repair" } as never);
    await waitFor(() => expect(screen.queryByText("Creating case…")).toBeNull());
    await Promise.resolve();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http");
  });

  it("requires an explicit remediation workspace and opens the created case", async () => {
    vi.mocked(listEngagements).mockResolvedValue([
      { key: "assessment", target: "Assessment", engagement_type: "offensive" },
      { key: "repair", target: "Repair workspace", engagement_type: "remediation" },
    ] as never[]);
    vi.mocked(createRemediationFromFinding).mockResolvedValue({ id: 9, engagement_key: "repair" } as never);
    workspace();
    fireEvent.click(await screen.findByRole("button", { name: "Create remediation case" }));
    const destination = await screen.findByRole("combobox", { name: "Remediation workspace" });
    const routeBeforeTypeahead = window.location.hash;
    destination.focus();
    fireEvent.keyDown(destination, { key: "j" });
    fireEvent.keyDown(destination, { key: "[" });
    expect(window.location.hash).toBe(routeBeforeTypeahead);
    expect(screen.queryByRole("option", { name: /Assessment/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Create & open case" }).hasAttribute("disabled")).toBe(true);
    fireEvent.change(destination, { target: { value: "repair" } });
    fireEvent.click(screen.getByRole("button", { name: "Create & open case" }));
    await waitFor(() => expect(createRemediationFromFinding).toHaveBeenCalledWith("demo", "VA-012", { remediation_engagement_key: "repair" }));
    await waitFor(() => expect(window.location.hash).toBe("#/remediation/repair?case=9"));
  });

  it("restores the selected section when browser history revisits the same finding", async () => {
    const rendered = workspace();
    fireEvent.click(await screen.findByRole("button", { name: "History 0" }));
    expect(window.location.hash).toContain("dtab=history");
    rendered.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" initialDrawerTab="submission" /></ToastProvider>);
    await waitFor(() => expect(screen.getByRole("button", { name: /Submission/ }).getAttribute("aria-current")).toBe("page"));
    rendered.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} initialFindingSlug="VA-012" initialDrawerTab="history" /></ToastProvider>);
    await waitFor(() => expect(screen.getByRole("button", { name: "History 0" }).getAttribute("aria-current")).toBe("page"));
    rendered.rerender(<ToastProvider><FindingsTab engagementKey="demo" findings={[finding] as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("region", { name: "Finding investigation" })).toBeNull());
  });
});

describe("RelatedIntelSection", () => {
  it("resolves finding ids into first-class Intel deep links and reports missing ids", async () => {
    vi.mocked(resolveIntelIds).mockResolvedValue([
      {
        requested_id: 42,
        resolution: "resolved",
        matches: [{
          id: 42,
          entity_type: "note",
          title: "OAuth boundary research",
          summary: "Vendor behavior and reproduction constraints.",
          status: "open",
        }],
      },
      { requested_id: 99, resolution: "missing", matches: [] },
      { requested_id: "legacy:key", resolution: "unsupported", matches: [] },
    ]);

    render(<RelatedIntelSection engagementKey="demo key" ids={[42, 99, "legacy:key"]} />);

    const link = await screen.findByRole("link", { name: /OAuth boundary research/i });
    expect(link.getAttribute("href")).toContain("tab=intel");
    expect(link.getAttribute("href")).toContain("intel_type=note");
    expect(link.getAttribute("href")).toContain("intel_id=42");
    expect(screen.getByText(/Intel #99 is missing/i)).toBeTruthy();
    expect(screen.getByText(/Intel #legacy:key is unsupported/i)).toBeTruthy();
  });
});
