// @vitest-environment jsdom

// The Submission pane renders the operator's own captures. Two properties are pinned
// here and neither is styling: the page shows the recorded bytes, and the copy
// chip beside them hands back the same bytes. A capture that the pane rewrites
// is a capture the reader cannot check against the target, and it puts the page
// out of step with lib/findingMarkdown.ts — which fences these same fields
// verbatim (AGENTS.md: never degrade the operator's own data; ADR 0019).

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getAssessmentFindingTransition, resolveIntelIds } from "../lib/api";
import { HistoryPane, RelatedIntelSection, SubmissionPane } from "./FindingsTab";
import type { Derived } from "./FindingsTab";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getAssessmentFindingTransition: vi.fn(),
    resolveIntelIds: vi.fn(),
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
