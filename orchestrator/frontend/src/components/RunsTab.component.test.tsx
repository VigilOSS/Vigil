// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AssessmentRun } from "../lib/api";
import {
  getAssessmentRun,
  getAssessmentRunComparison,
  listAssessmentRunChildren,
  listAssessmentRuns,
} from "../lib/api";
import { RunsTab } from "./RunsTab";

vi.mock("../lib/api", () => ({
  getAssessmentRun: vi.fn(),
  getAssessmentRunComparison: vi.fn(),
  listAssessmentRunChildren: vi.fn(),
  listAssessmentRuns: vi.fn(),
}));

const currentRun: AssessmentRun = {
  id: 41,
  run_uuid: "run-current",
  run_kind: "code",
  run_purpose: "scan",
  status: "partial",
  created_at: "2026-09-09T10:00:00Z",
  started_at: "2026-09-09T10:01:00Z",
  finished_at: "2026-09-09T10:02:00Z",
  target_identity: {
    host: "target.test",
    aws_secret_access_key: "aws-private-value",
    authorization: "Bearer opaque-token",
  },
  counts: { inventory_total: 2, open_hard_obligations: 1 },
  proof_health: { healthy: 1 },
  lifecycle_history: [
    { id: 1, from_status: null, to_status: "queued", created_at: "2026-09-09T10:00:00Z" },
    { id: 2, from_status: "queued", to_status: "running", created_at: "2026-09-09T10:01:00Z" },
    { id: 3, from_status: "running", to_status: "partial", created_at: "2026-09-09T10:02:00Z" },
  ],
  blockers: [
    {
      code: "open_hard_obligation",
      message: "Repository review remains open",
      object_type: "obligation",
      object_id: 9,
      action: "Record supported resolution",
    },
  ],
  seal: {
    dispatch_provenance: {
      dispatch_id: 5,
      agent_id: "VERIFY-1",
      actual_model: "gpt-5.6-sol",
      client_name: "codex",
      requested_client: "claude",
      launcher_effective_client: "codex",
      provider_observed_client: "unknown",
      launcher_effective_model: null,
      launcher_effective_reasoning: null,
      launcher_effective_source: null,
    },
  },
};

const baselineRun: AssessmentRun = {
  ...currentRun,
  id: 40,
  run_uuid: "run-baseline",
  status: "completed",
};

function arrangeSuccessfulAudit() {
  vi.mocked(listAssessmentRuns).mockResolvedValue([currentRun, baselineRun]);
  vi.mocked(getAssessmentRun).mockResolvedValue(currentRun);
  vi.mocked(getAssessmentRunComparison).mockResolvedValue({
    run_id: currentRun.id,
    baseline_run_id: baselineRun.id,
    target_compatible: true,
    source_compatible: true,
    deterministic: true,
    classifications: {
      new: ["new-finding"],
      persisting: ["persisting-finding"],
      resolved: ["resolved-finding"],
      unknown: ["unknown-finding"],
    },
  });
  vi.mocked(listAssessmentRunChildren).mockImplementation(
    async (_engagement, _runId, section, params) => {
      if (section === "sources" && (params?.offset ?? 0) === 0) {
        return {
          items: [{ id: 1, path: "src/first.py" }],
          total: 2,
          offset: 0,
          limit: 50,
          has_more: true,
        };
      }
      if (section === "sources") {
        return {
          items: [{ id: 2, path: "src/second.py" }],
          total: 2,
          offset: 1,
          limit: 50,
          has_more: false,
        };
      }
      return { items: [], total: 0, offset: 0, limit: 50, has_more: false };
    },
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("RunsTab", () => {
  it("stops deep-link pagination after a failed page instead of retrying indefinitely", async () => {
    arrangeSuccessfulAudit();
    vi.mocked(listAssessmentRunChildren).mockResolvedValueOnce({ items: [{ id: 1, path: "src/first.py" }], total: 2, offset: 0, limit: 50, has_more: true })
      .mockRejectedValueOnce(new Error("next page unavailable"))
      .mockImplementation(() => new Promise(() => {}));
    render(<RunsTab engagementKey="audit-test" initialRunId={41} initialSection="sources" initialObject="2" />);
    expect(await screen.findByText(/next page unavailable/)).toBeTruthy();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(listAssessmentRunChildren).toHaveBeenCalledTimes(2);
    expect(screen.getByText("src/first.py")).toBeTruthy();
  });

  it("reports an unavailable exact deep-linked ledger record", async () => {
    arrangeSuccessfulAudit();
    vi.mocked(listAssessmentRunChildren).mockResolvedValue({ items: [], total: 0, offset: 0, limit: 50, has_more: false });
    render(<RunsTab engagementKey="audit-test" initialRunId={41} initialSection="proof-receipts" initialObject="99" />);
    expect(await screen.findByText(/Requested record #99 is not present/)).toBeTruthy();
  });

  it("retains the last recorded detail and child ledger on refresh failure", async () => {
    arrangeSuccessfulAudit();
    const view = render(<RunsTab engagementKey="audit-test" initialRunId={41} initialSection="sources" refreshVersion={0} />);
    expect(await screen.findByText("src/first.py")).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "run-current" })).toBeTruthy();
    vi.mocked(getAssessmentRun).mockRejectedValue(new Error("detail refresh unavailable"));
    vi.mocked(listAssessmentRunChildren).mockRejectedValue(new Error("ledger refresh unavailable"));
    view.rerender(<RunsTab engagementKey="audit-test" initialRunId={41} initialSection="sources" refreshVersion={1} />);
    expect(await screen.findByText(/detail refresh unavailable/)).toBeTruthy();
    expect(await screen.findByText(/ledger refresh unavailable/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "run-current" })).toBeTruthy();
    expect(screen.getByText("src/first.py")).toBeTruthy();
    expect(screen.getAllByText(/last recorded/i).length).toBeGreaterThan(0);
  });

  it("writes run and section selection to canonical navigable history", async () => {
    arrangeSuccessfulAudit();
    vi.mocked(getAssessmentRun).mockImplementation(async (_key, id) => id === 40 ? baselineRun : currentRun);
    window.history.replaceState(null, "", "#/engagements/audit-test?tab=runs&run=41");
    render(<RunsTab engagementKey="audit-test" initialRunId={41} />);
    await screen.findByRole("heading", { name: "run-current" });
    fireEvent.click(screen.getByRole("button", { name: /run-baseline/ }));
    expect(window.location.hash).toContain("run=40");
    await screen.findByRole("heading", { name: "run-baseline" });
    fireEvent.click(screen.getByRole("tab", { name: "Sources" }));
    expect(window.location.hash).toContain("section=sources");
  });

  it("restores the default section when history drops an explicit section", async () => {
    arrangeSuccessfulAudit();
    const view = render(<RunsTab engagementKey="audit-test" initialRunId={41} initialSection="obligations" />);
    await screen.findByRole("heading", { name: "run-current" });
    view.rerender(<RunsTab engagementKey="audit-test" initialRunId={41} />);
    await waitFor(() => expect(screen.getByRole("tab", { name: "Sources" }).getAttribute("aria-selected")).toBe("true"));
  });

  it("renders loading, empty, and error states", async () => {
    let finishLoading: (runs: AssessmentRun[]) => void = () => undefined;
    vi.mocked(listAssessmentRuns).mockReturnValue(
      new Promise((resolve) => {
        finishLoading = resolve;
      }),
    );
    const loading = render(<RunsTab engagementKey="audit-test" />);
    expect(loading.container.querySelector('[aria-busy="true"]')).not.toBeNull();
    finishLoading([]);
    expect(await screen.findByText("No assessment runs have been recorded.")).toBeTruthy();
    loading.unmount();

    vi.mocked(listAssessmentRuns).mockRejectedValue(new Error("run ledger unavailable"));
    render(<RunsTab engagementKey="audit-test" />);
    expect(await screen.findByText("run ledger unavailable")).toBeTruthy();
  });

  it("renders audit state, safe links, raw values, history, paging, and comparisons", async () => {
    arrangeSuccessfulAudit();
    const view = render(
      <RunsTab engagementKey="audit test" initialRunId={currentRun.id} />,
    );

    expect(await screen.findByText("Repository review remains open")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open object →" }).getAttribute("href")).toBe(
      "#/engagements/audit%20test?tab=runs&run=41&section=obligations&object=9",
    );
    // The audit view is the evidence trail: the run's own credential material
    // renders verbatim, with no reveal step in front of it.
    await waitFor(() => expect(view.container.textContent).toContain("aws-private-value"));
    expect(view.container.textContent).toContain("Bearer opaque-token");
    fireEvent.click(screen.getByText("Advanced audit"));
    const dispatchPanel = screen.getByRole("heading", { name: "Dispatch" }).parentElement;
    expect(dispatchPanel?.textContent).toContain('"requested_client": "claude"');
    expect(dispatchPanel?.textContent).toContain('"launcher_effective_client": "codex"');
    expect(dispatchPanel?.textContent).toContain('"provider_observed_client": "unknown"');
    expect(dispatchPanel?.textContent).toContain('"launcher_effective_model": null');
    expect(dispatchPanel?.textContent).toContain('"launcher_effective_reasoning": null');
    expect(dispatchPanel?.textContent).toContain('"launcher_effective_source": null');
    expect(dispatchPanel?.textContent).toContain(
      '"client_name_compatibility_projection": "codex"',
    );
    expect(view.container.textContent).toContain("queued → running");
    expect(await screen.findByText("src/first.py")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Load more/ }));
    expect(await screen.findByText("src/second.py")).toBeTruthy();
    expect(view.container.textContent).toContain("persisting-finding");
    expect(view.container.textContent).toContain("unknown-finding");

    fireEvent.change(screen.getByLabelText("Baseline"), {
      target: { value: String(baselineRun.id) },
    });
    await waitFor(() => {
      expect(getAssessmentRunComparison).toHaveBeenCalledWith(
        "audit test",
        currentRun.id,
        baselineRun.id,
      );
    });

    fireEvent.click(screen.getByRole("tab", { name: "Observed events" }));
    await waitFor(() => {
      expect(listAssessmentRunChildren).toHaveBeenCalledWith(
        "audit test",
        currentRun.id,
        "observed-events",
        { limit: 50, offset: 0 },
      );
    });
    fireEvent.click(screen.getByRole("tab", { name: "Tool signals" }));
    await waitFor(() => {
      expect(listAssessmentRunChildren).toHaveBeenCalledWith(
        "audit test",
        currentRun.id,
        "tool-signals",
        { limit: 50, offset: 0 },
      );
    });
  });

  it("clears run-list loading after initial run navigation", async () => {
    arrangeSuccessfulAudit();
    vi.mocked(getAssessmentRun).mockImplementation(async (_engagementKey, runId) =>
      runId === baselineRun.id ? baselineRun : currentRun,
    );

    const view = render(
      <RunsTab engagementKey="audit test" initialRunId={currentRun.id} />,
    );
    expect(await screen.findByRole("heading", { name: "run-current" })).toBeTruthy();

    view.rerender(
      <RunsTab engagementKey="audit test" initialRunId={baselineRun.id} />,
    );
    expect(await screen.findByRole("heading", { name: "run-baseline" })).toBeTruthy();
    await waitFor(() => {
      expect(
        view.container.querySelector('.run-audit-rail [aria-busy="true"]'),
      ).toBeNull();
    });
  });

  it("keeps proof runs concise while retaining full data in advanced audit", async () => {
    const proofRun: AssessmentRun = {
      ...currentRun,
      id: 42,
      run_uuid: "proof-run",
      run_purpose: "proof",
      target_identity: {},
      counts: {
        inventory_total: 0,
        source_reads: 0,
        obligations: 0,
        findings: 1,
        proof_receipts: 2,
      },
      source_generations: [],
      exclusions: [],
      seal: null,
      producer_dispatch_id: undefined,
      producer_dispatch_agent_id: undefined,
      producer_dispatch_agent_role: undefined,
    };
    vi.mocked(listAssessmentRuns).mockResolvedValue([proofRun]);
    vi.mocked(getAssessmentRun).mockResolvedValue(proofRun);
    vi.mocked(getAssessmentRunComparison).mockResolvedValue({
      run_id: proofRun.id,
      baseline_run_id: baselineRun.id,
      target_compatible: null,
      source_compatible: null,
      deterministic: true,
      classifications: { new: [], persisting: [], resolved: [], unknown: [] },
    });
    vi.mocked(listAssessmentRunChildren).mockResolvedValue({
      items: [], total: 0, offset: 0, limit: 50, has_more: false,
    });

    render(<RunsTab engagementKey="audit-test" initialRunId={proofRun.id} />);

    expect(await screen.findByRole("heading", { name: "proof-run" })).toBeTruthy();
    expect(screen.getByText("proof receipts").previousElementSibling?.textContent).toBe("2");
    expect(screen.queryByText("inventory total")).toBeNull();
    expect(screen.queryByRole("heading", { name: "Target identity" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Command evidence" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: "Obligations" })).toBeNull();

    fireEvent.click(screen.getByText("Advanced audit"));
    expect(screen.getByText("inventory total")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Target identity" })).toBeTruthy();
    expect(screen.getByText(/Compatibility with run 40 is unknown/)).toBeTruthy();
  });
});
