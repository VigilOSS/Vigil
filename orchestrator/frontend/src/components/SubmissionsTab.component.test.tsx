// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { exportSubmissionVersion, recoverSubmissionExports } from "../lib/api";
import type { SubmissionVersion } from "../lib/api";
import {
  getSubmissionDesk,
  getSubmissionReadiness,
  listSubmissionAttachments,
  listSubmissionDesk,
} from "../lib/submissionsApi";
import type {
  SubmissionDeskDetail,
  SubmissionDeskListing,
  SubmissionDeskRow,
  SubmissionReadiness,
} from "../lib/submissionsApi";
import { ToastProvider, ToastViewport } from "../contexts/ToastContext";
import { SubmissionsTab } from "./SubmissionsTab";

vi.mock("../lib/api", () => ({
  exportSubmissionVersion: vi.fn(),
  recoverSubmissionExports: vi.fn(),
  submissionVersionDownloadUrl: vi.fn(
    (_engagement: string, slug: string, version: number) => `/download/${slug}/${version}`,
  ),
}));

// A three-row page keeps the paging tests small.
vi.mock("../lib/submissionsApi", () => ({
  SUBMISSION_PAGE_SIZE: 3,
  SUBMISSION_MAX_PAGE_SIZE: 500,
  listSubmissionDesk: vi.fn(),
  getSubmissionDesk: vi.fn(),
  getSubmissionReadiness: vi.fn(),
  listSubmissionAttachments: vi.fn(),
}));

const page = (returned: number, total = returned, offset = 0) => ({
  offset,
  limit: 100,
  returned,
  total,
  has_more: offset + returned < total,
  next_offset: offset + returned < total ? offset + returned : null,
});

function row(slug: string, overrides: Partial<SubmissionDeskRow> = {}): SubmissionDeskRow {
  return {
    id: Number(slug.replace(/\D/g, "")) || 1,
    slug,
    title: `Missing authorization on Acme admin API ${slug}`,
    severity: "high",
    workflow_status: "active",
    verification_status: "confirmed",
    submission_status: "none",
    submission_platform: "",
    submission_ref: "",
    submission_url: "",
    row_version: 9,
    version_count: 0,
    latest_version_number: null,
    staging_version_count: 0,
    failed_version_count: 0,
    created_at: "2026-09-01T10:00:00Z",
    updated_at: "2026-09-09T12:00:00Z",
    readiness: "ready",
    readiness_reason: "Ready to export",
    blocker_count: 0,
    first_blocker: "",
    latest_version_platform: null,
    latest_version_completed_at: null,
    default_platform: "hackerone",
    ...overrides,
  };
}

function listing(rows: SubmissionDeskRow[], overrides: Partial<SubmissionDeskListing> = {}): SubmissionDeskListing {
  return {
    findings: rows,
    findings_page: page(rows.length),
    counts: {
      ready: 4, blocked: 3, needs_draft: 90, exported: 2, filed: 12, not_candidate: 120,
      incomplete_exports: 0, actionable: 99, all: 231,
    },
    facets: { severity: { high: rows.length }, platform: { hackerone: rows.length } },
    staging_count: 0,
    failed_count: 0,
    ...overrides,
  };
}

const BODY_SHA = "b".repeat(64);

function readinessFor(overrides: Partial<SubmissionReadiness> = {}): SubmissionReadiness {
  return {
    attachment_ids: [11],
    final_ready: true,
    blockers: [],
    items: [],
    existing_version_number: null,
    attachment_total_bytes: 2048,
    attachment_limit_bytes: 256 * 1024 * 1024,
    platform: "hackerone",
    external_body_sha256: BODY_SHA,
    submission_sha256: "a".repeat(64),
    finding_row_version: 9,
    ...overrides,
  };
}

function version(number: number, overrides: Partial<SubmissionVersion> = {}): SubmissionVersion {
  return {
    id: 100 + number,
    finding_id: 1,
    version_number: number,
    status: "complete",
    platform: "hackerone",
    package_format: "zip",
    actor_surface: "web-ui",
    relative_path: `submissions/VA-001/versions/000${number}/submission.zip`,
    media_type: "application/zip",
    size_bytes: 4096,
    sha256: "d".repeat(64),
    submission_sha256: BODY_SHA,
    source_finding_row_version: 9,
    source_finding_updated_at: "2026-09-09T12:00:00Z",
    attachment_ids: [11],
    attachment_count: 1,
    artifact_id: 900,
    created_at: "2026-09-10T08:00:00Z",
    completed_at: "2026-09-10T08:00:01Z",
    stale: false,
    idempotent_replay: false,
    manifest: {
      schema: "vigil-submission-attachment-manifest/v1",
      finding_slug: "VA-001",
      submission_sha256: BODY_SHA,
      attachments: [{
        artifact_id: 11, archive_path: "attachments/11-poc.py",
        original_relative_path: "submissions/VA-001/poc.py", media_type: "text/x-python",
        size_bytes: 2048, sha256: "e".repeat(64),
      }],
    },
    ...overrides,
  };
}

function detail(slug = "VA-001", overrides: Partial<SubmissionDeskDetail> = {}): SubmissionDeskDetail {
  const external = "# Missing authorization\n\nReviewed external body.";
  return {
    finding: {
      ...row(slug),
      canonical_location: "https://acme.example/admin",
      summary: "An ordinary user can read the admin response.",
    } as unknown as SubmissionDeskDetail["finding"],
    workspace: {
      present: true,
      submission_path: `submissions/${slug}/submission.md`,
      context_path: `submissions/${slug}/submission-context.json`,
      markdown: `${external}\n\n---\n\n## OPERATOR DETAILS — NOT FOR SUBMISSION\n\nInternal operator reference note.`,
      external_body: external,
      external_body_valid_utf8: true,
      submission_sha256: "a".repeat(64),
      external_body_sha256: BODY_SHA,
      context: { platform: "hackerone", mode: "final" },
      final_ready: true,
      blockers: [],
    },
    platform: "hackerone",
    blind_triage: {
      required: true,
      verdict: "Accept@P3",
      accepted: true,
      packet_id: "f".repeat(64),
      decided_at: "2026-09-09T13:00:00Z",
      platform: "hackerone",
      reviewed_body_sha256: BODY_SHA,
      attachments: [{
        artifact_id: 11, source_path: `submissions/${slug}/poc.py`, packet_path: "attachments/11-poc.py",
        media_type: "text/x-python", bytes: 2048, sha256: "e".repeat(64),
      }],
      attachment_ids: [11],
      manifest_error: "",
    },
    latest_version: version(2),
    default_attachment_ids: [11],
    default_attachment_source: "blind_triage",
    default_attachments: [{
      id: 11, relative_path: `submissions/${slug}/poc.py`, kind: "script", media_type: "text/x-python",
      size_bytes: 2048, sha256: "e".repeat(64), present: true, related_finding_slug: slug,
      integrity_status: "verified", created_at: "2026-09-09T11:00:00Z", updated_at: "2026-09-09T11:00:00Z",
      internal: false,
    }],
    readiness: readinessFor(),
    eligible_attachments: [
      {
        id: 11, relative_path: `submissions/${slug}/poc.py`, kind: "script", media_type: "text/x-python",
        size_bytes: 2048, sha256: "e".repeat(64), present: true, related_finding_slug: slug,
        integrity_status: "verified", created_at: "2026-09-09T11:00:00Z", updated_at: "2026-09-09T11:00:00Z",
      },
      {
        id: 12, relative_path: "evidence/response.json", kind: "proof", media_type: "application/json",
        size_bytes: 18, sha256: "c".repeat(64), present: true, related_finding_slug: slug,
        integrity_status: "verified", created_at: "2026-09-09T11:00:00Z", updated_at: "2026-09-09T10:00:00Z",
      },
    ],
    eligible_attachments_page: page(2),
    engagement_attachment_total: 2,
    versions: [version(2), version(1, { stale: true, source_finding_row_version: 8 })],
    versions_page: page(2),
    pending_version_count: 0,
    pending_versions: [],
    pending_versions_page: page(0),
    ...overrides,
  };
}

function renderTab(refreshVersion = 0, route: { initialSubmissionSlug?: string; initialDrawerTab?: string } = {}) {
  return render(
    <ToastProvider>
      <SubmissionsTab engagementKey="acme" refreshVersion={refreshVersion} {...route} />
      <ToastViewport />
    </ToastProvider>,
  );
}

function rerenderTab(view: ReturnType<typeof render>, refreshVersion: number) {
  view.rerender(
    <ToastProvider>
      <SubmissionsTab engagementKey="acme" refreshVersion={refreshVersion} />
      <ToastViewport />
    </ToastProvider>,
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

// Runs `action` with fake timers, then lets the readiness debounce (350 ms)
// and the reads it starts settle before real timers come back. Each round
// ends an act scope, so effects that schedule the next timer have run.
async function withDebounce(action: () => void, ms = 400, rounds = 3) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    action();
    for (let round = 0; round < rounds; round += 1) {
      await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
    }
  } finally {
    vi.useRealTimers();
  }
}

async function cardHeader() {
  const card = await screen.findByRole("region", { name: "Submission VA-001" });
  return within(card.querySelector("header") as HTMLElement);
}

afterEach(() => {
  vi.useRealTimers();
  cleanup();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/acme?tab=submissions");
  vi.mocked(exportSubmissionVersion).mockReset();
  vi.mocked(recoverSubmissionExports).mockReset();
  vi.mocked(listSubmissionDesk).mockReset();
  vi.mocked(getSubmissionDesk).mockReset();
  vi.mocked(getSubmissionReadiness).mockReset();
  vi.mocked(listSubmissionAttachments).mockReset();
});

describe("SubmissionsTab", () => {
  it("separates verification, package readiness and external filing in the shared finding header", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { verification_status: "unreviewed", readiness: "not_candidate" })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    window.sessionStorage.setItem('finding.section.["acme","VA-001","findings"]', "history");
    renderTab();
    const nav = await screen.findByRole("navigation", { name: "Finding workflow" });
    expect(within(nav).getByRole("link", { name: "Review finding" }).getAttribute("href")).toBe("#/engagements/acme?tab=findings&finding=VA-001&dtab=history");
    expect(within(nav).getByRole("link", { name: "Disclosure package" }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("group", { name: "Verification status" }).textContent).toContain("Unreviewed");
    expect(screen.getByRole("group", { name: "Package readiness" }).textContent).toContain("Not eligible");
    expect(screen.getByRole("group", { name: "External submission status" })).toBeTruthy();
    const summary = screen.getByRole("list", { name: "Summary" });
    expect(summary.textContent).toContain("231 findings");
    expect(summary.textContent).toContain("120 not eligible");
    expect(summary.textContent).toContain("4 ready to export");
  });
  it("shows server-computed queue counts and filters the queue on the server", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();

    const summary = await screen.findByRole("list", { name: "Summary" });
    await waitFor(() => expect(summary.textContent).toContain("4 ready"));
    expect(summary.textContent).toContain("93 need work");
    expect(summary.textContent).toContain("12 filed");
    expect(vi.mocked(listSubmissionDesk).mock.calls[0][1]).toMatchObject({ readiness: "actionable" });
    const states = screen.getByRole("group", { name: "State" });
    fireEvent.click(within(states).getByRole("button", { name: /Blocked\s*3/ }));
    await waitFor(() => {
      expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ readiness: "blocked" });
    });
    expect(within(states).getByRole("button", { name: /Blocked\s*3/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("keeps the blocked action in the card header and opens the readiness guidance", async () => {
    const blocked = readinessFor({
      final_ready: false,
      blockers: ["reproduction has no independent check", "blind triage has no verdict for the current finding"],
      items: [
        { message: "reproduction has no independent check", fix: "Have an independent tester rehearse the authored steps.", command: "vigil assess contract agent decision" },
        { message: "blind triage has no verdict for the current finding", fix: "Build a blind-triage packet.", command: "vigil assess export triage-packet VA-001 --attachment-id 11" },
      ],
    });
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { readiness: "blocked", blocker_count: 2 })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail("VA-001", { readiness: blocked }));
    renderTab();

    const header = await cardHeader();
    const action = await header.findByRole("button", { name: /Export blocked by 2 issues/ });
    expect(action.textContent).toContain("Blocked (2)");
    fireEvent.click(action);
    expect(screen.getByRole("tab", { name: /Readiness/ }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("Have an independent tester rehearse the authored steps.")).toBeTruthy();
    expect(screen.getByText("vigil assess export triage-packet VA-001 --attachment-id 11")).toBeTruthy();
    expect(exportSubmissionVersion).not.toHaveBeenCalled();
  });

  it("confirms an export by stating exactly what will be sealed before calling the backend", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    vi.mocked(exportSubmissionVersion).mockResolvedValue(version(3));
    renderTab();

    const header = await cardHeader();
    fireEvent.click(await header.findByRole("button", { name: "Export v3…" }));
    const dialog = screen.getByRole("dialog", { name: "Export immutable v3 of VA-001?" });
    expect(within(dialog).getByText(BODY_SHA)).toBeTruthy();
    expect(within(dialog).getByText("poc.py")).toBeTruthy();
    // Same-named files from different folders stay distinguishable.
    expect(within(dialog).getByText("submissions/VA-001")).toBeTruthy();
    expect(within(dialog).getByText(/ZIP with the body, an attachment manifest, and 1 attachment \(2\.0 KB\)/)).toBeTruthy();
    expect(dialog.textContent).toContain("Exporting changes nothing on HackerOne");
    expect(exportSubmissionVersion).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Seal v3" }));
    await waitFor(() => expect(exportSubmissionVersion).toHaveBeenCalledWith("acme", "VA-001", {
      platform: "hackerone",
      submission_path: "submissions/VA-001/submission.md",
      context_path: "submissions/VA-001/submission-context.json",
      attachment_ids: [11],
      actor_surface: "web-ui",
    }));
    expect(await screen.findByText(/Sealed immutable v3 of VA-001\. Nothing was submitted to HackerOne\./)).toBeTruthy();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(getSubmissionDesk).toHaveBeenCalledTimes(2);
  });

  it("keeps an export failure inside the confirmation dialog", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    vi.mocked(exportSubmissionVersion).mockRejectedValue(new Error("attachment artifact 11 changed since registration"));
    renderTab();

    fireEvent.click(await (await cardHeader()).findByRole("button", { name: "Export v3…" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Seal v3" }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty(
      "textContent",
      "attachment artifact 11 changed since registration",
    );
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("offers the version that already captured this exact selection instead of a new export", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { readiness: "exported", latest_version_number: 2 })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail("VA-001", {
      readiness: readinessFor({ existing_version_number: 2 }),
    }));
    renderTab();

    const header = await cardHeader();
    const download = await header.findByRole("link", { name: /Already captured as v2 — Download/ });
    expect(download.getAttribute("href")).toBe("/download/VA-001/2");
    expect(header.queryByRole("button", { name: /Export v/ })).toBeNull();
  });

  it("preselects the blind-triage reviewed attachments and rechecks readiness for any other selection", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const recheck = deferred<SubmissionReadiness & { finding_slug: string }>();
    vi.mocked(getSubmissionReadiness).mockReturnValue(recheck.promise);
    renderTab();

    await (await cardHeader()).findByRole("button", { name: "Export v3…" });
    fireEvent.click(screen.getByRole("tab", { name: /Package/ }));
    expect(screen.getByText(/Reviewed by blind triage/)).toBeTruthy();
    const reviewed = screen.getByRole("checkbox", { name: "Attach submissions/VA-001/poc.py" }) as HTMLInputElement;
    expect(reviewed.checked).toBe(true);

    const header = await cardHeader();
    await withDebounce(() => {
      fireEvent.click(screen.getByRole("checkbox", { name: "Attach evidence/response.json" }));
      expect(screen.getByText(/This selection differs from the 1 file blind/)).toBeTruthy();
      expect((header.getByRole("button", { name: /Checking readiness/ }) as HTMLButtonElement).disabled).toBe(true);
    });
    expect(getSubmissionReadiness).toHaveBeenCalledWith("acme", "VA-001", [11, 12]);
    await act(async () => {
      recheck.resolve({
        ...readinessFor({
          attachment_ids: [11, 12],
          final_ready: false,
          blockers: ["blind triage verdict covers different external attachments"],
          items: [{ message: "blind triage verdict covers different external attachments", fix: "Build a new packet.", command: "" }],
        }),
        finding_slug: "VA-001",
      });
    });
    expect(await header.findByRole("button", { name: /Export blocked by 1 issue/ })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Use reviewed set (1)" }));
    expect(await header.findByRole("button", { name: "Export v3…" })).toBeTruthy();
    expect(getSubmissionReadiness).toHaveBeenCalledTimes(1);
  });

  it("rechecks a changed selection after an export instead of reusing its pre-export readiness", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { severity: "low" })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    vi.mocked(getSubmissionReadiness)
      .mockResolvedValueOnce({ ...readinessFor({ attachment_ids: [11, 12], attachment_total_bytes: 2066 }), finding_slug: "VA-001" })
      .mockResolvedValueOnce({
        ...readinessFor({ attachment_ids: [11, 12], existing_version_number: 3 }),
        finding_slug: "VA-001",
      });
    vi.mocked(exportSubmissionVersion).mockResolvedValue(version(3, { attachment_ids: [11, 12] }));
    renderTab();

    const header = await cardHeader();
    await header.findByRole("button", { name: "Export v3…" });
    fireEvent.click(screen.getByRole("tab", { name: /Package/ }));
    await withDebounce(() => fireEvent.click(screen.getByRole("checkbox", { name: "Attach evidence/response.json" })));
    fireEvent.click(header.getByRole("button", { name: "Export v3…" }));
    await withDebounce(() => fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Seal v3" })));
    expect(exportSubmissionVersion).toHaveBeenCalledWith(
      "acme", "VA-001", expect.objectContaining({ attachment_ids: [11, 12] }),
    );
    expect(header.getByRole("link", { name: /Already captured as v3 — Download/ })).toBeTruthy();
    expect(getSubmissionReadiness).toHaveBeenCalledTimes(2);
  });

  it("shows the selected title at once with a document skeleton and a slow-load hint", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockReturnValue(new Promise(() => undefined));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      renderTab();
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      expect(screen.getByRole("heading", { name: "Missing authorization on Acme admin API VA-001" })).toBeTruthy();
      expect(screen.getByRole("status", { name: "Loading submission" })).toBeTruthy();
      // No findBy under fake timers: testing-library's async wrapper waits on a real timeout.
      const header = within(screen.getByRole("region", { name: "Submission VA-001" }).querySelector("header") as HTMLElement);
      expect((header.getByRole("button", { name: /Checking readiness/ }) as HTMLButtonElement).disabled).toBe(true);
      // The shared slow-load hint appears after two seconds.
      await act(async () => { await vi.advanceTimersByTimeAsync(2_100); });
      expect(screen.getByText(/Still loading this submission…/)).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders the external body by default and keeps operator notes in their own tab", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();

    expect(await screen.findByText("Reviewed external body.")).toBeTruthy();
    expect(screen.queryByText("Internal operator reference note.")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Operator notes" }));
    expect(screen.getByText("Internal operator reference note.")).toBeTruthy();
    expect(screen.queryByText("Reviewed external body.")).toBeNull();
  });

  it("guides an unrendered finding with its own platform and never assumes one", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([
      row("VA-001", { readiness: "needs_draft", default_platform: null }),
    ]));
    const unrendered = detail("VA-001", {
      platform: null,
      latest_version: null,
      default_attachment_ids: [],
      default_attachment_source: "none",
      default_attachments: [],
      versions: [],
      versions_page: page(0),
      readiness: readinessFor({ attachment_ids: [], final_ready: false, blockers: ["submission workspace is missing: submissions/VA-001/submission.md"], platform: null }),
    });
    unrendered.workspace = { ...unrendered.workspace, present: false, markdown: "", external_body: "", context: {} };
    vi.mocked(getSubmissionDesk).mockResolvedValue(unrendered);
    renderTab();

    expect(await screen.findByText(
      "vigil assess export submission VA-001 --platform <bugcrowd|hackerone|direct> --draft",
    )).toBeTruthy();
    expect(screen.queryByText(/--platform bugcrowd/)).toBeNull();
    expect(await (await cardHeader()).findByRole("button", { name: /No rendered submission yet/ })).toBeTruthy();
  });

  it("keeps the reviewed preview until the operator refreshes after a live finding change", async () => {
    vi.mocked(listSubmissionDesk)
      .mockResolvedValueOnce(listing([row("VA-001")]))
      .mockResolvedValue(listing([row("VA-001", { row_version: 10 })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const view = renderTab(0);
    await screen.findByText("Reviewed external body.");

    rerenderTab(view, 1);
    expect(await screen.findByText(/The finding changed while you were reviewing/)).toBeTruthy();
    expect(getSubmissionDesk).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    await waitFor(() => expect(getSubmissionDesk).toHaveBeenCalledTimes(2));
  });

  it("coalesces refresh bursts and re-reads every loaded page", async () => {
    const firstPage = Array.from({ length: 3 }, (_, index) => row(`VA-00${index + 1}`));
    const secondPage = [row("VA-004")];
    vi.mocked(listSubmissionDesk).mockImplementation(async (_key, params) => {
      if (params?.findingOffset === 3) {
        return listing(secondPage, { findings_page: { ...page(1, 4, 3), limit: 3 } });
      }
      const limit = params?.findingLimit ?? 3;
      const rows = [...firstPage, ...secondPage].slice(0, limit);
      return listing(rows, { findings_page: { ...page(rows.length, 4), limit } });
    });
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const view = renderTab(0);
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    expect(await screen.findByText("Showing 1–4 of 4")).toBeTruthy();

    const gate = deferred<SubmissionDeskListing>();
    vi.mocked(listSubmissionDesk).mockClear();
    vi.mocked(listSubmissionDesk).mockReturnValueOnce(gate.promise);
    rerenderTab(view, 1);
    rerenderTab(view, 2);
    rerenderTab(view, 3);
    expect(listSubmissionDesk).toHaveBeenCalledTimes(1);
    expect(vi.mocked(listSubmissionDesk).mock.calls[0][1]).toMatchObject({ findingOffset: 0, findingLimit: 4 });
    await act(async () => {
      gate.resolve(listing([...firstPage, ...secondPage], { findings_page: { ...page(4, 4), limit: 4 } }));
    });
    await waitFor(() => expect(listSubmissionDesk).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Showing 1–4 of 4")).toBeTruthy();
  });

  it("restores the loaded queue window after leaving for finding review", async () => {
    const rows = [row("VA-001"), row("VA-002"), row("VA-003"), row("VA-004")];
    vi.mocked(listSubmissionDesk).mockImplementation(async (_key, params) => {
      const offset = params?.findingOffset ?? 0;
      const limit = params?.findingLimit ?? 3;
      const selected = rows.slice(offset, offset + limit);
      return listing(selected, { findings_page: { ...page(selected.length, 4, offset), limit } });
    });
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const view = renderTab();
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    await screen.findByText("Showing 1–4 of 4");
    view.unmount();
    vi.mocked(listSubmissionDesk).mockClear();
    renderTab();
    await waitFor(() => expect(vi.mocked(listSubmissionDesk).mock.calls[0][1]).toMatchObject({ findingOffset: 0, findingLimit: 4 }));
    expect(await screen.findByText("Showing 1–4 of 4")).toBeTruthy();
  });

  it("ignores a late detail response for a finding that is no longer selected", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]));
    const slow = deferred<SubmissionDeskDetail>();
    vi.mocked(getSubmissionDesk).mockImplementation((_key, slug) => (
      slug === "VA-001" ? slow.promise : Promise.resolve(detail("VA-002", {
        workspace: { ...detail("VA-002").workspace, external_body: "Second body." },
      }))
    ));
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Second Acme finding/ }));
    await waitFor(() => expect(getSubmissionDesk).toHaveBeenLastCalledWith("acme", "VA-002"));
    expect(await screen.findByText("Second body.")).toBeTruthy();
    await act(async () => slow.resolve(detail("VA-001")));
    expect(screen.getByText("Second body.")).toBeTruthy();
    expect(screen.queryByText("Reviewed external body.")).toBeNull();
  });

  it("keeps a finding picked before the first listing's effects have run", async () => {
    const queue = deferred<SubmissionDeskListing>();
    vi.mocked(listSubmissionDesk).mockReturnValue(queue.promise);
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    renderTab();
    // Click the row from the mutation callback of the commit that shows it:
    // the commit's passive effects (the first-row auto-select) run later.
    const reactActEnvironment = globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean };
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = false;
    try {
      await new Promise<void>((done) => {
        const observer = new MutationObserver(() => {
          const second = screen.queryByRole("button", { name: /Second Acme finding/ });
          if (!second) return;
          observer.disconnect();
          second.click();
          done();
        });
        observer.observe(document.body, { childList: true, subtree: true });
        queue.resolve(listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]));
      });
    } finally {
      reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    }
    expect(await screen.findByRole("region", { name: "Submission VA-002" })).toBeTruthy();
    await waitFor(() => expect(getSubmissionDesk).toHaveBeenLastCalledWith("acme", "VA-002"));
  });

  it("shows version history with attachments, finding version, staleness, and downloads", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();
    await screen.findByText("Reviewed external body.");
    fireEvent.click(screen.getByRole("tab", { name: /Versions/ }));

    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[2]).getByText("Stale")).toBeTruthy();
    expect(within(rows[1]).getByText("poc.py")).toBeTruthy();
    expect(within(rows[2]).getByRole("link", { name: /Download v1/ }).getAttribute("href")).toBe("/download/VA-001/1");
  });

  it("links only http(s) platform URLs from the external record", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([
      row("VA-001", { readiness: "filed", submission_status: "submitted", submission_ref: "H1-77", submission_url: "javascript:alert(1)" }),
    ]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const view = renderTab();
    const header = await cardHeader();
    expect(await header.findByText("javascript:alert(1)")).toBeTruthy();
    expect(header.queryByRole("link", { name: /Platform report/ })).toBeNull();
    view.unmount();

    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([
      row("VA-001", { readiness: "filed", submission_status: "submitted", submission_url: "https://hackerone.example/reports/77" }),
    ]));
    renderTab();
    const link = await (await cardHeader()).findByRole("link", { name: /Platform report/ });
    expect(link.getAttribute("href")).toBe("https://hackerone.example/reports/77");
  });

  it("recovers staged exports across every diagnostic page and locks selection meanwhile", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001"), row("VA-002")], { staging_count: 1 }));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const firstPage = deferred<Awaited<ReturnType<typeof recoverSubmissionExports>>>();
    vi.mocked(recoverSubmissionExports)
      .mockReturnValueOnce(firstPage.promise)
      .mockResolvedValueOnce({
        actor_surface: "web-ui",
        recovered_version_ids: [],
        failed_version_ids: [8],
        failed_versions: [{ id: 8, finding_slug: "VA-002", version_number: 4, status: "failed", failure_reason: "published package changed", staging_relative_path: "submissions/VA-002/versions/.staging/0004.tmp", relative_path: "submissions/VA-002/versions/0004/submission.md" }],
        failed_versions_page: { ...page(1, 2, 1) },
        orphaned_staging_paths: [],
        orphaned_staging_page: { limit: 100, returned: 0, has_more: false, next_after: null },
      });
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Recover 1 staged export/ }));
    const queueRow = screen.getAllByRole("button", { pressed: false }).find((button) => button.textContent?.includes("VA-002"));
    expect((queueRow as HTMLButtonElement).disabled).toBe(true);
    await act(async () => {
      firstPage.resolve({
        actor_surface: "web-ui",
        recovered_version_ids: [7],
        failed_version_ids: [],
        failed_versions: [],
        failed_versions_page: { ...page(0, 2), has_more: true, next_offset: 1 },
        orphaned_staging_paths: [],
        orphaned_staging_page: { limit: 100, returned: 0, has_more: false, next_after: null },
      });
    });
    await waitFor(() => expect(recoverSubmissionExports).toHaveBeenCalledTimes(2));
    expect(vi.mocked(recoverSubmissionExports).mock.calls[1][2]).toEqual({ failedVersionOffset: 1, orphanAfter: "" });
    expect(await screen.findByText("published package changed")).toBeTruthy();
    expect(await screen.findByText("Recovered 1 staged export.")).toBeTruthy();
  });

  it("keeps rendered Markdown tables keyboard-scrollable and image references inert", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    const withMedia = detail();
    withMedia.workspace = {
      ...withMedia.workspace,
      external_body: "| Field | Value |\n| --- | --- |\n| role | admin |\n\n![Acme capture](https://acme.example/capture.png)",
    };
    vi.mocked(getSubmissionDesk).mockResolvedValue(withMedia);
    const { container } = renderTab();

    const table = await screen.findByRole("region", { name: "Scrollable table" });
    expect(table.getAttribute("tabindex")).toBe("0");
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("https://acme.example/capture.png")).toBeTruthy();
  });

  it("keeps a queue failure visible inside the queue with a retry", async () => {
    vi.mocked(listSubmissionDesk)
      .mockRejectedValueOnce(new Error("submissions backend unavailable"))
      .mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();

    const queue = await screen.findByRole("complementary", { name: "Submission queue" });
    expect(await within(queue).findByText("submissions backend unavailable")).toBeTruthy();
    fireEvent.click(within(queue).getByRole("button", { name: "Retry" }));
    expect(await within(queue).findByText("Missing authorization on Acme admin API VA-001")).toBeTruthy();
  });

  it("offers the shared Needs attention scope and widens it for a state outside it", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();
    const scope = await screen.findByRole("group", { name: "Scope" });
    await waitFor(() => expect(within(scope).getByRole("button", { name: /^Needs attention\s*99/ }).getAttribute("aria-pressed")).toBe("true"));
    expect(within(scope).getByRole("button", { name: /^All\s*231/ })).toBeTruthy();
    fireEvent.click(within(screen.getByRole("group", { name: "State" })).getByRole("button", { name: /Filed\s*12/ }));
    await waitFor(() => expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ readiness: "filed" }));
    expect(within(scope).getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(within(scope).getByRole("button", { name: /^All/ }));
    fireEvent.click(within(screen.getByRole("group", { name: "State" })).getByRole("button", { name: /Filed\s*12/ }));
    await waitFor(() => expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ readiness: "all" }));
  });

  it("moves the selection with a filter change and never shows a finding the list excludes unannounced", async () => {
    vi.mocked(listSubmissionDesk).mockImplementation(async (_key, params) => {
      if (params?.readiness === "filed") return listing([row("VA-005", { title: "Filed Acme finding", readiness: "filed" })]);
      if (params?.readiness === "ready") return listing([]);
      return listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]);
    });
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    renderTab();
    await screen.findByRole("region", { name: "Submission VA-001" });
    const states = screen.getByRole("group", { name: "State" });
    fireEvent.click(within(states).getByRole("button", { name: /Filed/ }));
    expect(await screen.findByRole("region", { name: "Submission VA-005" })).toBeTruthy();
    fireEvent.click(within(states).getByRole("button", { name: /Ready to export/ }));
    expect(await screen.findByText("No finding selected.")).toBeTruthy();
    expect(screen.queryByRole("region", { name: /Submission VA-/ })).toBeNull();
  });

  it("starts a filter change at once and drops the superseded listing when it lands", async () => {
    const stale = deferred<SubmissionDeskListing>();
    vi.mocked(listSubmissionDesk).mockImplementation((_key, params) => (
      params?.readiness === "filed"
        ? Promise.resolve(listing([row("VA-005", { title: "Filed Acme finding", readiness: "filed" })]))
        : stale.promise
    ));
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    renderTab();
    fireEvent.click(within(await screen.findByRole("group", { name: "State" })).getByRole("button", { name: /Filed/ }));
    const queue = screen.getByRole("complementary", { name: "Submission queue" });
    expect(await within(queue).findByText("Filed Acme finding")).toBeTruthy();
    await act(async () => { stale.resolve(listing([row("VA-001")])); });
    expect(within(queue).getByText("Filed Acme finding")).toBeTruthy();
    expect(within(queue).getAllByRole("listitem")).toHaveLength(1);
  });

  it("keeps a finding a refresh dropped from the list open, and says it is outside the list", async () => {
    vi.mocked(listSubmissionDesk)
      .mockResolvedValueOnce(listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]))
      .mockResolvedValue(listing([row("VA-002", { title: "Second Acme finding" })]));
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    const view = renderTab(0);
    await screen.findByRole("region", { name: "Submission VA-001" });
    rerenderTab(view, 1);
    expect(await screen.findByText(/VA-001 is not in this list/)).toBeTruthy();
    expect(screen.getByRole("region", { name: "Submission VA-001" })).toBeTruthy();
  });

  it("opens the finding and section a link names, and writes the selection to the address", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]));
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    renderTab(0, { initialSubmissionSlug: "VA-002", initialDrawerTab: "versions" });
    expect(await screen.findByRole("region", { name: "Submission VA-002" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /Versions/ }).getAttribute("aria-selected")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: /Missing authorization on Acme admin API VA-001/ }));
    await waitFor(() => expect(window.location.hash).toBe("#/engagements/acme?tab=submissions&submission=VA-001&dtab=versions"));
    fireEvent.click(screen.getByRole("tab", { name: "Submission body" }));
    await waitFor(() => expect(window.location.hash).toBe("#/engagements/acme?tab=submissions&submission=VA-001"));
  });

  it("keeps filters and the open finding when the tab is left and reopened", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001"), row("VA-002", { title: "Second Acme finding" })]));
    vi.mocked(getSubmissionDesk).mockImplementation(async (_key, slug) => detail(slug));
    const first = renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Second Acme finding/ }));
    fireEvent.click(within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: /High/ }));
    await screen.findByRole("region", { name: "Submission VA-002" });
    first.unmount();
    vi.mocked(getSubmissionDesk).mockClear();
    renderTab();
    // The saved finding's detail read starts at once, before the listing settles.
    await waitFor(() => expect(getSubmissionDesk).toHaveBeenCalledWith("acme", "VA-002"));
    expect(await screen.findByRole("region", { name: "Submission VA-002" })).toBeTruthy();
    expect(within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: /High/ }).getAttribute("aria-pressed")).toBe("true");
    await waitFor(() => expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ severity: ["high"] }));
  });

  it("tells an empty engagement apart from a filter that matches nothing", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([], {
      counts: { ready: 0, blocked: 0, needs_draft: 0, exported: 0, filed: 0, not_candidate: 0, incomplete_exports: 0, actionable: 0, all: 0 },
      facets: { severity: {}, platform: {} },
    }));
    const view = renderTab();
    expect(await screen.findByText("No findings to submit yet.")).toBeTruthy();
    expect(screen.queryByText(/match these filters/)).toBeNull();
    view.unmount();

    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([], { findings_page: page(0) }));
    renderTab();
    const queue = await screen.findByRole("complementary", { name: "Submission queue" });
    expect(await within(queue).findByText("No findings are in To do.")).toBeTruthy();
    expect(within(queue).getByRole("button", { name: "Show all findings" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Search submissions"), { target: { value: "zzzz" } });
    expect(await within(queue).findByText("No findings match these filters.")).toBeTruthy();
    fireEvent.click(within(queue).getByRole("button", { name: "Clear filters" }));
    expect((screen.getByLabelText("Search submissions") as HTMLInputElement).value).toBe("");
  });

  it("shows each queued finding's severity as a word, not colour alone", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001"), row("VA-002", { severity: "low", title: "Second Acme finding" })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();
    const queue = await screen.findByRole("complementary", { name: "Submission queue" });
    const second = (await within(queue).findByText("Second Acme finding")).closest("button") as HTMLElement;
    expect(within(second).getByTitle("Severity: Low").textContent).toBe("Low");
    expect((await cardHeader()).getByTitle("Severity: High").textContent).toBe("High");
  });

  it("keeps the time of day for changes older than the relative window", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { updated_at: "2025-01-02T03:04:05Z" })]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();
    const queue = await screen.findByRole("complementary", { name: "Submission queue" });
    expect(await within(queue).findByText("2025-01-02 03:04 UTC")).toBeTruthy();
  });

  it("opens on All when nothing needs attention, and on Needs attention again next visit", async () => {
    const quiet = { ready: 0, blocked: 0, needs_draft: 0, exported: 0, filed: 2, not_candidate: 3, incomplete_exports: 0, actionable: 0, all: 5 };
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001", { readiness: "filed" })], { counts: quiet }));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    const first = renderTab();
    const scope = await screen.findByRole("group", { name: "Scope" });
    await waitFor(() => expect(within(scope).getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true"));
    await waitFor(() => expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ readiness: "all" }));
    first.unmount();
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    renderTab();
    const again = await screen.findByRole("group", { name: "Scope" });
    await waitFor(() => expect(within(again).getByRole("button", { name: /^Needs attention/ }).getAttribute("aria-pressed")).toBe("true"));
    expect(vi.mocked(listSubmissionDesk).mock.calls.at(-1)?.[1]).toMatchObject({ readiness: "actionable" });
  });

  it("keeps the blind-triage note one readable sentence around the packet hash", async () => {
    vi.mocked(listSubmissionDesk).mockResolvedValue(listing([row("VA-001")]));
    vi.mocked(getSubmissionDesk).mockResolvedValue(detail());
    renderTab();
    await (await cardHeader()).findByRole("button", { name: "Export v3…" });
    fireEvent.click(screen.getByRole("tab", { name: /Package/ }));
    const note = screen.getByText(/Reviewed by blind triage/).closest(".subm-pkg-note") as HTMLElement;
    // Icon plus one text block: the hash is inline in the sentence, not its own flex item.
    expect([...note.children].map((child) => child.tagName.toLowerCase())).toEqual(["svg", "span"]);
  });
});
