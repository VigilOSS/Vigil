// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  exportSubmissionVersion,
  getSubmissionDetail,
  listSubmissions,
  recoverSubmissionExports,
} from "../lib/api";
import { SubmissionsTab } from "./SubmissionsTab";

vi.mock("../lib/api", () => ({
  exportSubmissionVersion: vi.fn(),
  getSubmissionDetail: vi.fn(),
  listSubmissions: vi.fn(),
  recoverSubmissionExports: vi.fn(),
  submissionVersionDownloadUrl: vi.fn(
    (_engagement: string, slug: string, version: number) =>
      `/download/${slug}/${version}`,
  ),
}));

const listing = {
  findings: [
    {
      id: 91,
      slug: "VA-001",
      title: "Missing authorization on admin API",
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
    },
  ],
  findings_page: {
    offset: 0,
    limit: 100,
    returned: 1,
    total: 1,
    has_more: false,
    next_offset: null,
  },
  staging_count: 0,
  failed_count: 0,
};

const detail = {
  finding: {
    ...listing.findings[0],
    canonical_location: "https://target.test/admin",
    summary: "An ordinary user can read the admin response.",
  },
  workspace: {
    present: true,
    submission_path: "submissions/VA-001/submission.md",
    context_path: "submissions/VA-001/submission-context.json",
    markdown: "# Missing authorization\n\nReviewed body.",
    submission_sha256: "b".repeat(64),
    context: { platform: "bugcrowd", mode: "final" },
    final_ready: true,
    blockers: [],
  },
  eligible_attachments: [
    {
      id: 42,
      relative_path: "evidence/response.json",
      kind: "proof",
      media_type: "application/json",
      size_bytes: 18,
      sha256: "c".repeat(64),
      present: true,
    },
  ],
  eligible_attachments_page: {
    offset: 0,
    limit: 100,
    returned: 1,
    total: 1,
    has_more: false,
    next_offset: null,
  },
  versions: [],
  versions_page: {
    offset: 0,
    limit: 100,
    returned: 0,
    total: 0,
    has_more: false,
    next_offset: null,
  },
  pending_version_count: 0,
  pending_versions: [],
  pending_versions_page: {
    offset: 0,
    limit: 100,
    returned: 0,
    total: 0,
    has_more: false,
    next_offset: null,
  },
};

afterEach(() => {
  cleanup();
  vi.mocked(exportSubmissionVersion).mockReset();
  vi.mocked(getSubmissionDetail).mockReset();
  vi.mocked(listSubmissions).mockReset();
  vi.mocked(recoverSubmissionExports).mockReset();
});

describe("SubmissionsTab", () => {
  it("keeps a listing failure visible instead of presenting an empty workspace", async () => {
    vi.mocked(listSubmissions).mockRejectedValueOnce(
      new Error("submission API unavailable"),
    );

    render(<SubmissionsTab engagementKey="demo" />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("submission API unavailable");
    expect(screen.queryByText("No findings to review")).toBeNull();
  });

  it("keeps the newest listing when overlapping refreshes finish out of order", async () => {
    const staleListing = {
      ...listing,
      findings: [{ ...listing.findings[0], title: "Stale submission finding" }],
    };
    const freshListing = {
      ...listing,
      findings: [{ ...listing.findings[0], title: "Fresh submission finding" }],
    };
    let resolveStale: (value: typeof listing) => void = () => undefined;
    let resolveFresh: (value: typeof listing) => void = () => undefined;
    vi.mocked(listSubmissions)
      .mockImplementationOnce(
        () => new Promise((resolve) => {
          resolveStale = resolve;
        }),
      )
      .mockImplementationOnce(
        () => new Promise((resolve) => {
          resolveFresh = resolve;
        }),
      );
    vi.mocked(getSubmissionDetail).mockResolvedValue(detail);

    const { rerender } = render(
      <SubmissionsTab engagementKey="engagement one" refreshVersion={0} />,
    );
    await waitFor(() => expect(listSubmissions).toHaveBeenCalledTimes(1));
    rerender(<SubmissionsTab engagementKey="engagement one" refreshVersion={1} />);
    await waitFor(() => expect(listSubmissions).toHaveBeenCalledTimes(2));

    await act(async () => resolveFresh(freshListing));
    expect(await screen.findByText("Fresh submission finding")).toBeTruthy();
    await act(async () => resolveStale(staleListing));

    expect(screen.getByText("Fresh submission finding")).toBeTruthy();
    expect(screen.queryByText("Stale submission finding")).toBeNull();
  });

  it("preserves a selected later-page finding across first-page refreshes", async () => {
    const secondFinding = {
      ...listing.findings[0],
      id: 92,
      slug: "VA-002",
      title: "Second finding",
    };
    const firstPage = {
      ...listing,
      findings_page: {
        offset: 0,
        limit: 1,
        returned: 1,
        total: 2,
        has_more: true,
        next_offset: 1,
      },
    };
    const secondPage = {
      ...listing,
      findings: [secondFinding],
      findings_page: {
        offset: 1,
        limit: 1,
        returned: 1,
        total: 2,
        has_more: false,
        next_offset: null,
      },
    };
    vi.mocked(listSubmissions)
      .mockResolvedValueOnce(firstPage)
      .mockResolvedValueOnce(secondPage)
      .mockResolvedValueOnce({
        ...firstPage,
        findings: [{ ...listing.findings[0], title: "Refreshed first finding" }],
      });
    vi.mocked(getSubmissionDetail).mockImplementation(async (_engagementKey, slug) => ({
      ...detail,
      finding: slug === "VA-002"
        ? { ...detail.finding, id: 92, slug: "VA-002", title: "Second finding" }
        : detail.finding,
    }));

    const { rerender } = render(
      <SubmissionsTab engagementKey="engagement one" refreshVersion={0} />,
    );
    await screen.findByText("Missing authorization on admin API");
    fireEvent.click(screen.getByRole("button", { name: "Load more findings" }));
    const secondButton = await screen.findByRole("button", { name: /Second finding/ });
    fireEvent.click(secondButton);
    await waitFor(() => expect(secondButton.className).toContain("is-selected"));

    rerender(<SubmissionsTab engagementKey="engagement one" refreshVersion={1} />);
    await waitFor(() => expect(listSubmissions).toHaveBeenCalledTimes(3));

    const retainedButton = await screen.findByRole("button", { name: /Second finding/ });
    expect(retainedButton.className).toContain("is-selected");
    expect(screen.getByText("Refreshed first finding")).toBeTruthy();
  });

  it("keeps the reviewed document primary and attachments opt-in", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(listing);
    vi.mocked(getSubmissionDetail).mockResolvedValue(detail);

    render(<SubmissionsTab engagementKey="engagement one" />);

    expect(await screen.findByText("Missing authorization on admin API")).toBeTruthy();
    expect(await screen.findByText("Reviewed body.")).toBeTruthy();
    expect(screen.getByText("No attachments selected")).toBeTruthy();
    expect(
      (screen.getByRole("checkbox", { name: /response\.json/ }) as HTMLInputElement).checked,
    ).toBe(false);
    expect(
      (screen.getByRole("button", { name: "Export immutable version" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);

    fireEvent.click(screen.getByRole("tab", { name: "Raw Markdown" }));
    expect(screen.getByText(/# Missing authorization/)).toBeTruthy();
  });

  it("renders untrusted Markdown images as inert references", async () => {
    vi.mocked(listSubmissions).mockResolvedValue(listing);
    vi.mocked(getSubmissionDetail).mockResolvedValue({
      ...detail,
      workspace: {
        ...detail.workspace,
        markdown: [
          "![remote proof](https://attacker.test/pixel.png)",
          "![inline proof](data:image/png;base64,AAAA)",
          "[review source](https://example.test/report)",
        ].join("\n\n"),
      },
    });

    const { container } = render(<SubmissionsTab engagementKey="engagement one" />);

    expect(await screen.findByText("remote proof")).toBeTruthy();
    expect(screen.getByText("inline proof")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("https://attacker.test/pixel.png")).toBeTruthy();
    const normalLink = screen.getByRole("link", { name: "review source" });
    expect(normalLink.getAttribute("target")).toBe("_blank");
    expect(normalLink.getAttribute("rel")).toBe("noopener noreferrer");
  });

  it("loads later attachment pages without losing selections or duplicating candidates", async () => {
    const laterArtifact = {
      ...detail.eligible_attachments[0],
      id: 43,
      relative_path: "evidence/later-response.json",
      sha256: "e".repeat(64),
    };
    const firstPage = {
      ...detail,
      eligible_attachments_page: {
        offset: 0,
        limit: 1,
        returned: 1,
        total: 2,
        has_more: true,
        next_offset: 1,
      },
    };
    const secondPage = {
      ...detail,
      eligible_attachments: [detail.eligible_attachments[0], laterArtifact],
      eligible_attachments_page: {
        offset: 1,
        limit: 1,
        returned: 2,
        total: 2,
        has_more: false,
        next_offset: null,
      },
    };
    let resolveSecondPage: (value: typeof secondPage) => void = () => undefined;
    const secondPageRequest = new Promise<typeof secondPage>((resolve) => {
      resolveSecondPage = resolve;
    });
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      staging_count: 1,
      findings: [
        ...listing.findings,
        {
          ...listing.findings[0],
          id: 92,
          slug: "VA-002",
          title: "Second finding",
        },
      ],
    });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce(firstPage)
      .mockReturnValueOnce(secondPageRequest);

    render(<SubmissionsTab engagementKey="engagement one" />);

    const firstAttachment = await screen.findByRole("checkbox", { name: /response\.json/ });
    fireEvent.click(firstAttachment);
    expect(screen.getByText("Showing 1 of 2 eligible artifacts.")).toBeTruthy();
    expect(screen.getByText(/bounded attachment page is truncated/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Load more attachments" }));

    expect(
      screen.getByRole("button", { name: /Second finding/ }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: "Recover staged exports" }).hasAttribute("disabled"),
    ).toBe(true);
    resolveSecondPage(secondPage);
    expect(await screen.findByRole("checkbox", { name: /later-response\.json/ })).toBeTruthy();
    expect(getSubmissionDetail).toHaveBeenLastCalledWith(
      "engagement one",
      "VA-001",
      { attachmentOffset: 1, attachmentLimit: 1 },
    );
    expect(
      (screen.getByRole("checkbox", { name: /^Attach evidence\/response\.json$/ }) as HTMLInputElement)
        .checked,
    ).toBe(true);
    expect(screen.getAllByRole("checkbox")).toHaveLength(2);
    expect(screen.getByText("Showing 2 of 2 eligible artifacts.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Load more attachments" })).toBeNull();
  });

  it("loads later bounded finding and version pages", async () => {
    const secondFinding = {
      ...listing.findings[0],
      id: 92,
      slug: "VA-002",
      title: "Second finding",
    };
    const versionOne = {
      id: 77,
      finding_id: 91,
      version_number: 1,
      status: "complete" as const,
      platform: "bugcrowd" as const,
      package_format: "markdown" as const,
      actor_surface: "web-ui" as const,
      relative_path: "submissions/VA-001/versions/0001/submission.md",
      media_type: "text/markdown",
      size_bytes: 100,
      sha256: "d".repeat(64),
      submission_sha256: "d".repeat(64),
      source_finding_row_version: 9,
      source_finding_updated_at: "2026-09-09T12:00:00Z",
      attachment_ids: [],
      attachment_count: 0,
      artifact_id: 88,
      created_at: "2026-09-09T12:00:00Z",
      completed_at: "2026-09-09T12:00:01Z",
      stale: false,
      idempotent_replay: false,
    };
    const versionTwo = {
      ...versionOne,
      id: 78,
      version_number: 2,
      relative_path: "submissions/VA-001/versions/0002/submission.md",
    };
    vi.mocked(listSubmissions)
      .mockResolvedValueOnce({
        ...listing,
        findings_page: {
          offset: 0,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: true,
          next_offset: 1,
        },
      })
      .mockResolvedValueOnce({
        ...listing,
        findings: [secondFinding],
        findings_page: {
          offset: 1,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: false,
          next_offset: null,
        },
      });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce({
        ...detail,
        versions: [versionTwo],
        versions_page: {
          offset: 0,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: true,
          next_offset: 1,
        },
      })
      .mockResolvedValueOnce({
        ...detail,
        versions: [versionOne],
        versions_page: {
          offset: 1,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: false,
          next_offset: null,
        },
      });

    render(<SubmissionsTab engagementKey="engagement one" />);

    await screen.findByText("Version 2");
    fireEvent.click(screen.getByRole("button", { name: "Load more findings" }));
    expect(await screen.findByRole("button", { name: /Second finding/ })).toBeTruthy();
    expect(listSubmissions).toHaveBeenLastCalledWith("engagement one", {
      findingOffset: 1,
      findingLimit: 1,
    });

    fireEvent.click(screen.getByRole("button", { name: "Load more versions" }));
    expect(await screen.findByText("Version 1")).toBeTruthy();
    expect(getSubmissionDetail).toHaveBeenLastCalledWith(
      "engagement one",
      "VA-001",
      { versionOffset: 1, versionLimit: 1 },
    );
  });

  it("loads later bounded incomplete-export pages", async () => {
    const pendingOne = {
      id: 78,
      finding_slug: "VA-001",
      version_number: 2,
      status: "failed" as const,
      failure_reason: "first failure",
      staging_relative_path: "submissions/VA-001/versions/.staging/0002.tmp",
      relative_path: "submissions/VA-001/versions/0002/submission.md",
    };
    const pendingTwo = {
      ...pendingOne,
      id: 79,
      version_number: 3,
      failure_reason: "second failure",
      staging_relative_path: "submissions/VA-001/versions/.staging/0003.tmp",
      relative_path: "submissions/VA-001/versions/0003/submission.md",
    };
    vi.mocked(listSubmissions).mockResolvedValue(listing);
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce({
        ...detail,
        pending_version_count: 2,
        pending_versions: [pendingOne],
        pending_versions_page: {
          offset: 0,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: true,
          next_offset: 1,
        },
      })
      .mockResolvedValueOnce({
        ...detail,
        pending_version_count: 2,
        pending_versions: [pendingTwo],
        pending_versions_page: {
          offset: 1,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: false,
          next_offset: null,
        },
      });

    render(<SubmissionsTab engagementKey="engagement one" />);

    await screen.findByText(/Failed version 2/);
    fireEvent.click(
      screen.getByRole("button", { name: "Load more incomplete exports" }),
    );
    expect(await screen.findByText(/Failed version 3/)).toBeTruthy();
    expect(getSubmissionDetail).toHaveBeenLastCalledWith(
      "engagement one",
      "VA-001",
      { pendingVersionOffset: 1, pendingVersionLimit: 1 },
    );
  });

  it("clears the previous document when a newly selected finding fails to load", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      findings: [
        ...listing.findings,
        {
          ...listing.findings[0],
          id: 92,
          slug: "VA-002",
          title: "Second finding",
        },
      ],
    });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce(detail)
      .mockRejectedValueOnce(new Error("second finding unavailable"));

    render(<SubmissionsTab engagementKey="engagement one" />);

    expect(await screen.findByText("Reviewed body.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Second finding/ }));

    expect((await screen.findByRole("alert")).textContent).toContain("second finding unavailable");
    expect(screen.queryByText("Reviewed body.")).toBeNull();
    expect(screen.getByText("Submission detail unavailable.")).toBeTruthy();
  });

  it("uses a supported finding platform in no-workspace renderer guidance", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      findings: [{ ...listing.findings[0], submission_platform: "direct" }],
    });
    vi.mocked(getSubmissionDetail).mockResolvedValue({
      ...detail,
      finding: { ...detail.finding, submission_platform: "direct" },
      workspace: {
        ...detail.workspace,
        present: false,
        markdown: "",
        submission_sha256: "",
        context: {},
        final_ready: false,
        blockers: ["submission workspace not found"],
      },
    });

    render(<SubmissionsTab engagementKey="engagement one" />);

    expect(await screen.findByText(/Direct disclosure/)).toBeTruthy();
    expect(
      await screen.findByText(/vigil assess export submission VA-001 --platform direct --draft/),
    ).toBeTruthy();
  });

  it("shows the existing external record and links only safe submission URLs", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      findings: [
        {
          ...listing.findings[0],
          submission_status: "submitted",
          submission_platform: "hackerone",
          submission_ref: "H1-12345",
          submission_url: "https://hackerone.com/reports/12345",
        },
        {
          ...listing.findings[0],
          id: 92,
          slug: "VA-002",
          title: "Unsafe external URL",
          submission_status: "needs_info",
          submission_url: "javascript:alert(1)",
        },
      ],
    });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce(detail)
      .mockResolvedValueOnce({
        ...detail,
        finding: { ...detail.finding, id: 92, slug: "VA-002" },
      });

    render(<SubmissionsTab engagementKey="engagement one" />);

    const externalRecord = await screen.findByRole("region", {
      name: "External submission record",
    });
    expect(externalRecord.textContent).toContain("submitted");
    expect(externalRecord.textContent).toContain("H1-12345");
    expect(
      within(externalRecord)
        .getByRole("link", { name: /hackerone\.com\/reports\/12345/ })
        .getAttribute("href"),
    ).toBe("https://hackerone.com/reports/12345");

    fireEvent.click(screen.getByRole("button", { name: /Unsafe external URL/ }));
    await waitFor(() => {
      expect(externalRecord.textContent).toContain("javascript:alert(1)");
    });
    expect(within(externalRecord).queryByRole("link")).toBeNull();
  });

  it("exports selected registered artifacts and exposes immutable history", async () => {
    vi.mocked(listSubmissions)
      .mockResolvedValueOnce(listing)
      .mockResolvedValueOnce({
        ...listing,
        findings: [
          {
            ...listing.findings[0],
            version_count: 1,
            latest_version_number: 1,
          },
        ],
      });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce(detail)
      .mockResolvedValueOnce({
        ...detail,
        versions: [
          {
            id: 77,
            version_number: 1,
            status: "complete",
            platform: "bugcrowd",
            package_format: "zip",
            actor_surface: "web-ui",
            relative_path: "submissions/VA-001/versions/0001/submission.zip",
            media_type: "application/zip",
            size_bytes: 900,
            sha256: "d".repeat(64),
            submission_sha256: "b".repeat(64),
            source_finding_row_version: 9,
            source_finding_updated_at: "2026-09-09T12:00:00Z",
            attachment_ids: [42],
            attachment_count: 1,
            artifact_id: 88,
            created_at: "2026-09-09T12:10:00Z",
            completed_at: "2026-09-09T12:10:01Z",
            stale: false,
            idempotent_replay: false,
          },
        ],
      });
    vi.mocked(exportSubmissionVersion).mockResolvedValue({
      id: 77,
      version_number: 1,
      status: "complete",
    } as never);

    render(<SubmissionsTab engagementKey="engagement one" />);
    const attachment = await screen.findByRole("checkbox", { name: /response\.json/ });
    fireEvent.click(attachment);
    expect(screen.getByText("1 attachment selected")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export immutable version" }));

    await waitFor(() => {
      expect(exportSubmissionVersion).toHaveBeenCalledWith(
        "engagement one",
        "VA-001",
        {
          platform: "bugcrowd",
          submission_path: "submissions/VA-001/submission.md",
          context_path: "submissions/VA-001/submission-context.json",
          attachment_ids: [42],
          actor_surface: "web-ui",
        },
      );
    });
    expect(
      (await screen.findByRole("link", { name: /Download v1/ })).getAttribute("href"),
    ).toBe("/download/VA-001/1");
    expect(screen.getByText("ZIP · 1 attachment")).toBeTruthy();
    expect(await screen.findByLabelText("1 immutable version")).toBeTruthy();
  });

  it("locks recovery and finding selection while an export refresh is in flight", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      staging_count: 1,
      findings: [
        ...listing.findings,
        {
          ...listing.findings[0],
          id: 92,
          slug: "VA-002",
          title: "Second finding",
        },
      ],
    });
    vi.mocked(getSubmissionDetail).mockResolvedValue(detail);
    vi.mocked(exportSubmissionVersion).mockImplementation(
      () => new Promise(() => undefined),
    );

    render(<SubmissionsTab engagementKey="engagement one" />);

    await screen.findByText("Reviewed body.");
    fireEvent.click(screen.getByRole("button", { name: "Export immutable version" }));

    expect(
      screen.getByRole("button", { name: /Second finding/ }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: "Recover staged exports" }).hasAttribute("disabled"),
    ).toBe(true);
  });

  it("locks export and finding selection while recovery is in flight", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      staging_count: 1,
      findings: [
        ...listing.findings,
        {
          ...listing.findings[0],
          id: 92,
          slug: "VA-002",
          title: "Second finding",
        },
      ],
    });
    vi.mocked(getSubmissionDetail).mockResolvedValue(detail);
    vi.mocked(recoverSubmissionExports).mockImplementation(
      () => new Promise(() => undefined),
    );

    render(<SubmissionsTab engagementKey="engagement one" />);

    await screen.findByText("Reviewed body.");
    fireEvent.click(screen.getByRole("button", { name: "Recover staged exports" }));

    expect(
      screen.getByRole("button", { name: "Export immutable version" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: /Second finding/ }).hasAttribute("disabled"),
    ).toBe(true);
  });

  it("surfaces recovery and final-readiness blockers", async () => {
    const failedVersion = {
      id: 78,
      finding_slug: "VA-001",
      version_number: 2,
      status: "failed",
      failure_reason: "staged package digest no longer matches",
      staging_relative_path: "submissions/VA-001/versions/.staging/version-2.tmp",
      relative_path: "submissions/VA-001/versions/0002/submission.zip",
    };
    vi.mocked(listSubmissions)
      .mockResolvedValueOnce({ ...listing, staging_count: 1 })
      .mockResolvedValueOnce({
        ...listing,
        staging_count: 0,
        failed_count: 1,
        findings: [{ ...listing.findings[0], failed_version_count: 1 }],
      });
    vi.mocked(getSubmissionDetail)
      .mockResolvedValueOnce({
        ...detail,
        workspace: {
          ...detail.workspace,
          final_ready: false,
          blockers: ["submission workspace is stale relative to the current finding"],
        },
        pending_version_count: 1,
        pending_versions: [{ ...failedVersion, status: "staging", failure_reason: "" }],
      })
      .mockResolvedValueOnce({
        ...detail,
        workspace: {
          ...detail.workspace,
          final_ready: false,
          blockers: ["submission workspace is stale relative to the current finding"],
        },
        pending_version_count: 1,
        pending_versions: [failedVersion],
      });
    vi.mocked(recoverSubmissionExports).mockResolvedValue({
      actor_surface: "web-ui",
      recovered_version_ids: [77],
      failed_version_ids: [78],
      failed_versions: [failedVersion],
      failed_versions_page: {
        offset: 0,
        limit: 100,
        returned: 1,
        total: 1,
        has_more: false,
        next_offset: null,
      },
      orphaned_staging_paths: [
        "submissions/VA-001/versions/.staging/orphaned-package.tmp",
      ],
      orphaned_staging_page: {
        limit: 100,
        returned: 1,
        has_more: false,
        next_after: null,
      },
    });

    render(<SubmissionsTab engagementKey="engagement one" />);

    expect(await screen.findByText(/workspace is stale/)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Export immutable version" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Recover staged exports" }));
    await waitFor(() => {
      expect(recoverSubmissionExports).toHaveBeenCalledWith("engagement one", "web-ui");
    });
    expect(await screen.findByText(/Failed version 2 \(#78\)/)).toBeTruthy();
    expect(screen.getAllByText(/staged package digest no longer matches/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/version-2\.tmp/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/0002\/submission\.zip/).length).toBeGreaterThan(0);
    expect(screen.getByText(/orphaned-package\.tmp/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Recover staged exports" })).toBeNull();
    expect(screen.getByRole("status", { name: "1 failed export reservation" })).toBeTruthy();
    expect(screen.getAllByText(/Failed version 2 \(#78\)/)).toHaveLength(1);
    expect(
      await screen.findByRole("region", { name: "Incomplete export reservations" }),
    ).toBeTruthy();
  });

  it("consumes every bounded recovery-diagnostic page", async () => {
    const failedOne = {
      id: 78,
      finding_slug: "VA-001",
      version_number: 2,
      status: "failed" as const,
      failure_reason: "first failure",
      staging_relative_path: "submissions/VA-001/versions/.staging/0002.tmp",
      relative_path: "submissions/VA-001/versions/0002/submission.md",
    };
    const failedTwo = {
      ...failedOne,
      id: 79,
      version_number: 3,
      failure_reason: "second failure",
      staging_relative_path: "submissions/VA-001/versions/.staging/0003.tmp",
      relative_path: "submissions/VA-001/versions/0003/submission.md",
    };
    const orphanOne = "submissions/VA-098/versions/.staging/a.tmp";
    const orphanTwo = "submissions/VA-099/versions/.staging/b.tmp";
    vi.mocked(listSubmissions)
      .mockResolvedValueOnce({ ...listing, staging_count: 1 })
      .mockResolvedValueOnce(listing);
    vi.mocked(getSubmissionDetail).mockResolvedValue(detail);
    vi.mocked(recoverSubmissionExports)
      .mockResolvedValueOnce({
        actor_surface: "web-ui",
        recovered_version_ids: [77],
        failed_version_ids: [78],
        failed_versions: [failedOne],
        failed_versions_page: {
          offset: 0,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: true,
          next_offset: 1,
        },
        orphaned_staging_paths: [orphanOne],
        orphaned_staging_page: {
          limit: 1,
          returned: 1,
          has_more: true,
          next_after: orphanOne,
        },
      })
      .mockResolvedValueOnce({
        actor_surface: "web-ui",
        recovered_version_ids: [],
        failed_version_ids: [79],
        failed_versions: [failedTwo],
        failed_versions_page: {
          offset: 1,
          limit: 1,
          returned: 1,
          total: 2,
          has_more: false,
          next_offset: null,
        },
        orphaned_staging_paths: [orphanTwo],
        orphaned_staging_page: {
          limit: 1,
          returned: 1,
          has_more: false,
          next_after: null,
        },
      });

    render(<SubmissionsTab engagementKey="engagement one" />);

    await screen.findByText("Reviewed body.");
    fireEvent.click(screen.getByRole("button", { name: "Recover staged exports" }));

    expect(await screen.findByText(/second failure/)).toBeTruthy();
    expect(screen.getByText(orphanOne)).toBeTruthy();
    expect(screen.getByText(orphanTwo)).toBeTruthy();
    expect(recoverSubmissionExports).toHaveBeenNthCalledWith(
      2,
      "engagement one",
      "web-ui",
      { failedVersionOffset: 1, orphanAfter: orphanOne },
    );
  });

  it("keeps failed reservation diagnostics visible when there is nothing to recover", async () => {
    vi.mocked(listSubmissions).mockResolvedValue({
      ...listing,
      failed_count: 1,
      findings: [{ ...listing.findings[0], failed_version_count: 1 }],
    });
    vi.mocked(getSubmissionDetail).mockResolvedValue({
      ...detail,
      pending_version_count: 1,
      pending_versions: [
        {
          id: 79,
          finding_slug: "VA-001",
          version_number: 3,
          status: "failed",
          failure_reason: "destination verification failed",
          staging_relative_path: "submissions/VA-001/versions/.staging/version-3.tmp",
          relative_path: "submissions/VA-001/versions/0003/submission.zip",
        },
      ],
    });

    render(<SubmissionsTab engagementKey="engagement one" />);

    const reservations = await screen.findByRole("region", {
      name: "Incomplete export reservations",
    });
    expect(reservations.textContent).toContain("Failed version 3 (#79)");
    expect(reservations.textContent).toContain("destination verification failed");
    expect(reservations.textContent).toContain("version-3.tmp");
    expect(reservations.textContent).toContain("0003/submission.zip");
    expect(screen.getByRole("status", { name: "1 failed export reservation" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Recover staged exports" })).toBeNull();
  });
});
