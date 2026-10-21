// @vitest-environment jsdom

import { StrictMode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { listEngagementFiles, readEngagementFile, type EngagementFile, type EngagementFileContent } from "../lib/filesApi";
import { FilesTab } from "./FilesTab";

vi.mock("../lib/filesApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/filesApi")>()),
  listEngagementFiles: vi.fn(),
  readEngagementFile: vi.fn(),
}));

function file(name: string, overrides: Partial<EngagementFile> = {}): EngagementFile {
  const json = name.endsWith(".json");
  return {
    name,
    relative_path: name,
    media_type: json ? "application/json" : "text/markdown",
    exists: true,
    group: json ? "snapshot" : "working",
    role: `${name} role`,
    description: `${name} description`,
    size_bytes: 2048,
    modified_at: "2026-09-12T05:06:07Z",
    is_stub: false,
    stub_waiver: "",
    ...overrides,
  };
}

function content(entry: EngagementFile, text: string, overrides: Partial<EngagementFileContent> = {}): EngagementFileContent {
  return { ...entry, content: text, truncated: false, returned_bytes: text.length, ...overrides };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

const brief = file("ENGAGEMENT.md");
const resume = file("RESUME.md");
const rules = file("RULES.md");
const scope = file("scope.json");
const compact = file("COMPACT.md", { exists: false, size_bytes: null, modified_at: null });
const snapshot = file("findings.md", { group: "snapshot", role: "Export snapshot (DB is the source of truth)" });

const bodies: Record<string, string> = {
  "ENGAGEMENT.md": "# Acme brief\n\nAuthorization: Bearer acme-token-123\n",
  "RESUME.md": "# Resume\n\nNext: retest the Acme login.\n",
  "RULES.md": "# Legacy rules\n",
  "scope.json": "{\"hostname\":\"acme.example\",\"scope_hosts\":[\"acme.example\"]}",
  "findings.md": "# Findings export\n",
};

beforeEach(() => {
  window.history.replaceState(null, "", "#/engagements/acme?tab=artifacts");
  vi.mocked(listEngagementFiles).mockResolvedValue([brief, resume, compact, scope, snapshot]);
  vi.mocked(readEngagementFile).mockImplementation(async (_key, name) => {
    const entry = [brief, resume, rules, scope, snapshot].find((item) => item.name === name)!;
    return content(entry, bodies[name]);
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("FilesTab", () => {
  it("opens the program brief first and groups files by role", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);

    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
    expect(readEngagementFile).toHaveBeenCalledWith("acme", "ENGAGEMENT.md");
    const list = screen.getByRole("navigation", { name: "Engagement files" });
    const working = within(list).getByRole("heading", { name: "Working documents" }).parentElement!;
    const snapshots = within(list).getByRole("heading", { name: "Snapshots & config" }).parentElement!;
    expect(within(working).getByText("ENGAGEMENT.md")).toBeTruthy();
    expect(within(working).getByText("RESUME.md")).toBeTruthy();
    expect(within(snapshots).getByText("scope.json")).toBeTruthy();
    expect(within(snapshots).getByText("Export snapshot (DB is the source of truth)")).toBeTruthy();
    // Missing files sit behind a disclosure instead of as disabled rows.
    expect(within(list).getByText("Not created yet (1)")).toBeTruthy();
    expect(within(working).queryByText("COMPACT.md")).toBeNull();
    expect(screen.getByRole("button", { name: /ENGAGEMENT\.md/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("falls back to the legacy brief, then scope, when ENGAGEMENT.md is absent", async () => {
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([
      file("ENGAGEMENT.md", { exists: false, size_bytes: null, modified_at: null }),
      resume,
      rules,
      scope,
    ]);
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledWith("acme", "RULES.md"));
    cleanup();

    vi.mocked(readEngagementFile).mockClear();
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([resume, scope]);
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledWith("acme", "scope.json"));
    expect(await screen.findByRole("note")).toBeTruthy();
    expect(screen.getByRole("note").textContent).toContain("No program brief");
  });

  it("shows size and modified time, and renders the exact bytes in Raw", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    const viewer = await screen.findByRole("article", { name: "ENGAGEMENT.md contents" });
    await within(viewer).findByRole("heading", { name: "Acme brief" });

    expect(within(viewer).getByText("2.0 KB")).toBeTruthy();
    expect(within(viewer).getByText("2026-09-12 05:06:07 UTC")).toBeTruthy();
    fireEvent.click(within(viewer).getByRole("button", { name: "Raw" }));
    expect(viewer.querySelector("pre")?.textContent).toBe(bodies["ENGAGEMENT.md"]);
  });

  it("renders JSON through the syntax-highlighted JSON view", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("heading", { name: "Acme brief" });
    fireEvent.click(screen.getByRole("button", { name: /scope\.json/ }));

    const viewer = await screen.findByRole("article", { name: "scope.json contents" });
    await within(viewer).findByRole("button", { name: "Copy JSON to clipboard" });
    expect(viewer.querySelector(".json-tok-key")?.textContent).toBe("\"hostname\"");
  });

  it("flags an unfilled brief template and the operator's waiver", async () => {
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content({ ...brief, is_stub: true }, "> **STUB — fill this in\n"));
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([{ ...brief, is_stub: true }, scope]);
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);

    expect(await screen.findByText("Unfilled template")).toBeTruthy();
    expect((await screen.findByText("Unfilled template.")).closest("[role=note]")?.textContent)
      .toContain("Target-facing commands are blocked");
    cleanup();

    const reason = "Operator confirmed the Acme lab has no separate brief.";
    const waived = { ...brief, is_stub: true, stub_waiver: reason };
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([waived, scope]);
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content(waived, "> **STUB — fill this in\n"));
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    expect(await screen.findByText("Template · waived")).toBeTruthy();
    expect(await screen.findByText(reason)).toBeTruthy();
  });

  it("reads the list again from Try again after it failed", async () => {
    vi.mocked(listEngagementFiles).mockRejectedValueOnce(new Error("list denied"));
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    expect((await screen.findByRole("alert")).textContent).toContain("File list unavailable: list denied");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
    expect(listEngagementFiles).toHaveBeenCalledTimes(2);
  });

  it("says when a large file was truncated by the view limit", async () => {
    vi.mocked(readEngagementFile).mockResolvedValueOnce(
      content({ ...brief, size_bytes: 3 * 1024 * 1024 }, "# Acme brief\n", { truncated: true, returned_bytes: 1024 * 1024 }),
    );
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);

    const notice = await screen.findByText(/Showing the first 1\.0 MB of 3\.0 MB/);
    expect(notice.closest("[role=note]")?.textContent).toContain("ENGAGEMENT.md");
  });

  it("loads the list once under StrictMode's repeated mount effect", async () => {
    render(<StrictMode><FilesTab engagementKey="acme" refreshVersion={0} /></StrictMode>);
    await screen.findByRole("heading", { name: "Acme brief" });

    expect(listEngagementFiles).toHaveBeenCalledTimes(1);
  });

  it("keeps the open file visible while refreshes coalesce into one follow-up read", async () => {
    const view = render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("heading", { name: "Acme brief" });
    expect(readEngagementFile).toHaveBeenCalledTimes(1);

    const slow = deferred<EngagementFileContent>();
    vi.mocked(readEngagementFile).mockReturnValueOnce(slow.promise);
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={1} />);
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledTimes(2));
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={2} />);
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={3} />);

    // Previous content stays on screen, marked busy, while the refresh runs.
    const viewer = screen.getByRole("article", { name: "ENGAGEMENT.md contents" });
    expect(viewer.getAttribute("aria-busy")).toBe("true");
    expect(within(viewer).getByRole("heading", { name: "Acme brief" })).toBeTruthy();

    slow.resolve(content(brief, "# Acme brief v2\n"));
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledTimes(3));
    await waitFor(() => expect(viewer.getAttribute("aria-busy")).toBe("false"));
  });

  it("keeps the last content with a stale notice when a refresh read fails", async () => {
    const view = render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("heading", { name: "Acme brief" });

    vi.mocked(readEngagementFile).mockRejectedValueOnce(new Error("read denied"));
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={1} />);

    expect((await screen.findByRole("alert")).textContent).toContain("Showing last available content for ENGAGEMENT.md");
    expect(screen.getByRole("heading", { name: "Acme brief" })).toBeTruthy();
  });

  it("opens the default file again when the open one disappears", async () => {
    const view = render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("heading", { name: "Acme brief" });
    fireEvent.click(screen.getByRole("button", { name: /RESUME\.md/ }));
    await screen.findByRole("heading", { name: "Resume" });

    vi.mocked(listEngagementFiles).mockResolvedValueOnce([brief, scope]);
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={1} />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /ENGAGEMENT\.md/ }).getAttribute("aria-pressed")).toBe("true"));
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
  });

  it("ignores a late read failure for a file that is no longer selected", async () => {
    let rejectOld!: (error: Error) => void;
    vi.mocked(readEngagementFile).mockImplementation(async (_key, name) => name === "ENGAGEMENT.md"
      ? new Promise((_resolve, reject) => { rejectOld = reject; })
      : content(scope, bodies["scope.json"]));
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("status", { name: "Loading ENGAGEMENT.md" });

    fireEvent.click(screen.getByRole("button", { name: /scope\.json/ }));
    const viewer = await screen.findByRole("article", { name: "scope.json contents" });
    await within(viewer).findAllByText("\"acme.example\"");
    rejectOld(new Error("old file failure"));
    await Promise.resolve();

    expect(screen.queryByText(/old file failure/)).toBeNull();
    expect(within(viewer).getAllByText("\"acme.example\"")).toHaveLength(2);
  });

  it("opens the file the URL names and puts the chosen file in the URL", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} initialFileName="RESUME.md" />);

    expect(await screen.findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Files" })).toBeTruthy();
    expect(readEngagementFile).not.toHaveBeenCalledWith("acme", "ENGAGEMENT.md");
    const before = window.history.length;
    fireEvent.click(screen.getByRole("button", { name: /scope\.json/ }));
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts&file=scope.json");
    expect(window.history.length).toBe(before + 1);
  });

  it("follows the URL to another file, as browser Back does", async () => {
    const view = render(<FilesTab engagementKey="acme" refreshVersion={0} initialFileName="RESUME.md" />);
    await screen.findByRole("heading", { name: "Resume" });
    view.rerender(<FilesTab engagementKey="acme" refreshVersion={0} initialFileName={undefined} />);
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
  });

  it("says when the file the URL names is not one of the engagement's files", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} initialFileName="PLAN.md" />);

    expect((await screen.findByText(/PLAN\.md is not one of this engagement's files/)).closest("[role=status]")).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
  });

  it("opens each file in its rendered view even after Raw was chosen for another", async () => {
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole("heading", { name: "Acme brief" });
    fireEvent.click(screen.getByRole("button", { name: "Raw" }));
    fireEvent.click(screen.getByRole("button", { name: /RESUME\.md/ }));

    expect(await screen.findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Rendered" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("says what is missing when there is neither a brief nor a scope file", async () => {
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([resume]);
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);

    const note = await screen.findByText(/No program brief/);
    expect(note.closest("[role=note]")?.textContent).toContain("no scope.json");
    expect(note.closest("[role=note]")?.textContent).not.toContain("agents work from scope.json");
  });
});

describe("Files rendered Markdown", () => {
  it("hides HTML comments in the rendered brief and keeps them in Raw", async () => {
    const text = "<!-- Fill in the program rules below. -->\n# Acme brief\n\nScope: acme.example\n\n```\n<!-- kept in code -->\n```\n";
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content(brief, text));
    render(<FilesTab engagementKey="acme" refreshVersion={0} />);
    const viewer = await screen.findByRole("article", { name: "ENGAGEMENT.md contents" });
    await within(viewer).findByRole("heading", { name: "Acme brief" });

    expect(viewer.textContent).not.toContain("Fill in the program rules below.");
    expect(viewer.textContent).toContain("<!-- kept in code -->");
    expect(within(viewer).getByText(/1 HTML comment hidden/)).toBeTruthy();
    fireEvent.click(within(viewer).getByRole("button", { name: "Raw" }));
    expect(viewer.querySelector("pre.files-raw")?.textContent).toBe(text);
  });
});
