// @vitest-environment jsdom

import { StrictMode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import { listEngagementFiles, readEngagementFile, type EngagementFile, type EngagementFileContent } from "../lib/filesApi";
import { FilesTab } from "./FilesTab";

// The real Markdown renderer, counting how often a document is rendered.
const markdown = vi.hoisted(() => ({ renders: 0 }));
vi.mock("./Markdown", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./Markdown")>();
  return {
    ...actual,
    MarkdownBlock: (props: Parameters<typeof actual.MarkdownBlock>[0]) => {
      markdown.renders += 1;
      return <actual.MarkdownBlock {...props} />;
    },
  };
});

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

type TabProps = Parameters<typeof FilesTab>[0];
const tab = (props: Partial<TabProps> = {}) => (
  <ToastProvider><FilesTab engagementKey="acme" refreshVersion={0} {...props} /></ToastProvider>
);
const fileList = () => screen.getByRole("navigation", { name: "Engagement files" });
const row = (name: RegExp) => within(fileList()).getByRole("button", { name });
const record = () => screen.findByRole("region", { name: "File" });
/** The section the open file shows: the record's section button marked current. */
const section = () => within(screen.getByRole("group", { name: "File sections" })).getAllByRole("button").find((button) => button.getAttribute("aria-current") === "page")?.textContent;

describe("FilesTab", () => {
  it("lists the files grouped by role, the brief first, and opens none on the bare tab link", async () => {
    render(tab());

    const working = (await within(fileList()).findByRole("heading", { name: "Working documents" })).parentElement!;
    const snapshots = within(fileList()).getByRole("heading", { name: "Snapshots & config" }).parentElement!;
    expect(within(working).getAllByRole("button").map((button) => button.getAttribute("data-record-key"))).toEqual(["ENGAGEMENT.md", "RESUME.md"]);
    expect(within(snapshots).getByText("scope.json")).toBeTruthy();
    expect(within(snapshots).getByText("Export snapshot (DB is the source of truth)")).toBeTruthy();
    // A row says what the file is for, so the list can be read before anything is opened.
    expect(row(/ENGAGEMENT\.md/).textContent).toContain("ENGAGEMENT.md description");
    // Missing files sit behind a disclosure instead of as disabled rows.
    expect(within(fileList()).getByText("Not created yet (1)")).toBeTruthy();
    expect(within(working).queryByText("COMPACT.md")).toBeNull();
    // The list is the tab's first view: no file is read until one is opened.
    expect(screen.queryByRole("region", { name: "File" })).toBeNull();
    expect(readEngagementFile).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { level: 1, name: "Files" })).toBeTruthy();
  });

  it("opens a file from its row in the record view, and Back returns to the list with focus on that row", async () => {
    render(tab());
    const before = window.history.length;
    fireEvent.click(await within(fileList()).findByRole("button", { name: /RESUME\.md/ }));

    const view = await record();
    expect(await within(view).findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(within(view).getByRole("heading", { level: 2, name: "RESUME.md" })).toBeTruthy();
    expect(within(view).getByText("2 of 4 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts&file=RESUME.md");
    expect(window.history.length).toBe(before + 1);
    // The list stays mounted behind the record, out of the accessibility tree.
    expect(screen.queryByRole("navigation", { name: "Engagement files" })).toBeNull();

    fireEvent.click(within(view).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "File" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts");
    await waitFor(() => expect(document.activeElement).toBe(row(/RESUME\.md/)));
  });

  it("walks the files in the order the list shows them, across both groups, and Escape returns", async () => {
    render(tab({ initialFileName: "RESUME.md" }));
    const view = await record();
    await within(view).findByRole("heading", { name: "Resume" });

    fireEvent.click(within(view).getByRole("button", { name: "Next file" }));
    await within(view).findByRole("heading", { level: 2, name: "scope.json" });
    expect(within(view).getByText("3 of 4 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts&file=scope.json");
    fireEvent.keyDown(window, { key: "[" });
    fireEvent.keyDown(window, { key: "[" });
    await within(view).findByRole("heading", { level: 2, name: "ENGAGEMENT.md" });
    expect((within(view).getByRole("button", { name: "Previous file" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "File" })).toBeNull());
    // Returning lands on the file last shown, not the one first opened.
    await waitFor(() => expect(document.activeElement).toBe(row(/ENGAGEMENT\.md/)));
  });

  it("names the missing brief on the list when ENGAGEMENT.md is absent", async () => {
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([resume, scope]);
    render(tab());
    expect((await screen.findByRole("note")).textContent).toContain("No program brief");
    expect(readEngagementFile).not.toHaveBeenCalled();
  });

  it("shows size and modified time, and the exact bytes in the Raw section, which the address names", async () => {
    render(tab({ initialFileName: "ENGAGEMENT.md" }));
    const view = await record();
    const viewer = await within(view).findByRole("article", { name: "ENGAGEMENT.md contents" });
    await within(viewer).findByRole("heading", { name: "Acme brief" });

    expect(within(view).getByText("2.0 KB")).toBeTruthy();
    expect(within(view).getByText("2026-09-12 05:06:07 UTC")).toBeTruthy();
    expect(within(view).getByText("ENGAGEMENT.md role")).toBeTruthy();
    expect(within(view).getByText("ENGAGEMENT.md description")).toBeTruthy();
    expect(section()).toBe("Rendered");
    fireEvent.click(within(view).getByRole("button", { name: "Raw" }));
    expect(viewer.querySelector("pre")?.textContent).toBe(bodies["ENGAGEMENT.md"]);
    expect(section()).toBe("Raw");
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts&file=ENGAGEMENT.md&dtab=raw");
  });

  it("opens the Raw section a link names", async () => {
    render(tab({ initialFileName: "ENGAGEMENT.md", initialDrawerTab: "raw" }));
    const viewer = await screen.findByRole("article", { name: "ENGAGEMENT.md contents" });
    await waitFor(() => expect(viewer.querySelector("pre.files-raw")?.textContent).toBe(bodies["ENGAGEMENT.md"]));
    expect(section()).toBe("Raw");
  });

  it("renders JSON through the syntax-highlighted JSON view", async () => {
    render(tab({ initialFileName: "scope.json" }));

    const viewer = await screen.findByRole("article", { name: "scope.json contents" });
    await within(viewer).findByRole("button", { name: "Copy JSON to clipboard" });
    expect(viewer.querySelector(".json-tok-key")?.textContent).toBe("\"hostname\"");
  });

  it("flags an unfilled brief template and the operator's waiver, on the list and in the record", async () => {
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content({ ...brief, is_stub: true }, "> **STUB — fill this in\n"));
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([{ ...brief, is_stub: true }, scope]);
    render(tab());

    expect(await within(fileList()).findByText("Unfilled template")).toBeTruthy();
    fireEvent.click(row(/ENGAGEMENT\.md/));
    const view = await record();
    expect(within(view).getByText("Unfilled template")).toBeTruthy();
    expect((await within(view).findByText("Unfilled template.")).closest("[role=note]")?.textContent)
      .toContain("Target-facing commands are blocked");
    cleanup();

    const reason = "Operator confirmed the Acme lab has no separate brief.";
    const waived = { ...brief, is_stub: true, stub_waiver: reason };
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([waived, scope]);
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content(waived, "> **STUB — fill this in\n"));
    render(tab({ initialFileName: "ENGAGEMENT.md" }));
    expect(await within(await record()).findByText("Template · waived")).toBeTruthy();
    expect(await screen.findByText(reason)).toBeTruthy();
  });

  it("reads the list again from Try again after it failed", async () => {
    vi.mocked(listEngagementFiles).mockRejectedValueOnce(new Error("list denied"));
    render(tab());
    expect((await screen.findByRole("alert")).textContent).toContain("File list unavailable: list denied");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await within(fileList()).findByRole("button", { name: /ENGAGEMENT\.md/ })).toBeTruthy();
    expect(listEngagementFiles).toHaveBeenCalledTimes(2);
  });

  it("says when a large file was truncated by the view limit", async () => {
    vi.mocked(readEngagementFile).mockResolvedValueOnce(
      content({ ...brief, size_bytes: 3 * 1024 * 1024 }, "# Acme brief\n", { truncated: true, returned_bytes: 1024 * 1024 }),
    );
    render(tab({ initialFileName: "ENGAGEMENT.md" }));

    const notice = await screen.findByText(/Showing the first 1\.0 MB of 3\.0 MB/);
    expect(notice.closest("[role=note]")?.textContent).toContain("ENGAGEMENT.md");
  });

  it("loads the list once under StrictMode's repeated mount effect", async () => {
    render(<StrictMode>{tab()}</StrictMode>);
    await within(fileList()).findByRole("button", { name: /ENGAGEMENT\.md/ });

    expect(listEngagementFiles).toHaveBeenCalledTimes(1);
  });

  it("keeps the open file visible while refreshes coalesce into one follow-up read", async () => {
    const view = render(tab({ initialFileName: "ENGAGEMENT.md" }));
    await screen.findByRole("heading", { name: "Acme brief" });
    expect(readEngagementFile).toHaveBeenCalledTimes(1);

    const slow = deferred<EngagementFileContent>();
    vi.mocked(readEngagementFile).mockReturnValueOnce(slow.promise);
    view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: 1 }));
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledTimes(2));
    view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: 2 }));
    view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: 3 }));

    // Previous content stays on screen, marked busy, while the refresh runs.
    const viewer = screen.getByRole("article", { name: "ENGAGEMENT.md contents" });
    expect(viewer.getAttribute("aria-busy")).toBe("true");
    expect(within(viewer).getByRole("heading", { name: "Acme brief" })).toBeTruthy();

    slow.resolve(content(brief, "# Acme brief v2\n"));
    expect(await screen.findByRole("heading", { name: "Acme brief" })).toBeTruthy();
    await waitFor(() => expect(readEngagementFile).toHaveBeenCalledTimes(3));
    await waitFor(() => expect(viewer.getAttribute("aria-busy")).toBe("false"));
  });

  it("leaves the open document as rendered when a refresh reads the same content, and shows new content when it changes", async () => {
    const view = render(tab({ initialFileName: "ENGAGEMENT.md" }));
    await screen.findByRole("heading", { name: "Acme brief" });
    const viewer = screen.getByRole("article", { name: "ENGAGEMENT.md contents" });
    const rendered = markdown.renders;

    for (const version of [1, 2]) {
      view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: version }));
      await waitFor(() => expect(readEngagementFile).toHaveBeenCalledTimes(version + 1));
      await waitFor(() => expect(viewer.getAttribute("aria-busy")).toBe("false"));
    }
    expect(markdown.renders).toBe(rendered);

    vi.mocked(readEngagementFile).mockResolvedValueOnce(content(brief, "# Acme brief, revised\n"));
    view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: 3 }));
    expect(await screen.findByRole("heading", { name: "Acme brief, revised" })).toBeTruthy();
  });

  it("does not read a file again on refresh while only the list shows", async () => {
    const view = render(tab({ initialFileName: "ENGAGEMENT.md" }));
    fireEvent.click(within(await record()).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "File" })).toBeNull());
    const reads = vi.mocked(readEngagementFile).mock.calls.length;
    view.rerender(tab({ refreshVersion: 1 }));
    await waitFor(() => expect(listEngagementFiles).toHaveBeenCalledTimes(2));
    expect(readEngagementFile).toHaveBeenCalledTimes(reads);
  });

  it("shows a JSON file that does not parse as its exact text and offers no rendered view of it", async () => {
    const cut = "{\"hostname\":\"acme.exa";
    vi.mocked(readEngagementFile).mockImplementation(async (_key, name) => (name === "scope.json"
      ? content(scope, cut, { truncated: true, size_bytes: 4096 })
      : content(brief, bodies["ENGAGEMENT.md"])));
    render(tab({ initialFileName: "scope.json" }));
    const view = await record();
    const viewer = await within(view).findByRole("article", { name: "scope.json contents" });
    await waitFor(() => expect(viewer.querySelector("pre")?.textContent).toBe(cut));
    // Nothing claims a rendered view is on screen, and a note says why there is none.
    expect(within(view).queryByRole("button", { name: "Rendered" })).toBeNull();
    expect(section()).toBe("Raw");
    expect(within(view).getAllByRole("note").some((note) => /JSON/.test(note.textContent ?? ""))).toBe(true);
  });

  it("keeps the last content with a stale notice when a refresh read fails", async () => {
    const view = render(tab({ initialFileName: "ENGAGEMENT.md" }));
    await screen.findByRole("heading", { name: "Acme brief" });

    vi.mocked(readEngagementFile).mockRejectedValueOnce(new Error("read denied"));
    view.rerender(tab({ initialFileName: "ENGAGEMENT.md", refreshVersion: 1 }));

    expect((await screen.findByRole("alert")).textContent).toContain("Showing last available content for ENGAGEMENT.md");
    expect(screen.getByRole("heading", { name: "Acme brief" })).toBeTruthy();
  });

  it("offers Try again inside the record when the file cannot be read", async () => {
    vi.mocked(readEngagementFile).mockRejectedValueOnce(new Error("read denied"));
    render(tab({ initialFileName: "RESUME.md" }));
    const view = await record();
    expect((await within(view).findByRole("alert")).textContent).toContain("RESUME.md unavailable: read denied");
    fireEvent.click(within(view).getByRole("button", { name: "Try again" }));
    expect(await within(view).findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(within(view).queryByRole("alert")).toBeNull();
  });

  it("returns to the list, saying why, when the open file disappears", async () => {
    const view = render(tab({ initialFileName: "RESUME.md" }));
    await screen.findByRole("heading", { name: "Resume" });

    vi.mocked(listEngagementFiles).mockResolvedValueOnce([brief, scope]);
    view.rerender(tab({ initialFileName: "RESUME.md", refreshVersion: 1 }));

    expect((await screen.findByText(/RESUME\.md is not one of this engagement's files/)).closest("[role=status]")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "File" })).toBeNull();
    expect(row(/ENGAGEMENT\.md/)).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts");
  });

  it("ignores a late read failure for a file that is no longer open", async () => {
    let rejectOld!: (error: Error) => void;
    vi.mocked(readEngagementFile).mockImplementation(async (_key, name) => name === "ENGAGEMENT.md"
      ? new Promise((_resolve, reject) => { rejectOld = reject; })
      : content(scope, bodies["scope.json"]));
    render(tab({ initialFileName: "ENGAGEMENT.md" }));
    const view = await record();
    await within(view).findByRole("status", { name: "Loading ENGAGEMENT.md" });

    // ENGAGEMENT.md, RESUME.md, scope.json: two steps on.
    fireEvent.click(within(view).getByRole("button", { name: "Next file" }));
    fireEvent.click(within(view).getByRole("button", { name: "Next file" }));
    const viewer = await within(view).findByRole("article", { name: "scope.json contents" });
    await within(viewer).findAllByText("\"acme.example\"");
    rejectOld(new Error("old file failure"));
    await Promise.resolve();

    expect(screen.queryByText(/old file failure/)).toBeNull();
    expect(within(viewer).getAllByText("\"acme.example\"")).toHaveLength(2);
  });

  it("opens the file the URL names without reading any other", async () => {
    render(tab({ initialFileName: "RESUME.md" }));

    expect(await screen.findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(readEngagementFile).toHaveBeenCalledTimes(1);
    expect(readEngagementFile).toHaveBeenCalledWith("acme", "RESUME.md");
  });

  it("follows the URL to another file and back to the list, as browser Back does", async () => {
    const view = render(tab({ initialFileName: "RESUME.md" }));
    await screen.findByRole("heading", { name: "Resume" });
    view.rerender(tab({ initialFileName: "scope.json" }));
    expect(await screen.findByRole("article", { name: "scope.json contents" })).toBeTruthy();
    view.rerender(tab({ initialFileName: undefined }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "File" })).toBeNull());
    expect(row(/RESUME\.md/)).toBeTruthy();
  });

  it("says when the file the URL names is not one of the engagement's files, and shows the list", async () => {
    window.history.replaceState(null, "", "#/engagements/acme?tab=artifacts&file=PLAN.md");
    render(tab({ initialFileName: "PLAN.md" }));

    const notice = (await screen.findByText(/PLAN\.md is not one of this engagement's files/)).closest("[role=status]")!;
    expect(notice.textContent).toContain("The file list is shown");
    expect(screen.queryByRole("region", { name: "File" })).toBeNull();
    expect(row(/ENGAGEMENT\.md/)).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts");
  });

  it("says a listed file has not been created yet when the URL names it", async () => {
    render(tab({ initialFileName: "COMPACT.md" }));
    expect((await screen.findByText(/COMPACT\.md has not been created yet/)).closest("[role=status]")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "File" })).toBeNull();
  });

  it("opens each file in its rendered view even after Raw was chosen for another", async () => {
    render(tab({ initialFileName: "ENGAGEMENT.md" }));
    const view = await record();
    await within(view).findByRole("heading", { name: "Acme brief" });
    fireEvent.click(within(view).getByRole("button", { name: "Raw" }));
    fireEvent.click(within(view).getByRole("button", { name: "Next file" }));

    expect(await within(view).findByRole("heading", { name: "Resume" })).toBeTruthy();
    expect(section()).toBe("Rendered");
    expect(window.location.hash).toBe("#/engagements/acme?tab=artifacts&file=RESUME.md");
  });

  it("says what is missing when there is neither a brief nor a scope file", async () => {
    vi.mocked(listEngagementFiles).mockResolvedValueOnce([resume]);
    render(tab());

    const note = await screen.findByText(/No program brief/);
    expect(note.closest("[role=note]")?.textContent).toContain("no scope.json");
    expect(note.closest("[role=note]")?.textContent).not.toContain("agents work from scope.json");
  });
});

describe("Files rendered Markdown", () => {
  it("hides HTML comments in the rendered brief and keeps them in Raw", async () => {
    const text = "<!-- Fill in the program rules below. -->\n# Acme brief\n\nScope: acme.example\n\n```\n<!-- kept in code -->\n```\n";
    vi.mocked(readEngagementFile).mockResolvedValueOnce(content(brief, text));
    render(tab({ initialFileName: "ENGAGEMENT.md" }));
    const view = await record();
    const viewer = await within(view).findByRole("article", { name: "ENGAGEMENT.md contents" });
    await within(viewer).findByRole("heading", { name: "Acme brief" });

    expect(viewer.textContent).not.toContain("Fill in the program rules below.");
    expect(viewer.textContent).toContain("<!-- kept in code -->");
    expect(within(viewer).getByText(/1 HTML comment hidden/)).toBeTruthy();
    fireEvent.click(within(view).getByRole("button", { name: "Raw" }));
    expect(viewer.querySelector("pre.files-raw")?.textContent).toBe(text);
  });
});
