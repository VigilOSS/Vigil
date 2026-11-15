// @vitest-environment jsdom
import type { ReactElement } from "react";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ToastProvider } from "../contexts/ToastContext";
import { FileList, FileRecord } from "./ArtifactViewer";
import type { FileSection, ViewerContent } from "./ArtifactViewer";

afterEach(cleanup);
const artifact = { name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown", content: "# Notes\n\nAuthorization: Bearer full-token\n__init__.py > output\n" } satisfies ViewerContent;

const withToasts = (node: ReactElement) => <ToastProvider>{node}</ToastProvider>;
type RecordProps = Parameters<typeof FileRecord>[0];
const record = (props: Partial<RecordProps> & Pick<RecordProps, "name">) => withToasts(
  <FileRecord file={null} content={null} section="rendered" onSectionChange={() => {}} titleId="file-title" {...props} />,
);

it("makes the exact file bytes reachable beside the rendered view", () => {
  const onSectionChange = vi.fn<(next: FileSection) => void>();
  const view = render(record({ name: "notes.md", content: artifact, onSectionChange }));
  fireEvent.click(screen.getByRole("button", { name: "Raw" }));
  expect(onSectionChange).toHaveBeenCalledWith("raw");
  view.rerender(record({ name: "notes.md", content: artifact, section: "raw" }));
  expect(view.container.querySelector("pre")?.textContent).toBe(artifact.content);
  expect(screen.getByRole("button", { name: "Raw" }).getAttribute("aria-current")).toBe("page");
});

it("preserves empty Markdown table cells without shifting evidence into another column", () => {
  const table = { ...artifact, content: "| Account | Token | Result |\n| --- | --- | --- |\n| alice | | retained |\n" };
  const view = render(record({ name: "notes.md", content: table }));
  const cells = Array.from(view.container.querySelectorAll("tbody td"), cell => cell.textContent);
  expect(cells).toEqual(["alice", "", "retained"]);
});

it("does not repeat the file name as redundant path metadata in the file list", () => {
  render(<FileList files={[{ name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown" }]} onOpen={() => {}} />);
  expect(screen.getByRole("button", { name: "notes.md" })).toBeTruthy();
});

it("retains a different recorded relative path in the file list and in the record, where it is what Copy copies", () => {
  const stored = { name: "notes.md", relative_path: "reports/notes.md", exists: true, media_type: "text/markdown" };
  const view = render(<FileList files={[stored]} onOpen={() => {}} />);
  expect(screen.getByText("reports/notes.md")).toBeTruthy();
  view.unmount();
  render(record({ name: "notes.md", file: stored, content: { ...artifact, relative_path: "reports/notes.md" } }));
  expect(screen.getByText("reports/notes.md")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Copy path" })).toBeTruthy();
});

it("hands the row that was used to the opener, so the record can return focus to it", () => {
  const onOpen = vi.fn<(name: string, invoker: HTMLElement) => void>();
  render(<FileList files={[{ name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown" }]} onOpen={onOpen} />);
  const row = screen.getByRole("button", { name: "notes.md" });
  fireEvent.click(row);
  expect(onOpen).toHaveBeenCalledWith("notes.md", row);
  expect(row.getAttribute("data-record-key")).toBe("notes.md");
});

it("shows the requested file's loading shape, not a different file, and says when it is slow", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    render(record({ name: "scope.json", content: artifact }));
    expect(screen.getByRole("status", { name: "Loading scope.json" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "scope.json" })).toBeTruthy();
    expect(screen.getByRole("article", { name: "scope.json contents" }).getAttribute("aria-busy")).toBe("true");
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    expect(screen.getByText("Still loading scope.json…")).toBeTruthy();
  } finally {
    vi.useRealTimers();
  }
});

it("puts a rendered document's headings under the record's title: they start at level 3", () => {
  const brief = {
    ...artifact,
    name: "ENGAGEMENT.md",
    relative_path: "ENGAGEMENT.md",
    content: "# Acme brief\n\n## Rules\n\n###### Deepest\n\nScope\n=====\n\nTargets\n-------\n\n```\n# a comment in code\n```\n",
  } satisfies ViewerContent;
  const view = render(record({ name: "ENGAGEMENT.md", content: brief }));
  expect(screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent)).toEqual(["ENGAGEMENT.md"]);
  const document = screen.getByRole("article", { name: "ENGAGEMENT.md contents" });
  expect(within(document).getAllByRole("heading").map((heading) => [heading.textContent, heading.tagName])).toEqual([
    ["Acme brief", "H3"],
    ["Rules", "H4"],
    ["Deepest", "H6"],
    ["Scope", "H3"],
    ["Targets", "H4"],
  ]);
  expect(within(document).getByText("# a comment in code")).toBeTruthy();
  // Raw keeps the exact bytes.
  view.rerender(record({ name: "ENGAGEMENT.md", content: brief, section: "raw" }));
  expect(view.container.querySelector("pre")?.textContent).toBe(brief.content);
});

it("flags an unfilled template with the shared status pill", () => {
  render(
    <FileList
      files={[
        { name: "ENGAGEMENT.md", relative_path: "ENGAGEMENT.md", exists: true, media_type: "text/markdown", is_stub: true, stub_waiver: "" },
        { name: "RULES.md", relative_path: "RULES.md", exists: true, media_type: "text/markdown", is_stub: true, stub_waiver: "No separate Acme brief." },
      ]}
      onOpen={() => {}}
    />,
  );
  expect(screen.getByText("Unfilled template").closest(".ui-status")?.getAttribute("data-tone")).toBe("warning");
  expect(screen.getByText("Template · waived").closest(".ui-status")?.getAttribute("data-tone")).toBe("neutral");
});

it("offers Try again when the file list cannot be read", () => {
  const onRetry = vi.fn();
  render(<FileList files={[]} error="list denied" onRetry={onRetry} onOpen={() => {}} />);
  expect(screen.getByRole("alert").textContent).toContain("File list unavailable: list denied");
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

it("describes an unavailable file without an endless loading state, and offers to read it again", () => {
  const onRetry = vi.fn();
  render(record({ name: "scope.json", content: artifact, loadError: "read denied", onRetry }));
  expect(screen.getByRole("alert").textContent).toContain("scope.json unavailable: read denied");
  expect(screen.queryByRole("status")).toBeNull();
  expect(screen.queryByText("notes.md")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

it("preserves the file's last successful bytes with a stale refresh notice", () => {
  const view = render(record({ name: "notes.md", content: artifact, loadError: "refresh unavailable", section: "raw" }));
  expect(screen.getByRole("alert").textContent).toContain("Showing last available content");
  expect(view.container.querySelector("pre")?.textContent).toBe(artifact.content);
});

it("offers only the Raw section for a file with no rendered view", () => {
  const log = { name: "run.log", relative_path: "run.log", exists: true, media_type: "text/plain", content: "GET /login 200\n" } satisfies ViewerContent;
  const view = render(record({ name: "run.log", content: log }));
  expect(screen.queryByRole("button", { name: "Rendered" })).toBeNull();
  expect(screen.getByRole("button", { name: "Raw" }).getAttribute("aria-current")).toBe("page");
  expect(view.container.querySelector("pre.files-raw")?.textContent).toBe(log.content);
});
