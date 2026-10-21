// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ArtifactViewer } from "./ArtifactViewer";
import type { ViewerContent } from "./ArtifactViewer";

afterEach(cleanup);
const artifact = { name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown", content: "# Notes\n\nAuthorization: Bearer full-token\n__init__.py > output\n" } satisfies ViewerContent;

it("makes the exact file bytes reachable beside the rendered view", () => {
  const view = render(<ArtifactViewer artifacts={[]} selectedName="notes.md" selectedArtifact={artifact} onSelect={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Raw" }));
  expect(view.container.querySelector("pre")?.textContent).toBe(artifact.content);
  expect(screen.getByRole("button", { name: "Raw" }).getAttribute("aria-pressed")).toBe("true");
});

it("preserves empty Markdown table cells without shifting evidence into another column", () => {
  const table = { ...artifact, content: "| Account | Token | Result |\n| --- | --- | --- |\n| alice | | retained |\n" };
  const view = render(<ArtifactViewer artifacts={[]} selectedName="notes.md" selectedArtifact={table} onSelect={() => {}} />);
  const cells = Array.from(view.container.querySelectorAll("tbody td"), cell => cell.textContent);
  expect(cells).toEqual(["alice", "", "retained"]);
});

it("does not repeat the file name as redundant path metadata in the file list", () => {
  render(<ArtifactViewer artifacts={[{ name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown" }]} selectedName={null} selectedArtifact={null} onSelect={() => {}} />);
  expect(screen.getByRole("button", { name: "notes.md" })).toBeTruthy();
});

it("retains a different recorded relative path in the file list", () => {
  render(<ArtifactViewer artifacts={[{ name: "notes.md", relative_path: "reports/notes.md", exists: true, media_type: "text/markdown" }]} selectedName={null} selectedArtifact={null} onSelect={() => {}} />);
  expect(screen.getByText("reports/notes.md")).toBeTruthy();
});

it("shows the requested file's loading shape, not a different file, and says when it is slow", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    render(<ArtifactViewer artifacts={[]} selectedName="scope.json" selectedArtifact={artifact} onSelect={() => {}} />);
    expect(screen.getByRole("status", { name: "Loading scope.json" })).toBeTruthy();
    expect(within(screen.getByRole("article", { name: "scope.json contents" })).getByText("scope.json")).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    expect(screen.getByText("Still loading scope.json…")).toBeTruthy();
  } finally {
    vi.useRealTimers();
  }
});

it("keeps the page's one level-1 heading: a rendered document's headings start at level 2", () => {
  const brief = {
    ...artifact,
    name: "ENGAGEMENT.md",
    relative_path: "ENGAGEMENT.md",
    content: "# Acme brief\n\n## Rules\n\n###### Deepest\n\nScope\n=====\n\nTargets\n-------\n\n```\n# a comment in code\n```\n",
  } satisfies ViewerContent;
  const view = render(
    <ArtifactViewer artifacts={[{ name: "ENGAGEMENT.md", relative_path: "ENGAGEMENT.md", exists: true, media_type: "text/markdown" }]} selectedName="ENGAGEMENT.md" selectedArtifact={brief} onSelect={() => {}} />,
  );
  expect(screen.getAllByRole("heading", { level: 1 }).map((heading) => heading.textContent)).toEqual(["Files"]);
  const document = screen.getByRole("article", { name: "ENGAGEMENT.md contents" });
  expect(within(document).getAllByRole("heading").map((heading) => [heading.textContent, heading.tagName])).toEqual([
    ["Acme brief", "H2"],
    ["Rules", "H3"],
    ["Deepest", "H6"],
    ["Scope", "H2"],
    ["Targets", "H3"],
  ]);
  expect(within(document).getByText("# a comment in code")).toBeTruthy();
  // Raw keeps the exact bytes.
  fireEvent.click(screen.getByRole("button", { name: "Raw" }));
  expect(view.container.querySelector("pre")?.textContent).toBe(brief.content);
});

it("flags an unfilled template with the shared status pill", () => {
  render(
    <ArtifactViewer
      artifacts={[
        { name: "ENGAGEMENT.md", relative_path: "ENGAGEMENT.md", exists: true, media_type: "text/markdown", is_stub: true, stub_waiver: "" },
        { name: "RULES.md", relative_path: "RULES.md", exists: true, media_type: "text/markdown", is_stub: true, stub_waiver: "No separate Acme brief." },
      ]}
      selectedName={null}
      selectedArtifact={null}
      onSelect={() => {}}
    />,
  );
  expect(screen.getByText("Unfilled template").closest(".ui-status")?.getAttribute("data-tone")).toBe("warning");
  expect(screen.getByText("Template · waived").closest(".ui-status")?.getAttribute("data-tone")).toBe("neutral");
});

it("offers Try again when the file list cannot be read", () => {
  const onRetry = vi.fn();
  render(<ArtifactViewer artifacts={[]} selectedName={null} selectedArtifact={null} listError="list denied" onRetry={onRetry} onSelect={() => {}} />);
  expect(screen.getByRole("alert").textContent).toContain("File list unavailable: list denied");
  fireEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

it("describes an unavailable selected file without an endless loading state", () => {
  render(<ArtifactViewer artifacts={[]} selectedName="scope.json" selectedArtifact={artifact} loadError="read denied" onSelect={() => {}} />);
  expect(screen.getByRole("alert").textContent).toContain("scope.json unavailable: read denied");
  expect(screen.queryByRole("status")).toBeNull();
  expect(screen.queryByText("notes.md")).toBeNull();
});

it("preserves the selected file's last successful bytes with a stale refresh notice", () => {
  const view = render(<ArtifactViewer artifacts={[]} selectedName="notes.md" selectedArtifact={artifact} loadError="refresh unavailable" onSelect={() => {}} />);
  expect(screen.getByRole("alert").textContent).toContain("Showing last available content");
  fireEvent.click(screen.getByRole("button", { name: "Raw" }));
  expect(view.container.querySelector("pre")?.textContent).toBe(artifact.content);
});
