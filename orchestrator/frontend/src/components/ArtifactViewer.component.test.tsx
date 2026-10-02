// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { ArtifactViewer } from "./ArtifactViewer";
import type { ArtifactContent } from "../lib/api";

afterEach(cleanup);
const artifact = { name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown", content: "# Notes\n\nAuthorization: Bearer full-token\n__init__.py > output\n" } satisfies ArtifactContent;

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
  expect(screen.getByRole("button", { name: "notes.md Available" })).toBeTruthy();
});

it("retains a different recorded relative path in the file list", () => {
  render(<ArtifactViewer artifacts={[{ name: "notes.md", relative_path: "reports/notes.md", exists: true, media_type: "text/markdown" }]} selectedName={null} selectedArtifact={null} onSelect={() => {}} />);
  expect(screen.getByText("reports/notes.md")).toBeTruthy();
});

it("does not show a different selected file while the requested one loads", () => {
  render(<ArtifactViewer artifacts={[]} selectedName="scope.json" selectedArtifact={artifact} onSelect={() => {}} />);
  expect(screen.queryByText("notes.md")).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("Loading scope.json");
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
