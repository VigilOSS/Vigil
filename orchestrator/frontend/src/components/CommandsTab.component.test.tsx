// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getAssessmentCommandRun, listAssessmentCommandRuns } from "../lib/api";
import { CommandsTab } from "./CommandsTab";

vi.mock("../lib/api", () => ({
  getAssessmentCommandRun: vi.fn(),
  listAssessmentCommandRuns: vi.fn(),
}));

vi.mock("./CommandsGrid", () => ({
  default: ({ rows, onRowOpen }: {
    rows: Array<{ id: number; statusLabel: string; target: string; targetSource: string }>;
    onRowOpen: (id: number, invoker: HTMLElement) => void;
  }) => rows.length > 0
    ? <div>{rows.map((row) => (
        <button key={row.id} type="button" onClick={(event) => onRowOpen(row.id, event.currentTarget)}>
          command grid {row.id} {row.statusLabel} {row.target} {row.targetSource}
        </button>
      ))}</div>
    : <span>No command runs match.</span>,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

beforeEach(() => {
  Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
  vi.mocked(getAssessmentCommandRun).mockResolvedValue({ id: 11, finding_slug: null, stdout_preview: "", stderr_preview: "" } as never);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("CommandsTab live audit", () => {
  it("contains command-palette focus and restores its opener on Escape", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{ id: 11, tool_bin: "curl", status: "failed", argv: ["curl"], command: "curl stored-command", success: false, timed_out: false }] as never);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /command grid 11/ });
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    screen.getByPlaceholderText(/Search command \/ argv/).focus();
    expect(document.querySelector(".cmd-box")?.contains(document.activeElement)).toBe(true);
    const dialog = screen.getByRole("dialog", { name: "Jump to command" });
    const input = within(dialog).getByRole("textbox", { name: "Search commands to jump to" });
    expect(document.body.classList.contains("detail-modal-open")).toBe(true);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: /curl stored-command/ }));
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(input);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Jump to command" })).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
  });
  it("opens the arrow-selected command from the keyboard palette", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{ id: 11, tool_bin: "curl", status: "failed", argv: [], command: "stored curl", success: false, timed_out: false }, { id: 12, tool_bin: "node", status: "failed", argv: [], command: "stored node", success: false, timed_out: false }] as never);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /command grid 11/ });
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    const input = screen.getByPlaceholderText(/Jump to command ·/);
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("heading", { name: "node" })).toBeTruthy();
    expect(document.querySelector(".cmd-overlay")).toBeNull();
  });
  it("leaves an empty filtered ledger alone when next/previous shortcuts are pressed", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([]);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByText("No command runs match.");
    const errors: string[] = [];
    const record = (event: ErrorEvent) => { errors.push(event.message); event.preventDefault(); };
    window.addEventListener("error", record);
    try { for (const key of ["j", "k", "[", "]"]) fireEvent.keyDown(window, { key }); }
    finally { window.removeEventListener("error", record); }
    expect(errors).toEqual([]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("does not move the record while a detail control handles a native key", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{ id: 11, status: "failed", tool_bin: "first", argv: ["first"], command: "first", success: false, timed_out: false }, { id: 12, status: "failed", tool_bin: "second", argv: ["second"], command: "second", success: false, timed_out: false }] as never);
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /command grid 11/i }));
    const heading = screen.getByRole("dialog").querySelector("h2")!.textContent;
    fireEvent.keyDown(screen.getByRole("button", { name: /close detail/i }), { key: "k" });
    expect(screen.getByRole("dialog").querySelector("h2")!.textContent).toBe(heading);
  });
  it("links a recorded finding association using the canonical slug from command detail", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{ id: 11, status: "failed", argv: [], command: "recorded command", success: false, timed_out: false, finding_id: 74 }] as never);
    vi.mocked(getAssessmentCommandRun).mockResolvedValue({ id: 11, finding_slug: "VA-012", stdout_preview: "", stderr_preview: "" } as never);
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /command grid 11/i }));
    expect((await screen.findByRole("link", { name: "VA-012" })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=findings&finding=VA-012");
    expect(screen.getByText("74")).toBeTruthy();
    expect(getAssessmentCommandRun).toHaveBeenCalledWith("demo", 11);
  });

  it("keeps a numeric association visible without inventing a finding route when its detail lookup fails", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{ id: 11, status: "failed", argv: [], command: "recorded command", success: false, timed_out: false, finding_id: 74 }] as never);
    vi.mocked(getAssessmentCommandRun).mockRejectedValue(new Error("command detail unavailable"));
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /command grid 11/i }));
    expect((await screen.findByRole("alert")).textContent).toContain("command detail unavailable");
    expect(screen.getByText("74")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /74/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Retry command detail" })).toBeTruthy();
  });

  it("does not render the grid's no-match overlay when the initial ledger request fails", async () => {
    vi.mocked(listAssessmentCommandRuns).mockRejectedValue(new Error("command ledger unavailable"));

    render(<CommandsTab engagementKey="demo" />);

    expect((await screen.findByRole("alert")).textContent).toContain("command ledger unavailable");
    expect(screen.queryByText("No command runs match.")).toBeNull();
  });

  it("describes an exact fetch-limit response as potentially incomplete without promising filters fetch hidden rows", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue(
      Array.from({ length: 1000 }, (_, index) => ({
        id: index + 1,
        argv: [],
        command: "",
        timed_out: false,
        success: true,
      })) as never,
    );

    render(<CommandsTab engagementKey="demo" />);

    const notice = await screen.findByText(/command limit reached — results may be incomplete/i);
    expect(notice.getAttribute("title")).toContain("Filters only narrow this loaded snapshot");
  });

  it("keeps the last loaded command rows visible when a background refresh fails", async () => {
    vi.mocked(listAssessmentCommandRuns)
      .mockResolvedValueOnce([{ id: 1, status: "failed", argv: [], command: "", timed_out: false, success: false }] as never)
      .mockRejectedValueOnce(new Error("command refresh unavailable"));

    render(<CommandsTab engagementKey="demo" />);
    expect(await screen.findByText(/command grid/)).toBeTruthy();
    fireEvent(document, new Event("visibilitychange"));

    expect((await screen.findByRole("alert")).textContent).toContain("command refresh unavailable");
    expect(screen.getByText(/command grid/)).toBeTruthy();
  });

  it("queues a visibility refresh that arrives during the initial load", async () => {
    const first = deferred<never[]>();
    vi.mocked(listAssessmentCommandRuns)
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce([]);

    render(<CommandsTab engagementKey="demo" />);
    await waitFor(() => expect(listAssessmentCommandRuns).toHaveBeenCalledTimes(1));
    fireEvent(document, new Event("visibilitychange"));
    first.resolve([]);

    await waitFor(() => expect(listAssessmentCommandRuns).toHaveBeenCalledTimes(2));
  });

  it.each(["pending", "warning"])(
    "shows captured stdout with a clear %s integrity warning",
    async (integrity) => {
      vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{
        id: 41,
        run_uuid: "run-41",
        status: "failed",
        argv: ["printf", "operator-evidence"],
        command: "printf operator-evidence",
        tool_name: "printf",
        timed_out: false,
        success: false,
        stdout_bytes: 17,
        stderr_bytes: 0,
        stdout_preview_chars: 17,
        stderr_preview_chars: 0,
        output_retention_status: "retained",
        output_integrity_status: integrity,
        output_integrity_warning: "Capture has not completed its integrity check.",
      }] as never);
      vi.mocked(getAssessmentCommandRun).mockResolvedValue({
        id: 41,
        stdout_preview: "operator-evidence",
        stderr_preview: "",
      } as never);

      render(<CommandsTab engagementKey="demo" />);
      fireEvent.click(await screen.findByRole("button", { name: /command grid/ }));
      fireEvent.click(await screen.findByRole("button", { name: /stdout/i }));

      expect(await screen.findByText("operator-evidence")).toBeTruthy();
      expect(screen.getByText(`Output integrity is ${integrity}`)).toBeTruthy();
      expect(screen.getByText(/captured output is shown below/i)).toBeTruthy();
    },
  );

  it("defaults to needs-attention while retaining the all-runs ledger and durable lifecycle status", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([
      {
        id: 1,
        status: "completed",
        success: true,
        timed_out: false,
        output_retention_status: "retained",
        output_integrity_status: "verified",
        argv: [],
        command: "curl https://clean.test",
      },
      {
        id: 2,
        status: "lost",
        success: false,
        timed_out: false,
        output_retention_status: "retained",
        output_integrity_status: "verified",
        argv: [],
        command: "curl https://lost.test",
      },
    ] as never);

    render(<CommandsTab engagementKey="demo" />);

    expect(await screen.findByRole("button", { name: /command grid 2 lost/i })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /command grid 1 completed/i })).toBeNull();
    expect(screen.getByRole("button", { name: /needs attention/i }).getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: /^all/i }));
    expect(await screen.findByRole("button", { name: /command grid 1 completed/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^all/i }).getAttribute("aria-pressed")).toBe("true");
  });

  it("uses stored attribution and labels command-derived targets as inferred", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([
      {
        id: 11,
        run_uuid: "stored",
        status: "failed",
        success: false,
        timed_out: false,
        output_retention_status: "retained",
        output_integrity_status: "verified",
        argv: [],
        command: "curl https://wrong.example/path",
        target_host: "stored.example",
        auth_context: "admin-session",
        scope_version: "sha256:scope-v3",
        finding_id: 74,
        partial_results: true,
        superseded_by_id: 12,
      },
      {
        id: 12,
        status: "failed",
        success: false,
        timed_out: false,
        output_retention_status: "retained",
        output_integrity_status: "verified",
        argv: [],
        command: "curl https://inferred.example/path",
      },
    ] as never);

    render(<CommandsTab engagementKey="demo" />);

    expect(await screen.findByRole("button", { name: /stored\.example stored/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /inferred\.example inferred/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /command grid 11/i }));
    expect(screen.getByText("admin-session")).toBeTruthy();
    expect(screen.getByText("sha256:scope-v3")).toBeTruthy();
    expect(screen.getByText("74")).toBeTruthy();
    expect(screen.getByText("partial")).toBeTruthy();
    expect(screen.getByText("Superseded by run 12")).toBeTruthy();
  });

  it("labels loaded previews and full-output artifact references honestly", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{
      id: 21,
      run_uuid: "artifact-run",
      status: "failed",
      success: false,
      timed_out: false,
      output_retention_status: "artifact",
      output_integrity_status: "verified",
      stdout_bytes: 99999,
      stdout_preview_chars: 12,
      stdout_artifact_ref: "scans/command-runs/21/stdout.log",
      argv: [],
      command: "tool --large-output",
    }] as never);
    vi.mocked(getAssessmentCommandRun).mockResolvedValue({
      id: 21,
      stdout_preview: "first 12 chars",
      stderr_preview: "",
    } as never);

    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /command grid 21/i }));
    fireEvent.click(screen.getByRole("button", { name: /stdout preview/i }));

    expect(await screen.findByText("Captured output preview")).toBeTruthy();
    expect(screen.getByText("Full output artifact")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy artifact reference" })).toBeTruthy();
  });

  it("gives search and filter controls accessible names and pressed state", async () => {
    vi.mocked(listAssessmentCommandRuns).mockResolvedValue([{
      id: 31,
      status: "failed",
      success: false,
      timed_out: false,
      output_retention_status: "retained",
      output_integrity_status: "verified",
      tool_bin: "curl",
      tool_name: "curl",
      argv: [],
      command: "curl example.test",
    }] as never);

    render(<CommandsTab engagementKey="demo" />);
    expect(await screen.findByRole("searchbox", { name: "Search command runs" })).toBeTruthy();
    const tool = screen.getByRole("button", { name: /filter by tool curl/i });
    expect(tool.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(tool);
    expect(tool.getAttribute("aria-pressed")).toBe("true");
  });
});
