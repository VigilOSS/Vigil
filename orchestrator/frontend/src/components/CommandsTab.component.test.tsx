// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { listAssessmentCommandRuns } from "../lib/api";
import { CommandsTab } from "./CommandsTab";

vi.mock("../lib/api", () => ({
  getAssessmentCommandRun: vi.fn(),
  listAssessmentCommandRuns: vi.fn(),
}));

vi.mock("./CommandsGrid", () => ({
  default: ({ rows }: { rows: unknown[] }) => rows.length > 0
    ? <div>command grid</div>
    : <span>No command runs match.</span>,
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

beforeEach(() => {
  Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("CommandsTab live audit", () => {
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
    expect(notice.getAttribute("title")).not.toContain("to see older rows");
  });

  it("keeps the last loaded command rows visible when a background refresh fails", async () => {
    vi.mocked(listAssessmentCommandRuns)
      .mockResolvedValueOnce([{ id: 1, argv: [], command: "", timed_out: false, success: true }] as never)
      .mockRejectedValueOnce(new Error("command refresh unavailable"));

    render(<CommandsTab engagementKey="demo" />);
    expect(await screen.findByText("command grid")).toBeTruthy();
    fireEvent(document, new Event("visibilitychange"));

    expect((await screen.findByRole("alert")).textContent).toContain("command refresh unavailable");
    expect(screen.getByText("command grid")).toBeTruthy();
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
});
