// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listActivityEntries, type ActivityEntry } from "../lib/api";
import { LogTab } from "./LogTab";

vi.mock("../lib/api", () => ({ listActivityEntries: vi.fn() }));

const entry = (id: number): ActivityEntry => ({
  id,
  engagement_id: 1,
  occurred_at: `2026-09-12T00:00:0${id}Z`,
  actor_kind: "operator",
  actor_name: "operator",
  title: `Entry ${id}`,
  action: "reviewed",
  result: "complete",
  artifact_ref: "",
  body_markdown: "",
  metadata: {},
  created_at: `2026-09-12T00:00:0${id}Z`,
  updated_at: `2026-09-12T00:00:0${id}Z`,
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("LogTab pagination", () => {
  it("loads the next bounded activity page without replacing earlier entries", async () => {
    vi.mocked(listActivityEntries)
      .mockResolvedValueOnce({ total: 2, items: [entry(2)] })
      .mockResolvedValueOnce({ total: 2, items: [entry(1)] });

    render(<LogTab engagementKey="demo" />);
    expect(await screen.findByText("Entry 2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load more activity" }));

    expect(await screen.findByText("Entry 1")).toBeTruthy();
    expect(screen.getByText("Entry 2")).toBeTruthy();
    await waitFor(() => {
      expect(listActivityEntries).toHaveBeenLastCalledWith(
        "demo",
        expect.objectContaining({ limit: 100, offset: 1 }),
      );
    });
  });
});
