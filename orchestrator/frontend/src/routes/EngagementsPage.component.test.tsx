// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deleteEngagement, getDashboardSummary, type Engagement } from "../lib/api";
import { EngagementsPage } from "./EngagementsPage";

vi.mock("../lib/api", () => ({
  deleteEngagement: vi.fn(),
  getDashboardSummary: vi.fn(),
}));

const engagement: Engagement = {
  id: 1,
  key: "demo",
  target: "https://target.test",
  status: "in_progress",
  engagement_root: "/tmp/demo",
  current_phase: "recon",
  exploit_policy: "pause",
  exploit_review_state: "not_requested",
  approved_targets: ["target.test"],
  created_at: "2026-09-12T00:00:00Z",
  updated_at: "2026-09-12T00:00:00Z",
  session_count: 1,
};

beforeEach(() => {
  vi.mocked(getDashboardSummary).mockRejectedValue(new Error("summary unavailable"));
  vi.mocked(deleteEngagement).mockResolvedValue({ deleted: true, key: "demo", id: 1 });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("EngagementsPage delete dialog", () => {
  it("keeps delete-key events out of card navigation and exposes a semantic open control", () => {
    const onOpenEngagement = vi.fn();
    render(
      <EngagementsPage
        engagements={[engagement]}
        onOpenEngagement={onOpenEngagement}
      />,
    );
    const opener = screen.getByRole("button", { name: "Delete engagement demo" });
    const openButton = screen.getByRole("button", { name: "Open engagement demo" });

    fireEvent.keyDown(opener, { key: "Enter" });
    expect(onOpenEngagement).not.toHaveBeenCalled();

    fireEvent.click(openButton);
    expect(onOpenEngagement).toHaveBeenCalledWith("demo");
  });

  it("traps focus, closes with Escape, and restores focus to its opener", async () => {
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    const opener = screen.getByRole("button", { name: "Delete engagement demo" });
    fireEvent.click(opener);

    const dialog = screen.getByRole("dialog", { name: "Delete engagement?" });
    const confirm = screen.getByRole("textbox", { name: /Type demo to confirm/ });
    await waitFor(() => expect(document.activeElement).toBe(confirm));

    const permanentDelete = screen.getByRole("button", { name: "Delete permanently" });
    permanentDelete.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(confirm);

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(dialog.isConnected).toBe(false);
  });

  it("cannot dismiss or reset the destructive dialog while deletion is in flight", async () => {
    let finishDelete!: () => void;
    vi.mocked(deleteEngagement).mockReturnValue(
      new Promise((resolve) => {
        finishDelete = () => resolve({ deleted: true, key: "demo", id: 1 });
      }),
    );
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Delete engagement demo" }));
    fireEvent.change(screen.getByRole("textbox", { name: /Type demo to confirm/ }), {
      target: { value: "demo" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    await waitFor(() => expect(deleteEngagement).toHaveBeenCalledTimes(1));

    const dialog = screen.getByRole("dialog", { name: "Delete engagement?" });
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByRole("dialog", { name: "Delete engagement?" })).toBe(dialog);
    fireEvent.click(dialog.parentElement as HTMLElement);
    expect(screen.getByRole("dialog", { name: "Delete engagement?" })).toBe(dialog);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("dialog", { name: "Delete engagement?" })).toBe(dialog);
    expect(screen.getByRole("button", { name: "Deleting..." })).toBeTruthy();

    finishDelete();
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Delete engagement?" })).toBeNull());
  });
});
