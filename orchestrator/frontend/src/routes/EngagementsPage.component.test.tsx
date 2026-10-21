// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
  target: "https://acme.example.com",
  status: "in_progress",
  engagement_root: "/tmp/demo",
  current_phase: "recon",
  exploit_policy: "pause",
  exploit_review_state: "not_requested",
  approved_targets: ["acme.example.com"],
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

// Delete lives behind each row's Actions menu; returns the menu button.
function openDeleteDialog(key = "demo") {
  const actions = screen.getByRole("button", { name: `Actions for engagement ${key}` });
  fireEvent.click(actions);
  fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: `Delete engagement ${key}` }));
  return actions;
}

describe("EngagementsPage ledger", () => {
  it("keeps delete out of the row until its Actions menu opens", () => {
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    expect(screen.queryByRole("menuitem", { name: "Delete engagement demo" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete engagement demo" })).toBeNull();
    const actions = screen.getByRole("button", { name: "Actions for engagement demo" });
    fireEvent.click(actions);
    expect(actions.getAttribute("aria-expanded")).toBe("true");
    const item = within(screen.getByRole("menu")).getByRole("menuitem", { name: "Delete engagement demo" });
    expect(document.activeElement).toBe(item);
    fireEvent.keyDown(item, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(actions);
  });

  it("states sessions only when the engagement has any", () => {
    render(<EngagementsPage engagements={[{ ...engagement, session_count: 0 }, { ...engagement, key: "two", session_count: 3 }]} onOpenEngagement={vi.fn()} />);
    expect(screen.queryByText(/0 sessions/)).toBeNull();
    expect(screen.getByText("3 sessions")).toBeTruthy();
  });

  it("names the engagements folder as code in the empty state", () => {
    render(<EngagementsPage engagements={[]} onOpenEngagement={vi.fn()} />);
    const empty = screen.getByText(/No engagements discovered under/);
    expect(empty.textContent).not.toContain("`");
    expect(within(empty).getByText("agent/engagements").tagName).toBe("CODE");
  });

  it("marks the sorted column and names the order shown", () => {
    render(<EngagementsPage engagements={[engagement, { ...engagement, key: "two", target: "https://beta.example.com" }]} onOpenEngagement={vi.fn()} />);
    const summary = () => screen.getByText(/Sorted by/).closest(".ui-results-summary")?.textContent;
    expect(screen.getByRole("columnheader", { name: "Updated" }).getAttribute("aria-sort")).toBe("descending");
    expect(summary()).toBe("2 of 2 engagements · Sorted by Updated, newest first");
    fireEvent.change(screen.getByRole("combobox", { name: "Sort" }), { target: { value: "target" } });
    expect(screen.getByRole("columnheader", { name: "Engagement" }).getAttribute("aria-sort")).toBe("ascending");
    expect(summary()).toBe("2 of 2 engagements · Sorted by Engagement, A to Z");
    fireEvent.change(screen.getByRole("combobox", { name: "Sort" }), { target: { value: "findings" } });
    expect(screen.getByRole("columnheader", { name: "Current findings" }).getAttribute("aria-sort")).toBe("descending");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search engagements" }), { target: { value: "beta" } });
    expect(summary()).toBe("1 of 2 engagements · Sorted by Current findings, highest first");
  });

  it("sorts by status urgency and shows every lifecycle as a styled status", () => {
    render(<EngagementsPage engagements={[
      { ...engagement, key: "a", target: "Archived target", status: "archived" },
      { ...engagement, key: "c", target: "Completed target", status: "completed" },
      { ...engagement, key: "p", target: "Active target", status: "in_progress" },
    ]} onOpenEngagement={vi.fn()} />);
    fireEvent.change(screen.getByRole("combobox", { name: "Sort" }), { target: { value: "status" } });
    const targets = screen.getAllByRole("button", { name: /^Open engagement/ }).map((button) => button.textContent);
    expect(targets).toEqual(["Active target", "Completed target", "Archived target"]);
    expect(screen.getByText("Archived").closest(".ui-status")?.getAttribute("data-tone")).toBe("neutral");
  });
});

describe("EngagementsPage delete dialog", () => {
  it("renders an engagement ledger with independent track phases", () => {
    render(<EngagementsPage engagements={[{ ...engagement, track_state: { web: { phase: "complete", complete: true }, code: { phase: "hunt", complete: false } }, aggregate_complete: false } as Engagement]} onOpenEngagement={vi.fn()} />);
    expect(screen.getByRole("table", { name: "Engagements" })).toBeTruthy();
    expect(screen.getByText("web: complete")).toBeTruthy();
    expect(screen.getByText("code: hunt")).toBeTruthy();
    expect(screen.queryByText("Phase: recon", { exact: false })).toBeNull();
  });
  it("keeps the complete ledger in a keyboard-focusable scroll region", () => {
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    const ledger = screen.getByRole("region", { name: "Engagement ledger" });
    expect(ledger.tabIndex).toBe(0);
    expect(ledger.contains(screen.getByRole("table", { name: "Engagements" }))).toBe(true);
    expect(screen.getAllByRole("columnheader")).toHaveLength(6);
  });
  it("names the filtered finding-count column and discloses its excluded statuses", () => {
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    expect(screen.getByRole("columnheader", { name: "Current findings" })).toBeTruthy();
    expect(screen.getByText("Current findings exclude merged and false-positive records.")).toBeTruthy();
  });
  it("keeps delete-key events out of card navigation and exposes a semantic open control", () => {
    const onOpenEngagement = vi.fn();
    render(
      <EngagementsPage
        engagements={[engagement]}
        onOpenEngagement={onOpenEngagement}
      />,
    );
    const opener = screen.getByRole("button", { name: "Actions for engagement demo" });
    const openButton = screen.getByRole("button", { name: "Open engagement demo" });

    fireEvent.keyDown(opener, { key: "Enter" });
    expect(onOpenEngagement).not.toHaveBeenCalled();

    fireEvent.click(openButton);
    expect(onOpenEngagement).toHaveBeenCalledWith("demo");
  });

  it("traps focus, closes with Escape, and restores focus to its opener", async () => {
    render(<EngagementsPage engagements={[engagement]} onOpenEngagement={vi.fn()} />);
    const opener = openDeleteDialog();

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
    openDeleteDialog();
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
