// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { listActivityFeed, type ActivityCategory, type ActivityFeedPage, type ActivityItem } from "../lib/activityApi";
import { ActivityTab } from "./ActivityTab";

vi.mock("../lib/activityApi", () => ({ listActivityFeed: vi.fn() }));

const CATEGORIES: ActivityCategory[] = [
  { key: "decisions", label: "Decisions & handoffs", count: 4, default: true },
  { key: "findings", label: "Findings & chains", count: 2, default: true },
  { key: "notes", label: "Notes & other", count: 3, default: true },
  { key: "tools", label: "Tool calls", count: 120, default: false },
];

function row(id: number, at: string, overrides: Partial<ActivityItem> = {}): ActivityItem {
  return {
    id: `audit:${id}`,
    source: "audit",
    source_id: id,
    cursor: `cursor-${id}`,
    occurred_at: at,
    actor: { name: "recon-specialist", kind: "agent" },
    category: "notes",
    kind: `Note ${id}`,
    summary: `Note ${id} about the Acme portal`,
    entities: [],
    dispatch: null,
    detail: { actor_kind: "agent", action: "", result: "", body_markdown: "", metadata: {} },
    ...overrides,
  };
}

function page(items: ActivityItem[], hasMore = false, total = 9): ActivityFeedPage {
  return { items, has_more: hasMore, total, categories: CATEGORIES };
}

function summaryText() {
  return document.querySelector(".ui-results-summary")?.textContent;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/acme?tab=activity");
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("ActivityTab", () => {
  it("states its purpose, groups rows by day, and shows server category counts", async () => {
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(3, "2026-10-20T10:00:00Z"),
      row(2, "2026-10-13T08:00:00Z"),
    ]));

    render(<ActivityTab engagementKey="acme" />);

    expect(screen.getByRole("heading", { level: 1, name: "Activity" })).toBeTruthy();
    expect(screen.getByText(/Everything that happened in this engagement/)).toBeTruthy();
    expect(await screen.findByText("Note 3 about the Acme portal")).toBeTruthy();
    expect(screen.getByRole("heading", { name: /Tue 2026-10-13/ })).toBeTruthy();
    const tools = screen.getByRole("button", { name: /Tool calls/ });
    expect(tools.getAttribute("aria-pressed")).toBe("false");
    expect(within(tools).getByText("120")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Decisions & handoffs/ }).getAttribute("aria-pressed")).toBe("true");
    expect(summaryText()).toBe("2 of 9 entries loaded · Sorted by Time, newest first");
    expect(listActivityFeed).toHaveBeenCalledWith("acme", expect.objectContaining({ categories: undefined, limit: 100 }));
  });

  it("focuses the search with / from anywhere on the tab, like the other ledgers", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<ActivityTab engagementKey="acme" />);
    await screen.findByText("Note 1 about the Acme portal");
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).toBe(screen.getByRole("searchbox", { name: "Search activity" }));
  });

  it("filters categories on the server when a chip is toggled", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<ActivityTab engagementKey="acme" />);
    await screen.findByText("Note 1 about the Acme portal");

    fireEvent.click(screen.getByRole("button", { name: /Tool calls/ }));

    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith(
      "acme",
      expect.objectContaining({ categories: ["decisions", "findings", "notes", "tools"] }),
    ));
    expect(screen.getByRole("button", { name: /Tool calls/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("keeps loaded older pages across live refreshes and adds new rows on top", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")], false))
      .mockResolvedValueOnce(page([row(6, "2026-10-20T10:06:00Z")], false, 10));

    const { rerender } = render(<ActivityTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByText("Note 5 about the Acme portal");
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText("Note 3 about the Acme portal");
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-4" }));

    rerender(<ActivityTab engagementKey="acme" refreshVersion={1} />);

    const fresh = await screen.findByText("Note 6 about the Acme portal");
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-5" }));
    expect(fresh.closest("li")?.className).toContain("is-new");
    for (const id of [5, 4, 3]) expect(screen.getByText(`Note ${id} about the Acme portal`)).toBeTruthy();
    expect(summaryText()).toMatch(/^4 of 10 entries loaded/);
  });

  it("holds new rows behind a pill while the reader is scrolled down", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(2, "2026-10-20T10:02:00Z")]))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")]));
    const { rerender } = render(<ActivityTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByText("Note 2 about the Acme portal");

    const list = screen.getByRole("region", { name: "Activity entries" });
    list.scrollTop = 400;
    fireEvent.scroll(list);
    rerender(<ActivityTab engagementKey="acme" refreshVersion={1} />);

    const pill = await screen.findByRole("button", { name: "1 new entry — show" });
    expect(screen.queryByText("Note 3 about the Acme portal")).toBeNull();
    fireEvent.click(pill);
    expect(screen.getByText("Note 3 about the Acme portal")).toBeTruthy();
  });

  it("coalesces refresh bursts into one request in flight and one rerun", async () => {
    const first = deferred<ActivityFeedPage>();
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(1, "2026-10-20T10:01:00Z")]))
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")]));
    const { rerender } = render(<ActivityTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByText("Note 1 about the Acme portal");

    rerender(<ActivityTab engagementKey="acme" refreshVersion={1} />);
    rerender(<ActivityTab engagementKey="acme" refreshVersion={2} />);
    rerender(<ActivityTab engagementKey="acme" refreshVersion={3} />);
    expect(listActivityFeed).toHaveBeenCalledTimes(2);

    await act(async () => first.resolve(page([row(2, "2026-10-20T10:02:00Z")])));

    await screen.findByText("Note 3 about the Acme portal");
    expect(listActivityFeed).toHaveBeenCalledTimes(3);
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-2" }));
    expect(screen.getByText("Note 2 about the Acme portal")).toBeTruthy();
  });

  it("catches up once the first page lands when a refresh arrived while it loaded", async () => {
    const firstPage = deferred<ActivityFeedPage>();
    vi.mocked(listActivityFeed)
      .mockReturnValueOnce(firstPage.promise)
      .mockResolvedValueOnce(page([row(2, "2026-10-20T10:02:00Z")], false, 10));
    const { rerender } = render(<ActivityTab engagementKey="acme" refreshVersion={0} />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenCalledTimes(1));

    // A row is written after the first page was requested; its refresh signal
    // arrives before that page lands.
    rerender(<ActivityTab engagementKey="acme" refreshVersion={1} />);
    await act(async () => firstPage.resolve(page([row(1, "2026-10-20T10:01:00Z")])));

    expect(await screen.findByText("Note 2 about the Acme portal")).toBeTruthy();
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-1" }));
    expect(screen.getByText("Note 1 about the Acme portal")).toBeTruthy();
    expect(summaryText()).toMatch(/^2 of 10 entries loaded/);
  });

  it("clears the search from the box, like the other ledgers", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<ActivityTab engagementKey="acme" initialQuery="portal" />);
    await screen.findByText("Note 1 about the Acme portal");
    fireEvent.click(screen.getByRole("button", { name: "Clear activity search" }));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("");
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: undefined })));
  });

  it("links entities to their owning view and discloses the stored fields verbatim", async () => {
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(7, "2026-10-20T10:07:00Z", {
        category: "findings",
        kind: "finding-record",
        summary: "Recorded finding VA-001 (high, active)",
        actor: { name: "va-acme-01", kind: "agent" },
        entities: [{ type: "finding", key: "VA-001", label: "VA-001" }],
        detail: {
          actor_kind: "system",
          action: "finding=VA-001 severity=high",
          result: "active",
          body_markdown: "",
          metadata: { finding_slug: "VA-001", token: "Bearer acme-secret" },
          recorded_at: "2026-10-20T10:07:01Z",
        },
      }),
    ]));
    render(<ActivityTab engagementKey="acme" />);

    const link = await screen.findByRole("link", { name: "VA-001" });
    expect(link.getAttribute("href")).toBe("#/engagements/acme?tab=findings&finding=VA-001");

    const toggle = screen.getByRole("button", { name: /Recorded finding VA-001/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("finding=VA-001 severity=high")).toBeTruthy();
    expect(screen.getByText(/Bearer acme-secret/)).toBeTruthy();
    expect(document.querySelector('time[datetime="2026-10-20T10:07:01.000Z"]')).toBeTruthy();
  });

  it("starts from the filters the URL names and writes later changes back without adding history", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    const before = window.history.length;
    render(<ActivityTab engagementKey="acme" initialQuery="VA-001" initialCategories={["findings", "notes"]} initialActor="agent" initialRange="7d" />);
    await screen.findByText("Note 1 about the Acme portal");

    expect(listActivityFeed).toHaveBeenCalledWith("acme", expect.objectContaining({
      q: "VA-001",
      categories: ["findings", "notes"],
      actor: "agent",
      since: expect.any(String),
    }));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("VA-001");
    expect(screen.getByRole("button", { name: /^Agents/ }).getAttribute("aria-pressed")).toBe("true");
    expect(within(screen.getByRole("group", { name: "Time" })).getByRole("button", { name: "Last 7 days" }).getAttribute("aria-pressed")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: /^Operator/ }));
    await waitFor(() => expect(window.location.hash).toBe("#/engagements/acme?tab=activity&q=VA-001&cats=findings%2Cnotes&actor=operator&range=7d"));
    const search = screen.getByRole("searchbox", { name: "Search activity" });
    fireEvent.change(search, { target: { value: "va-acme-01 finished" } });
    // Enter sends the search at once instead of after the typing pause.
    fireEvent.keyDown(search, { key: "Enter" });
    await waitFor(() => expect(window.location.hash).toContain("q=va-acme-01+finished"));
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: "va-acme-01 finished" }));
    expect(window.history.length).toBe(before);
  });

  it("follows the URL when it changes, as browser Back does", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    const view = render(<ActivityTab engagementKey="acme" initialQuery="first" />);
    await screen.findByText("Note 1 about the Acme portal");
    view.rerender(<ActivityTab engagementKey="acme" initialQuery="second" />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: "second" })));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("second");
  });

  it("brings back loaded pages and open entries after leaving the tab and returning", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")], false));
    const first = render(<ActivityTab engagementKey="acme" initialQuery="acme" />);
    await screen.findByText("Note 5 about the Acme portal");
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    fireEvent.click(await screen.findByRole("button", { name: /Note 3 about the Acme portal/ }));
    expect(screen.getByRole("button", { name: /Note 3 about the Acme portal/ }).getAttribute("aria-expanded")).toBe("true");
    first.unmount();

    vi.mocked(listActivityFeed).mockClear();
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z"), row(3, "2026-10-20T10:03:00Z"),
    ], false));
    render(<ActivityTab engagementKey="acme" initialQuery="acme" />);

    const restored = await screen.findByRole("button", { name: /Note 3 about the Acme portal/ });
    expect(restored.getAttribute("aria-expanded")).toBe("true");
    expect(listActivityFeed).toHaveBeenCalledTimes(1);
    expect(listActivityFeed).toHaveBeenCalledWith("acme", expect.objectContaining({ q: "acme", limit: 100 }));
  });

  it("says why the last selected category stays on instead of ignoring the click", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<ActivityTab engagementKey="acme" initialCategories={["notes"]} />);
    await screen.findByText("Note 1 about the Acme portal");

    fireEvent.click(screen.getByRole("button", { name: /^Notes & other/ }));

    expect(screen.getByText(/At least one category stays selected/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /^Notes & other/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("explains, instead of linking, an entity no view can open", async () => {
    const reason = "Only engagement root documents open in Files; this registered file has no viewer.";
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(8, "2026-10-20T10:08:00Z", {
        category: "files",
        kind: "artifact register",
        summary: "Registered note file scans/acme.txt",
        entities: [
          { type: "file", key: "scans/acme.txt", label: "scans/acme.txt", ref: null, unlinked_reason: reason },
          { type: "surface", key: "https://app.example.com/login", label: "https://app.example.com/login", ref: { surface_id: 41 }, unlinked_reason: "" },
        ],
      }),
    ]));
    render(<ActivityTab engagementKey="acme" />);

    expect((await screen.findByRole("link", { name: /app\.example\.com\/login/ })).getAttribute("href"))
      .toBe("#/engagements/acme?tab=surfaces&surface=41");
    expect(screen.queryByRole("link", { name: /scans\/acme\.txt/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Registered note file/ }));
    expect(screen.getByText(reason)).toBeTruthy();
  });

  it("offers Clear filters when nothing matches, and the plain empty state otherwise", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([], false, 0));
    const view = render(<ActivityTab engagementKey="acme" initialQuery="nothing-here" />);
    expect(await screen.findByText("No activity matches these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: undefined })));
    view.unmount();

    render(<ActivityTab engagementKey="acme" />);
    expect(await screen.findByText("No activity recorded yet.")).toBeTruthy();
    expect(screen.queryByText("No activity matches these filters.")).toBeNull();
    expect((screen.getByRole("button", { name: "Clear filters" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
