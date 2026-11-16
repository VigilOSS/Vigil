// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import { getActivityEntry, listActivityFeed, type ActivityCategory, type ActivityFeedPage, type ActivityItem } from "../lib/activityApi";
import { ApiError } from "../lib/api";
import { ActivityTab } from "./ActivityTab";

vi.mock("../lib/activityApi", () => ({ listActivityFeed: vi.fn(), getActivityEntry: vi.fn() }));

type TabProps = Parameters<typeof ActivityTab>[0];
function Tab(props: Partial<TabProps>) {
  return <ToastProvider><ActivityTab engagementKey="acme" {...props} /></ToastProvider>;
}

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
    order: [Date.parse(at) || 0, 1, id],
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

/** A feed page; its catch-up cursor defaults to its newest row's, as the backend's is without late rows. */
function page(items: ActivityItem[], hasMore = false, total = 9, catchUp = items[0]?.cursor ?? null): ActivityFeedPage {
  return { items, has_more: hasMore, catch_up_cursor: catchUp, total, categories: CATEGORIES };
}

function summaryText() {
  return document.querySelector(".ui-results-summary")?.textContent;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const note = (id: number) => `Note ${id} about the Acme portal`;
/** The note rows the list shows, by id, in shown order. */
const shownNotes = () => within(entries()).getAllByText(/^Note \d+ about the Acme portal$/).map((element) => Number(element.textContent?.split(" ")[1]));
const entries = () => screen.getByRole("region", { name: "Activity entries" });
/** A row of the list: the button that opens the entry's record. */
const entryRow = (name: RegExp | string) => within(entries()).getByRole("button", { name });
const record = () => screen.findByRole("region", { name: "Activity entry" });
const noRecord = () => waitFor(() => expect(screen.queryByRole("region", { name: "Activity entry" })).toBeNull());
/** The section the open entry shows: the record's section button marked current. */
const section = () => within(screen.getByRole("group", { name: "Entry sections" })).getAllByRole("button").find((button) => button.getAttribute("aria-current") === "page")?.textContent;

/** Two rows of one dispatch (the feed shows them as a card) around a plain note. */
function dispatchRows(): ActivityItem[] {
  const dispatch = { agent_id: "va-acme-01", role: "vulnerability-analyst", run_id: 7 };
  return [
    row(9, "2026-10-20T10:09:00Z", { kind: "agent done", summary: "va-acme-01 finished (completed)", dispatch, detail: { result: "completed" } }),
    row(8, "2026-10-20T10:08:00Z"),
    row(7, "2026-10-20T10:07:00Z", { kind: "agent start", summary: "Started va-acme-01", dispatch }),
  ];
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

    render(<Tab />);

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
    render(<Tab />);
    await screen.findByText("Note 1 about the Acme portal");
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).toBe(screen.getByRole("searchbox", { name: "Search activity" }));
  });

  it("filters categories on the server when a chip is toggled", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<Tab />);
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

    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText("Note 5 about the Acme portal");
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText("Note 3 about the Acme portal");
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-4" }));

    rerender(<Tab refreshVersion={1} />);

    const fresh = await screen.findByText("Note 6 about the Acme portal");
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-5" }));
    expect(fresh.closest("li")?.className).toContain("is-new");
    for (const id of [5, 4, 3]) expect(screen.getByText(`Note ${id} about the Acme portal`)).toBeTruthy();
    expect(summaryText()).toMatch(/^4 of 10 entries loaded/);
  });

  it("lists a row recorded before the loaded rows once, in place, while Load older keeps paging from the oldest row", async () => {
    // A late row's cursor (the backend's) pages from its own place; here it is a stand-in.
    const late = row(9, "2026-10-20T10:00:00Z", { cursor: "cursor-late" });
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockResolvedValueOnce(page([late]))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z"), late, row(2, "2026-10-20T09:59:00Z")], true))
      .mockResolvedValueOnce(page([row(1, "2026-10-20T09:58:00Z")], false));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(5));

    rerender(<Tab refreshVersion={1} />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-5" })));
    // Older history is unloaded: the older page lists the late row in its place.
    await waitFor(() => expect(summaryText()).toMatch(/^2 of 9 entries loaded/));
    expect(screen.queryByText(note(9))).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText(note(2));
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-4" }));
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText(note(1));
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-2" }));
    expect(shownNotes()).toEqual([5, 4, 3, 9, 2, 1]);
    expect(screen.queryByRole("button", { name: "Load older entries" })).toBeNull();
  });

  it("places a late row an older page read before it was recorded does not list", async () => {
    const olderPage = deferred<ActivityFeedPage>();
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockReturnValueOnce(olderPage.promise)
      .mockResolvedValueOnce(page([row(9, "2026-10-20T10:03:30Z")]));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(5));

    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    rerender(<Tab refreshVersion={1} />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenCalledTimes(3));
    await act(async () => olderPage.resolve(page([row(3, "2026-10-20T10:03:00Z"), row(2, "2026-10-20T10:02:00Z")], true)));

    await screen.findByText(note(9));
    expect(shownNotes()).toEqual([5, 4, 9, 3, 2]);
  });

  it("lists a late row below every loaded row at the end once all history is loaded", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], false))
      .mockResolvedValueOnce(page([row(6, "2026-10-20T10:06:00Z"), row(9, "2026-10-20T10:00:00Z"), row(6, "2026-10-20T10:06:00Z")]));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(5));

    rerender(<Tab refreshVersion={1} />);

    await screen.findByText(note(9));
    expect(shownNotes()).toEqual([6, 5, 4, 9]);
  });

  it("continues each refresh from the last one's catch-up cursor, so late rows are not offered again", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")]))
      // Only a late row arrived: no row is newer than the head.
      .mockResolvedValueOnce(page([row(9, "2026-10-20T10:04:30Z")], false, 9, "catch-up-1"))
      // Only rows the view hides arrived.
      .mockResolvedValueOnce(page([], false, 9, "catch-up-2"))
      .mockResolvedValueOnce(page([row(10, "2026-10-20T10:06:00Z")], false, 10));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(5));

    rerender(<Tab refreshVersion={1} />);
    await screen.findByText(note(9));
    const list = screen.getByRole("region", { name: "Activity entries" });
    list.scrollTop = 400;
    fireEvent.scroll(list);
    rerender(<Tab refreshVersion={2} />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "catch-up-1" })));
    rerender(<Tab refreshVersion={3} />);

    await screen.findByRole("button", { name: "1 new entry — show" });
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "catch-up-2" }));
    expect(shownNotes()).toEqual([5, 9, 4]);
  });

  it("drops an older page that lands after the list started again from its newest rows", async () => {
    const olderPage = deferred<ActivityFeedPage>();
    const behind = vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockReturnValueOnce(olderPage.promise);
    // Too far behind to stitch: every catch-up page says more remain.
    for (let id = 20; id < 25; id += 1) behind.mockResolvedValueOnce(page([row(id, `2026-10-20T11:${id}:00Z`)], true));
    behind
      .mockResolvedValueOnce(page([row(31, "2026-10-20T12:31:00Z"), row(30, "2026-10-20T12:30:00Z")], true, 40))
      .mockResolvedValueOnce(page([row(29, "2026-10-20T12:29:00Z")], true, 40));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(5));

    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    rerender(<Tab refreshVersion={1} />);
    await screen.findByText(note(31));
    await act(async () => olderPage.resolve(page([row(3, "2026-10-20T10:03:00Z"), row(2, "2026-10-20T10:02:00Z")], true)));

    expect(shownNotes()).toEqual([31, 30]);
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText(note(29));
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-30" }));
    expect(shownNotes()).toEqual([31, 30, 29]);
  });

  it("holds new rows behind a pill while the reader is scrolled down", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(2, "2026-10-20T10:02:00Z")]))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")]));
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText("Note 2 about the Acme portal");

    const list = screen.getByRole("region", { name: "Activity entries" });
    list.scrollTop = 400;
    fireEvent.scroll(list);
    rerender(<Tab refreshVersion={1} />);

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
    const { rerender } = render(<Tab refreshVersion={0} />);
    await screen.findByText("Note 1 about the Acme portal");

    rerender(<Tab refreshVersion={1} />);
    rerender(<Tab refreshVersion={2} />);
    rerender(<Tab refreshVersion={3} />);
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
    const { rerender } = render(<Tab refreshVersion={0} />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenCalledTimes(1));

    // A row is written after the first page was requested; its refresh signal
    // arrives before that page lands.
    rerender(<Tab refreshVersion={1} />);
    await act(async () => firstPage.resolve(page([row(1, "2026-10-20T10:01:00Z")])));

    expect(await screen.findByText("Note 2 about the Acme portal")).toBeTruthy();
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-1" }));
    expect(screen.getByText("Note 1 about the Acme portal")).toBeTruthy();
    expect(summaryText()).toMatch(/^2 of 10 entries loaded/);
  });

  it("clears the search from the box, like the other ledgers", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<Tab initialQuery="portal" />);
    await screen.findByText("Note 1 about the Acme portal");
    fireEvent.click(screen.getByRole("button", { name: "Clear activity search" }));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("");
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: undefined })));
  });

  it("links entities to their owning view and shows the stored fields verbatim in the entry's record", async () => {
    const token = `Bearer acme-secret-${"x".repeat(600)}`;
    const summary = `Recorded finding VA-001 (high, active) ${"with a long trail ".repeat(30)}end`;
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(7, "2026-10-20T10:07:00.250Z", {
        category: "findings",
        kind: "finding-record",
        summary,
        actor: { name: "va-acme-01", kind: "agent" },
        entities: [{ type: "finding", key: "VA-001", label: "VA-001" }],
        detail: {
          actor_kind: "system",
          action: `finding=VA-001 severity=high token=${token}`,
          result: "active",
          body_markdown: "",
          metadata: { finding_slug: "VA-001", token },
          recorded_at: "2026-10-20T10:07:01Z",
        },
      }),
    ]));
    render(<Tab />);

    const link = await within(entries()).findByRole("link", { name: "VA-001" });
    expect(link.getAttribute("href")).toBe("#/engagements/acme?tab=findings&finding=VA-001");

    fireEvent.click(entryRow(/Recorded finding VA-001/));
    const view = await record();
    // The record names the entry, and its title is the whole summary.
    expect(within(view).getByText("Audit log entry #7")).toBeTruthy();
    expect(within(view).getByRole("heading", { level: 2 }).textContent).toBe(summary);
    expect(within(view).getByText("Findings & chains")).toBeTruthy();
    expect(within(view).getByTitle("Agent: va-acme-01")).toBeTruthy();
    const dates = within(view).getByRole("group", { name: "Entry dates" });
    expect(dates.textContent).toContain("Occurred");
    expect(dates.querySelector('time[datetime="2026-10-20T10:07:01.000Z"]')).toBeTruthy();
    // Stored fields are whole: nothing is shortened or masked on the way in.
    expect(within(view).getByText(`finding=VA-001 severity=high token=${token}`)).toBeTruthy();
    expect(within(view).getByRole("button", { name: "Copy action for audit:7" })).toBeTruthy();
    expect(within(view).getByRole("button", { name: "Copy result for audit:7" })).toBeTruthy();
    expect(within(view).getByText(/stored as system/)).toBeTruthy();
    expect(within(view).getByText(/10:07:00\.250/)).toBeTruthy();
    expect(within(view).getByRole("link", { name: "VA-001" }).getAttribute("href")).toBe("#/engagements/acme?tab=findings&finding=VA-001");

    const metadata = within(view).getByRole("button", { name: /^Metadata/ });
    expect(within(metadata).getByText("2")).toBeTruthy();
    fireEvent.click(metadata);
    expect(section()).toContain("Metadata");
    expect(within(view).getByText(new RegExp(token))).toBeTruthy();
  });

  it("starts from the filters the URL names and writes later changes back without adding history", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    const before = window.history.length;
    render(<Tab initialQuery="VA-001" initialCategories={["findings", "notes"]} initialActor="agent" initialRange="7d" />);
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
    const view = render(<Tab initialQuery="first" />);
    await screen.findByText("Note 1 about the Acme portal");
    view.rerender(<Tab initialQuery="second" />);
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: "second" })));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("second");
  });

  it("brings back loaded pages and open cards after leaving the tab and returning", async () => {
    const [done, plain, started] = dispatchRows();
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([done, plain], true))
      .mockResolvedValueOnce(page([started], false));
    const first = render(<Tab initialQuery="acme" />);
    await screen.findByText(note(8));
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    const card = await within(entries()).findByRole("button", { name: /va-acme-01.*2 entries/ });
    expect(card.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(card);
    expect(entryRow("Started va-acme-01")).toBeTruthy();
    first.unmount();

    vi.mocked(listActivityFeed).mockClear();
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([done, plain, started], false));
    render(<Tab initialQuery="acme" />);

    const restored = await within(entries()).findByRole("button", { name: /va-acme-01.*2 entries/ });
    expect(restored.getAttribute("aria-expanded")).toBe("true");
    expect(entryRow("Started va-acme-01")).toBeTruthy();
    expect(listActivityFeed).toHaveBeenCalledTimes(1);
    expect(listActivityFeed).toHaveBeenCalledWith("acme", expect.objectContaining({ q: "acme", limit: 100 }));
  });

  it("returns to the scroll position the reader left, once the entries are back on screen", async () => {
    // A scroll box cannot scroll past its content: 100px per entry on screen.
    const scrolled = new WeakMap<Element, number>();
    const original = Object.getOwnPropertyDescriptor(Element.prototype, "scrollTop")!;
    Object.defineProperty(Element.prototype, "scrollTop", {
      configurable: true,
      get() { return scrolled.get(this) ?? 0; },
      set(value: number) { scrolled.set(this, Math.min(value, this.querySelectorAll(".activity-entry").length * 100)); },
    });
    try {
      const rows = [row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z"), row(3, "2026-10-20T10:03:00Z")];
      vi.mocked(listActivityFeed).mockResolvedValue(page(rows));
      const first = render(<Tab />);
      await screen.findByText("Note 5 about the Acme portal");
      const list = screen.getByRole("region", { name: "Activity entries" });
      list.scrollTop = 250;
      fireEvent.scroll(list);
      first.unmount();

      // The position comes back with the entries, not on a later timer that
      // can run before they are on screen.
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      render(<Tab />);
      await act(async () => {});
      expect(screen.getByText("Note 5 about the Acme portal")).toBeTruthy();
      expect(screen.getByRole("region", { name: "Activity entries" }).scrollTop).toBe(250);
    } finally {
      vi.useRealTimers();
      Object.defineProperty(Element.prototype, "scrollTop", original);
    }
  });

  it("says why the last selected category stays on instead of ignoring the click", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<Tab initialCategories={["notes"]} />);
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
    render(<Tab />);

    expect((await screen.findByRole("link", { name: /app\.example\.com\/login/ })).getAttribute("href"))
      .toBe("#/engagements/acme?tab=surfaces&surface=41");
    expect(screen.queryByRole("link", { name: /scans\/acme\.txt/ })).toBeNull();
    fireEvent.click(entryRow(/Registered note file/));
    const view = await record();
    expect(within(view).getByText(reason)).toBeTruthy();
    expect(within(view).queryByRole("link", { name: /scans\/acme\.txt/ })).toBeNull();
    expect(within(view).getByRole("link", { name: /app\.example\.com\/login/ }).getAttribute("href"))
      .toBe("#/engagements/acme?tab=surfaces&surface=41");
  });

  it("shows a changed filter's results from their first entry", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:00:00Z")]));
    render(<Tab />);
    await screen.findByText("Note 1 about the Acme portal");
    const list = screen.getByRole("region", { name: "Activity entries" });
    list.scrollTop = 400;
    fireEvent.scroll(list);

    fireEvent.click(screen.getByRole("button", { name: /^Agents/ }));

    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ actor: "agent" })));
    await waitFor(() => expect(list.scrollTop).toBe(0));
  });

  it("drops categories the feed does not have from a linked selection, and says which", async () => {
    vi.mocked(listActivityFeed).mockImplementation(async (_key, query = {}) => {
      if (query.categories?.includes("bogus")) throw new ApiError("unknown activity categories: bogus", 422, null);
      return page([row(1, "2026-10-20T10:00:00Z")]);
    });
    render(<Tab initialCategories={["notes", "bogus"]} />);

    expect(await screen.findByText("Note 1 about the Acme portal")).toBeTruthy();
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ categories: ["notes"] }));
    expect(screen.getByRole("button", { name: /Notes & other/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: /Findings & chains/ }).getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByText(/bogus/).closest('[role="status"]')).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&cats=notes");
  });

  it("still offers the category chips when the first read is refused, and bounds the search to what the feed accepts", async () => {
    const long = "a".repeat(1500);
    vi.mocked(listActivityFeed).mockImplementation(async (_key, query = {}) => {
      if ((query.q ?? "").length > 1024) throw new ApiError("query.q: String should have at most 1024 characters", 422, null);
      return page([row(1, "2026-10-20T10:00:00Z")]);
    });
    render(<Tab initialQuery={long} />);

    expect((await screen.findByText(/at most 1024 characters/)).getAttribute("role")).toBe("alert");
    expect(await screen.findByRole("button", { name: /Notes & other/ })).toBeTruthy();
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).maxLength).toBe(1024);
  });

  it("names the linked records a row has no room to show", async () => {
    const slugs = ["VA-001", "VA-002", "VA-003", "VA-004", "VA-005", "VA-006"];
    vi.mocked(listActivityFeed).mockResolvedValueOnce(page([
      row(8, "2026-10-20T10:08:00Z", { entities: slugs.map((slug) => ({ type: "finding", key: slug, label: slug })) }),
    ]));
    render(<Tab />);
    await screen.findByRole("link", { name: "VA-004" });
    expect(screen.queryByRole("link", { name: "VA-005" })).toBeNull();
    expect(screen.getByText("+2").getAttribute("title")).toContain("VA-005, VA-006");

    // The record lists every linked record.
    fireEvent.click(entryRow(note(8)));
    const view = await record();
    for (const slug of slugs) {
      expect(within(view).getByRole("link", { name: slug }).getAttribute("href")).toBe(`#/engagements/acme?tab=findings&finding=${slug}`);
    }
    expect(within(view).queryByText("+2")).toBeNull();
  });

  it("offers Clear filters when nothing matches, and the plain empty state otherwise", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([], false, 0));
    const view = render(<Tab initialQuery="nothing-here" />);
    expect(await screen.findByText("No activity matches these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ q: undefined })));
    view.unmount();

    render(<Tab />);
    expect(await screen.findByText("No activity recorded yet.")).toBeTruthy();
    expect(screen.queryByText("No activity matches these filters.")).toBeNull();
    expect((screen.getByRole("button", { name: "Clear filters" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("opens an entry from its row in the record view, and Back returns to the list with focus on that row", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(3, "2026-10-20T10:03:00Z"), row(2, "2026-10-20T10:02:00Z"), row(1, "2026-10-20T10:01:00Z")]));
    render(<Tab initialQuery="acme" />);
    await screen.findByText(note(3));
    const before = window.history.length;

    fireEvent.click(entryRow(note(2)));

    const view = await record();
    expect(within(view).getByRole("heading", { level: 2, name: note(2) })).toBeTruthy();
    expect(within(view).getByText("2 of 3 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&q=acme&entry=audit%3A2");
    expect(window.history.length).toBe(before + 1);
    expect(getActivityEntry).not.toHaveBeenCalled();
    // The list and the page header stay mounted behind the record, out of the accessibility tree.
    expect(screen.queryByRole("region", { name: "Activity entries" })).toBeNull();
    expect(screen.queryByRole("heading", { level: 1, name: "Activity" })).toBeNull();
    // `/` belongs to the list's search, which is not on screen.
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).not.toBe(screen.getByRole("searchbox", { name: "Search activity", hidden: true }));

    fireEvent.click(within(view).getByRole("button", { name: "Back to results" }));
    await noRecord();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&q=acme");
    expect(window.history.length).toBe(before + 2);
    await waitFor(() => expect(document.activeElement).toBe(entryRow(note(2))));
    expect((screen.getByRole("searchbox", { name: "Search activity" }) as HTMLInputElement).value).toBe("acme");
  });

  it("opens the focused row with Enter's activation, like any button", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:01:00Z")]));
    render(<Tab />);
    await screen.findByText(note(1));
    const opener = entryRow(note(1));
    expect(opener.tagName).toBe("BUTTON");
    expect(opener.getAttribute("data-record-key")).toBe("audit:1");
    expect(screen.getByText("open").closest(".findings-shortcuts")).toBeTruthy();
  });

  it("steps through the shown order with [ and ], members of a collapsed card included, and Escape lands on the entry last shown", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page(dispatchRows()));
    render(<Tab />);
    await screen.findByText(note(8));
    // The card (rows 9 and 7) sits where its newest row is; the note follows it.
    fireEvent.click(entryRow(note(8)));
    const view = await record();
    expect(within(view).getByText("3 of 3 results")).toBeTruthy();
    expect((within(view).getByRole("button", { name: "Next entry" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.keyDown(window, { key: "[" });
    await within(view).findByRole("heading", { level: 2, name: "Started va-acme-01" });
    expect(within(view).getByText("2 of 3 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&entry=audit%3A7");
    fireEvent.keyDown(window, { key: "[" });
    await within(view).findByRole("heading", { level: 2, name: "va-acme-01 finished (completed)" });
    expect((within(view).getByRole("button", { name: "Previous entry" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(window, { key: "]" });
    await within(view).findByRole("heading", { level: 2, name: "Started va-acme-01" });

    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();
    // The row is inside the card, which was collapsed: returning expands it.
    await waitFor(() => expect(document.activeElement).toBe(entryRow("Started va-acme-01")));
    expect(within(entries()).getByRole("button", { name: /va-acme-01.*2 entries/ }).getAttribute("aria-expanded")).toBe("true");
  });

  it("returns to a row inside a collapsed burst of dispatch cards", async () => {
    const dispatch = (agent: string) => ({ agent_id: agent, role: "vulnerability-analyst", run_id: null });
    const rows = [1, 2, 3].flatMap((n) => [
      row(n * 10 + 1, `2026-10-20T10:0${n}:30Z`, { kind: "agent done", summary: `va-acme-0${n} finished`, dispatch: dispatch(`va-acme-0${n}`) }),
      row(n * 10, `2026-10-20T10:0${n}:00Z`, { kind: "agent start", summary: `Started va-acme-0${n}`, dispatch: dispatch(`va-acme-0${n}`) }),
    ]).reverse();
    vi.mocked(listActivityFeed).mockResolvedValue(page(rows));
    // A cold link reads the entry at once, alongside the newest page that also holds it.
    vi.mocked(getActivityEntry).mockResolvedValue(rows.find((item) => item.id === "audit:20")!);
    render(<Tab initialEntryId="audit:20" />);

    const view = await record();
    await within(view).findByRole("heading", { level: 2, name: "Started va-acme-02" });
    expect(within(view).getByText("3 of 6 results")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();

    await waitFor(() => expect(document.activeElement).toBe(entryRow("Started va-acme-02")));
    expect(within(entries()).getByRole("button", { name: /3 vulnerability-analyst dispatches/ }).getAttribute("aria-expanded")).toBe("true");
    // Only the groups that hold the row opened.
    expect(within(entries()).queryByRole("button", { name: "Started va-acme-01" })).toBeNull();
  });

  it("loads older entries when a step passes the loaded edge, and counts only what is loaded", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z"), row(4, "2026-10-20T10:04:00Z")], true))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")], false));
    render(<Tab />);
    await screen.findByText(note(5));
    fireEvent.click(entryRow(note(4)));
    const view = await record();
    expect(within(view).getByText("2 of 2+ results")).toBeTruthy();

    fireEvent.click(within(view).getByRole("button", { name: "Next entry" }));

    await within(view).findByRole("heading", { level: 2, name: note(3) });
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ before: "cursor-4" }));
    expect(within(view).getByText("3 of 3 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&entry=audit%3A3");
  });

  it("says so in the record and under the list when older entries cannot be loaded, and retries from either", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z")], true))
      .mockRejectedValueOnce(new ApiError("feed is busy", 503, null))
      .mockResolvedValueOnce(page([row(4, "2026-10-20T10:04:00Z")], false));
    render(<Tab />);
    await screen.findByText(note(5));
    fireEvent.click(entryRow(note(5)));
    const view = await record();

    fireEvent.keyDown(window, { key: "]" });

    expect((await within(view).findByRole("alert")).textContent).toContain("feed is busy");
    expect(within(view).getByRole("heading", { level: 2, name: note(5) })).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();
    expect(within(entries()).getByRole("alert").textContent).toContain("feed is busy");

    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText(note(4));
    expect(within(entries()).queryByRole("alert")).toBeNull();
  });

  it("follows the address to an entry, to another, and back to the list, as browser Back and Forward do", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(3, "2026-10-20T10:03:00Z"), row(2, "2026-10-20T10:02:00Z")]));
    const view = render(<Tab />);
    await screen.findByText(note(3));
    const before = window.history.length;

    view.rerender(<Tab initialEntryId="audit:2" />);
    expect(await within(await record()).findByRole("heading", { level: 2, name: note(2) })).toBeTruthy();
    view.rerender(<Tab initialEntryId="audit:3" initialDrawerTab="metadata" />);
    expect(await within(await record()).findByRole("heading", { level: 2, name: note(3) })).toBeTruthy();
    view.rerender(<Tab />);
    await noRecord();

    expect(entryRow(note(3))).toBeTruthy();
    // Following the address writes nothing back.
    expect(window.history.length).toBe(before);
    expect(getActivityEntry).not.toHaveBeenCalled();
  });

  it("keeps the open entry's section in the address, and opens the section a link names", async () => {
    const withMetadata = row(2, "2026-10-20T10:02:00Z", { detail: { action: "scoped the login", metadata: { host: "app.example.com" } } });
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(3, "2026-10-20T10:03:00Z"), withMetadata]));
    vi.mocked(getActivityEntry).mockResolvedValue(withMetadata);
    const view = render(<Tab initialEntryId="audit:2" initialDrawerTab="metadata" />);

    const open = await record();
    await within(open).findByText(/app\.example\.com/);
    expect(section()).toContain("Metadata");
    expect(within(open).queryByText("scoped the login")).toBeNull();

    const before = window.history.length;
    fireEvent.click(within(open).getByRole("button", { name: "Details" }));
    expect(within(open).getByText("scoped the login")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&entry=audit%3A2");
    fireEvent.click(within(open).getByRole("button", { name: /^Metadata/ }));
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&entry=audit%3A2&dtab=metadata");
    expect(window.history.length).toBe(before + 2);

    // Browser Back: the address names the Details section again.
    view.rerender(<Tab initialEntryId="audit:2" />);
    await waitFor(() => expect(section()).toBe("Details"));
    // An entry without stored metadata has no Metadata section to show.
    fireEvent.keyDown(window, { key: "[" });
    await within(open).findByRole("heading", { level: 2, name: note(3) });
    expect(within(open).queryByRole("button", { name: /^Metadata/ })).toBeNull();
    expect(section()).toBe("Details");
  });

  it("opens a linked entry beyond the loaded rows by reading that entry, without paging the history", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(900, "2026-10-20T10:05:00Z"), row(899, "2026-10-20T10:04:00Z")], true, 5000));
    const old = row(12, "2026-09-01T08:00:00Z", {
      summary: "Scoped the Acme login flow",
      entities: [{ type: "file", key: "RESUME.md", label: "RESUME.md", ref: { file_name: "RESUME.md" }, unlinked_reason: "" }],
      detail: { action: "read the handoff", metadata: {} },
    });
    const read = deferred<ActivityItem>();
    vi.mocked(getActivityEntry).mockReturnValue(read.promise);
    window.history.replaceState(null, "", "#/engagements/acme?tab=activity&entry=audit%3A12");
    render(<Tab initialEntryId="audit:12" />);

    // The record is up before the list or the entry has arrived.
    const view = await record();
    expect(within(view).getByRole("status", { name: "Loading entry audit:12" })).toBeTruthy();
    expect(getActivityEntry).toHaveBeenCalledWith("acme", "audit:12");
    await act(async () => read.resolve(old));

    expect(await within(view).findByRole("heading", { level: 2, name: "Scoped the Acme login flow" })).toBeTruthy();
    expect(within(view).getByText("read the handoff")).toBeTruthy();
    expect(within(view).getByRole("link", { name: "RESUME.md" }).getAttribute("href")).toBe("#/engagements/acme?tab=artifacts&file=RESUME.md");
    await waitFor(() => expect(within(view).getByText("Outside current results")).toBeTruthy());
    expect(within(view).getByRole("note").textContent).toContain("2 entries");
    expect((within(view).getByRole("button", { name: "Next entry" }) as HTMLButtonElement).disabled).toBe(true);
    // One read of the newest page, one of the entry: the history is not walked to find it.
    expect(listActivityFeed).toHaveBeenCalledTimes(1);
    expect(getActivityEntry).toHaveBeenCalledTimes(1);
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&entry=audit%3A12");

    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();
    expect(entryRow(note(900))).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity");
    // The entry has no row to return to: focus goes to the list instead of the page.
    await waitFor(() => expect(document.activeElement).toBe(entries()));
  });

  it("gives a linked entry its position once it is among the loaded rows", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(5, "2026-10-20T10:05:00Z")], true))
      .mockResolvedValueOnce(page([row(4, "2026-10-20T10:04:00Z")], false));
    vi.mocked(getActivityEntry).mockResolvedValue(row(4, "2026-10-20T10:04:00Z"));
    const view = render(<Tab initialEntryId="audit:4" />);
    const open = await record();
    await within(open).findByRole("heading", { level: 2, name: note(4) });
    await waitFor(() => expect(within(open).getByText("Outside current results")).toBeTruthy());

    view.rerender(<Tab />);
    await noRecord();
    fireEvent.click(screen.getByRole("button", { name: "Load older entries" }));
    await screen.findByText(note(4));
    fireEvent.click(entryRow(note(4)));

    expect(within(await record()).getByText("2 of 2 results")).toBeTruthy();
    expect(within(await record()).queryByRole("note")).toBeNull();
  });

  it("shows the list with a notice naming the entry when the address names one this engagement does not have", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:01:00Z")]));
    vi.mocked(getActivityEntry).mockRejectedValue(new ApiError("activity entry audit:999 is not in this engagement's feed", 404, null));
    window.history.replaceState(null, "", "#/engagements/acme?tab=activity&q=acme&entry=audit%3A999");
    const before = window.history.length;
    render(<Tab initialQuery="acme" initialEntryId="audit:999" />);

    const notice = (await screen.findByText(/audit:999 is not one of this engagement's activity entries/)).closest("[role=status]")!;
    expect(notice.textContent).toContain("The list is shown");
    await noRecord();
    expect(await within(entries()).findByRole("button", { name: note(1) })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=activity&q=acme");
    expect(window.history.length).toBe(before);
  });

  it("offers Try again inside the record when the linked entry cannot be read", async () => {
    vi.mocked(listActivityFeed).mockResolvedValue(page([row(1, "2026-10-20T10:01:00Z")]));
    vi.mocked(getActivityEntry)
      .mockRejectedValueOnce(new ApiError("backend restarting", 503, null))
      .mockResolvedValueOnce(row(12, "2026-09-01T08:00:00Z"));
    render(<Tab initialEntryId="audit:12" />);

    const view = await record();
    expect((await within(view).findByRole("alert")).textContent).toContain("backend restarting");
    fireEvent.click(within(view).getByRole("button", { name: "Try again" }));
    expect(await within(view).findByRole("heading", { level: 2, name: note(12) })).toBeTruthy();
  });

  it("holds arrivals behind the pill while a record is open, and the list takes them on return when it was at its top", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(2, "2026-10-20T10:02:00Z"), row(1, "2026-10-20T10:01:00Z")]))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")], false, 10));
    const view = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(2));
    fireEvent.click(entryRow(note(1)));
    const open = await record();
    expect(within(open).getByText("2 of 2 results")).toBeTruthy();

    view.rerender(<Tab refreshVersion={1} initialEntryId="audit:1" />);

    // The refresh still reads only what is newer; the open record's position does not move.
    expect(await screen.findByRole("button", { name: "1 new entry — show", hidden: true })).toBeTruthy();
    expect(listActivityFeed).toHaveBeenLastCalledWith("acme", expect.objectContaining({ after: "cursor-2" }));
    expect(screen.queryByText(note(3))).toBeNull();
    expect(within(open).getByText("2 of 2 results")).toBeTruthy();

    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();
    expect((await screen.findByText(note(3))).closest("li")?.className).toContain("is-new");
    expect(screen.queryByRole("button", { name: "1 new entry — show" })).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(entryRow(note(1))));
  });

  it("waits for the record to close before restarting a list that fell too far behind to catch up", async () => {
    let restarts = 0;
    let next = 3;
    vi.mocked(listActivityFeed).mockImplementation(async (_key, params) => {
      // More newer rows than a refresh walks: every page of them says more follow.
      if (params?.after) return page([row(next++, "2026-10-20T10:03:00Z")], true);
      restarts += 1;
      return restarts === 1
        ? page([row(2, "2026-10-20T10:02:00Z"), row(1, "2026-10-20T10:01:00Z")])
        : page([row(90, "2026-10-20T11:00:00Z"), row(89, "2026-10-20T10:59:00Z")]);
    });
    const view = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(2));
    fireEvent.click(entryRow(note(1)));
    const open = await record();
    view.rerender(<Tab refreshVersion={1} initialEntryId="audit:1" />);
    await waitFor(() => expect(next).toBeGreaterThan(3));
    await act(async () => { await new Promise((done) => setTimeout(done, 20)); });
    // The open record's place in the list holds.
    expect(restarts).toBe(1);
    expect(within(open).getByText("2 of 2 results")).toBeTruthy();

    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();
    expect(await screen.findByText(note(90))).toBeTruthy();
  });

  it("keeps arrivals behind the pill on return when the reader had scrolled down before opening", async () => {
    vi.mocked(listActivityFeed)
      .mockResolvedValueOnce(page([row(2, "2026-10-20T10:02:00Z"), row(1, "2026-10-20T10:01:00Z")]))
      .mockResolvedValueOnce(page([row(3, "2026-10-20T10:03:00Z")]));
    const view = render(<Tab refreshVersion={0} />);
    await screen.findByText(note(2));
    entries().scrollTop = 400;
    fireEvent.scroll(entries());
    fireEvent.click(entryRow(note(1)));
    await record();
    view.rerender(<Tab refreshVersion={1} initialEntryId="audit:1" />);
    await screen.findByRole("button", { name: "1 new entry — show", hidden: true });

    fireEvent.keyDown(window, { key: "Escape" });
    await noRecord();

    expect(screen.queryByText(note(3))).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "1 new entry — show" }));
    expect(screen.getByText(note(3))).toBeTruthy();
  });
});
