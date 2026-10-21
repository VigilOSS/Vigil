// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { useEffect, useRef, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../../contexts/ToastContext";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs, RecordView, useResultsScrollMemory, type RecordNavigation } from "./RecordView";
import { listNavigation, useRecordPosition, type RecordPosition } from "./recordNavigation";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const RECORDS = ["Alpha", "Bravo", "Charlie"];

// A tab in miniature: a list of rows, one open record, Previous / Next over the list.
function Workspace({ initial = null, navigationOverride, returnToRecord = false }: { initial?: string | null; navigationOverride?: Partial<RecordNavigation>; returnToRecord?: boolean }) {
  const [open, setOpen] = useState<string | null>(initial);
  const [tab, setTab] = useState<"one" | "two">("one");
  const invoker = useRef<HTMLElement | null>(null);
  const results = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(results, open !== null, returnToRecord ? { recordKey: open } : undefined);
  const navigation = { ...listNavigation(RECORDS, open, setOpen), ...navigationOverride };
  return (
    <ToastProvider>
      <div ref={results} hidden={open !== null}>
      <div data-testid="results-scroller">
      <ul aria-label="Results">
        {RECORDS.map((name) => (
          <li key={name} data-record-key={returnToRecord ? name : undefined}>
            <button type="button" onClick={(event) => { invoker.current = event.currentTarget; setOpen(name); }}>Open {name}</button>
          </li>
        ))}
      </ul>
      </div>
      </div>
      <input aria-label="Search" />
      {open && (
        <RecordView label="Thing record" noun="thing" navigation={navigation} onBack={() => setOpen(null)} titleId="thing-title" returnFocusRef={invoker}>
          <RecordHeader
            key={open}
            id={`T-${open}`}
            copyId={open}
            title={open}
            titleId="thing-title"
            accent="var(--ok)"
            actions={<RecordCopyLinkButton noun="thing" />}
            pills={<span className="pill">status</span>}
            dates={[{ label: "Created", value: "2026-10-10 10:00:00" }, { label: "Finished", value: null, fallback: "still running" }]}
            datesLabel="Thing dates"
          />
          <RecordTabs label="Thing sections" active={tab} onChange={setTab} tabs={[{ id: "one", label: "One", count: 3 }, { id: "two", label: "Two" }, { id: "one", label: "Hidden", hidden: true }]} />
          <RecordBody>
            <input aria-label="Field inside the record" />
            {tab === "one" ? <p>Section one of {open}</p> : <p>Section two of {open}</p>}
          </RecordBody>
        </RecordView>
      )}
    </ToastProvider>
  );
}

describe("RecordView position", () => {
  it("states the position, an outside record, a pending lookup, and a failed one", () => {
    const cases: Array<[Partial<RecordNavigation>, string]> = [
      [{ index: 0, total: 3 }, "1 of 3 results"],
      [{ index: 1233, total: 12345 }, `${(1234).toLocaleString()} of ${(12345).toLocaleString()} results`],
      [{ index: null, total: 3 }, "Outside current results"],
      [{ index: undefined, total: undefined }, "Locating in results…"],
      [{ index: 2, total: 3, error: "offline" }, "Position in results unavailable"],
      [{ index: 0, total: 1000, partialTotal: true }, `1 of ${(1000).toLocaleString()}+ results`],
    ];
    for (const [navigation, text] of cases) {
      const { unmount } = render(<Workspace initial="Alpha" navigationOverride={navigation} />);
      const position = screen.getByRole("group", { name: "Thing review navigation" }).querySelector("[aria-live]");
      expect(position?.textContent).toBe(text);
      unmount();
    }
  });
});

describe("listNavigation", () => {
  it("walks the shown order and stops at both ends", () => {
    const open = vi.fn();
    const first = listNavigation(RECORDS, "Alpha", open);
    expect(first).toMatchObject({ index: 0, total: 3, onPrevious: undefined });
    first.onNext?.();
    expect(open).toHaveBeenLastCalledWith("Bravo");
    const last = listNavigation(RECORDS, "Charlie", open);
    expect(last.onNext).toBeUndefined();
    last.onPrevious?.();
    expect(open).toHaveBeenLastCalledWith("Bravo");
    expect(listNavigation(RECORDS, "Zulu", open)).toEqual({ index: null, total: 3 });
  });
});

describe("RecordView", () => {
  it("replaces the results, focuses the record heading, and states where it sits", () => {
    render(<Workspace />);
    fireEvent.click(screen.getByRole("button", { name: "Open Bravo" }));
    const record = screen.getByRole("region", { name: "Thing record" });
    expect(screen.queryByRole("list", { name: "Results" })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("heading", { level: 2, name: "Bravo" }));
    expect(record.textContent).toContain("2 of 3 results");
    expect(screen.getByText("T-Bravo")).toBeTruthy();
    expect(screen.getByRole("group", { name: "Thing dates" }).textContent).toContain("still running");
    expect(screen.getByRole("button", { name: "One 3" }).getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("button", { name: "Hidden" })).toBeNull();
    expect(screen.getByRole("button", { name: "Copy link to this thing" })).toBeTruthy();
  });

  it("steps with the buttons and [ / ], disabled at the ends", () => {
    render(<Workspace />);
    fireEvent.click(screen.getByRole("button", { name: "Open Alpha" }));
    const previous = screen.getByRole("button", { name: "Previous thing" }) as HTMLButtonElement;
    expect(previous.disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Next thing" }));
    expect(screen.getByRole("heading", { level: 2, name: "Bravo" })).toBeTruthy();
    fireEvent.keyDown(document.body, { key: "]" });
    // Focus left with the replaced record; it moves to the new heading.
    expect(document.activeElement).toBe(screen.getByRole("heading", { level: 2, name: "Charlie" }));
    expect((screen.getByRole("button", { name: "Next thing" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(document.body, { key: "]" });
    expect(screen.getByRole("heading", { level: 2, name: "Charlie" })).toBeTruthy();
    // Keys typed into a field are text, not navigation.
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Field inside the record" }), { key: "[" });
    expect(screen.getByRole("heading", { level: 2, name: "Charlie" })).toBeTruthy();
    // Focus stays on a step button after a click; the keys still step from it.
    fireEvent.keyDown(screen.getByRole("button", { name: "Previous thing" }), { key: "[" });
    expect(screen.getByRole("heading", { level: 2, name: "Bravo" })).toBeTruthy();
  });

  it("keeps focus in the step controls when a step reaches the first or last record", () => {
    render(<Workspace initial="Bravo" />);
    const next = screen.getByRole("button", { name: "Next thing" });
    next.focus();
    fireEvent.click(next);
    expect(screen.getByRole("heading", { level: 2, name: "Charlie" })).toBeTruthy();
    expect((next as HTMLButtonElement).disabled).toBe(true);
    const previous = screen.getByRole("button", { name: "Previous thing" });
    expect(document.activeElement).toBe(previous);
    fireEvent.click(previous);
    fireEvent.click(previous);
    expect(screen.getByRole("heading", { level: 2, name: "Alpha" })).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Next thing" }));
  });

  it("keeps the step buttons focusable but inert while a neighbour lookup is pending", () => {
    const onNext = vi.fn();
    render(<Workspace initial="Bravo" navigationOverride={{ pending: true, onNext }} />);
    const next = screen.getByRole("button", { name: "Next thing" }) as HTMLButtonElement;
    expect(next.disabled).toBe(false);
    expect(next.getAttribute("aria-disabled")).toBe("true");
    next.focus();
    fireEvent.click(next);
    fireEvent.keyDown(document.body, { key: "]" });
    expect(onNext).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(next);
  });

  it("explains a partial count and reports a failed step past the loaded results", () => {
    render(<Workspace initial="Charlie" navigationOverride={{ partialTotal: true, stepError: "Could not load older results: offline" }} />);
    const position = screen.getByText("3 of 3+ results");
    expect(position.getAttribute("title")).toMatch(/loaded results/);
    expect(screen.getByRole("alert").textContent).toBe("Could not load older results: offline");
  });

  it("returns on Escape to the originating row, but not from a field or under a dialog", async () => {
    render(<Workspace />);
    const opener = screen.getByRole("button", { name: "Open Charlie" });
    opener.focus();
    fireEvent.click(opener);
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Field inside the record" }), { key: "Escape" });
    expect(screen.getByRole("region", { name: "Thing record" })).toBeTruthy();

    const dialog = document.createElement("div");
    dialog.setAttribute("aria-modal", "true");
    document.body.append(dialog);
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.getByRole("region", { name: "Thing record" })).toBeTruthy();
    dialog.remove();

    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Thing record" })).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "Open Charlie" })));
  });

  it("leaves focus alone when something else took it as the record closed", async () => {
    render(<Workspace />);
    fireEvent.click(screen.getByRole("button", { name: "Open Alpha" }));
    const search = screen.getByRole("textbox", { name: "Search" });
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    search.focus();
    await act(async () => {});
    expect(document.activeElement).toBe(search);
  });
});

describe("RecordHeader", () => {
  it("colors the accent bar by the record's status tone, the same color as its status pill", () => {
    render(
      <ToastProvider>
        <RecordHeader id="Run #7" title="Run seven" titleId="run-title" tone="danger" />
      </ToastProvider>,
    );
    const header = screen.getByRole("heading", { name: "Run seven" }).closest("header");
    expect(header?.getAttribute("data-tone")).toBe("danger");
    expect(header?.classList.contains("has-accent")).toBe(true);
  });
});

describe("useResultsScrollMemory", () => {
  it("puts the hidden results' inner scroll offsets back when the record closes", () => {
    render(<Workspace />);
    const scroller = screen.getByTestId("results-scroller");
    scroller.scrollTop = 120;
    scroller.scrollLeft = 30;
    fireEvent.scroll(scroller);
    fireEvent.click(screen.getByRole("button", { name: "Open Bravo" }));
    // Hiding the results resets their offsets in a real browser.
    scroller.scrollTop = 0;
    scroller.scrollLeft = 0;
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    expect(scroller.scrollTop).toBe(120);
    expect(scroller.scrollLeft).toBe(30);
  });

  it("returns to the record stepped to, not the row that opened the first one", () => {
    render(<Workspace returnToRecord />);
    const opener = screen.getByRole("button", { name: "Open Alpha" });
    opener.focus();
    fireEvent.click(opener);
    fireEvent.click(screen.getByRole("button", { name: "Next thing" }));
    fireEvent.click(screen.getByRole("button", { name: "Next thing" }));
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    const charlie = screen.getByRole("button", { name: "Open Charlie" });
    expect(document.activeElement).toBe(charlie);
    expect(charlie.closest("li")?.classList.contains("record-return-highlight")).toBe(true);
    expect(opener.closest("li")?.classList.contains("record-return-highlight")).toBe(false);
  });

  it("focuses a deep-linked record's grid row once the grid renders its cells", async () => {
    // A grid laid out while hidden (a deep link never showed it) renders its
    // rows first and their cells a frame or more after it is shown.
    function GridResults() {
      const [open, setOpen] = useState<string | null>("Charlie");
      const [cellsShown, setCellsShown] = useState(false);
      const results = useRef<HTMLDivElement | null>(null);
      useResultsScrollMemory(results, open !== null, { recordKey: open });
      useEffect(() => {
        if (open !== null) return undefined;
        const frame = requestAnimationFrame(() => requestAnimationFrame(() => setCellsShown(true)));
        return () => cancelAnimationFrame(frame);
      }, [open]);
      return (
        <ToastProvider>
          <div ref={results} hidden={open !== null}>
            <div role="grid" aria-label="Results grid">
              {RECORDS.map((name) => (
                <div key={name} role="row" className="ag-row" row-id={name}>
                  {cellsShown && <div role="gridcell" className="ag-cell" tabIndex={-1}>{name}</div>}
                </div>
              ))}
            </div>
          </div>
          {open && (
            <RecordView label="Thing record" noun="thing" navigation={listNavigation(RECORDS, open, setOpen)} onBack={() => setOpen(null)} titleId="grid-thing-title">
              <RecordHeader id={open} title={open} titleId="grid-thing-title" />
            </RecordView>
          )}
        </ToastProvider>
      );
    }
    render(<GridResults />);
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    const cell = await screen.findByRole("gridcell", { name: "Charlie" });
    await waitFor(() => expect(document.activeElement).toBe(cell));
    expect(cell.closest(".ag-row")?.classList.contains("record-return-highlight")).toBe(true);
  });

  it("brings a deep-linked record's row into view on return", () => {
    const scrolled: Element[] = [];
    Element.prototype.scrollIntoView = vi.fn(function (this: Element) { scrolled.push(this); });
    render(<Workspace initial="Charlie" returnToRecord />);
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    const row = screen.getByRole("button", { name: "Open Charlie" }).closest("li");
    expect(scrolled).toContain(row);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Open Charlie" }));
  });
});

describe("useRecordPosition", () => {
  type Row = { id: string };
  const position = (index: number | null, previous: string | null, next: string | null, total = 500): RecordPosition<Row> => ({
    index,
    total,
    previous: previous ? { id: previous } : null,
    next: next ? { id: next } : null,
  });

  it("locates the record, shows a stepped neighbour's position at once, and ignores stale answers", async () => {
    const answers: Record<string, (value: RecordPosition<Row>) => void> = {};
    const load = vi.fn((key: string) => new Promise<RecordPosition<Row>>((resolve) => { answers[key] = resolve; }));
    const open = vi.fn();
    const { result, rerender } = renderHook(({ key, identity }) => useRecordPosition<Row>({
      key,
      identity,
      load: () => load(key),
      keyOf: (row) => row.id,
      open,
    }), { initialProps: { key: "a", identity: "sort=1" } });

    expect(result.current).toMatchObject({ index: undefined, pending: true });
    await act(async () => answers.a(position(199, "z", "b")));
    expect(result.current).toMatchObject({ index: 199, total: 500, pending: false });
    result.current.onNext?.();
    expect(open).toHaveBeenCalledWith({ id: "b" });

    rerender({ key: "b", identity: "sort=1" });
    // Known from the previous answer while the server is asked.
    expect(result.current).toMatchObject({ index: 200, total: 500, pending: true });
    expect(result.current.onNext).toBeUndefined();

    rerender({ key: "c", identity: "sort=1" });
    await act(async () => answers.b(position(200, "a", "c")));
    // b's late answer does not describe c.
    expect(result.current).toMatchObject({ index: undefined, pending: true });
    await act(async () => answers.c(position(201, "b", null)));
    expect(result.current).toMatchObject({ index: 201, pending: false, onNext: undefined });

    // A new order re-locates the record; the last answer and its neighbours stay meanwhile.
    rerender({ key: "c", identity: "sort=2" });
    expect(result.current).toMatchObject({ index: 201, pending: false });
    result.current.onPrevious?.();
    expect(open).toHaveBeenLastCalledWith({ id: "b" });
    await act(async () => answers.c(position(null, null, null, 12)));
    expect(result.current).toMatchObject({ index: null, total: 12, pending: false });
  });

  it("settles under a burst of refreshes and re-locates once after, stepping with the last answer meanwhile", async () => {
    const answers: Array<(value: RecordPosition<Row>) => void> = [];
    const load = vi.fn(() => new Promise<RecordPosition<Row>>((resolve) => { answers.push(resolve); }));
    const open = vi.fn();
    const { result, rerender } = renderHook(({ identity }) => useRecordPosition<Row>({
      key: "a",
      identity,
      load,
      keyOf: (row) => row.id,
      open,
    }), { initialProps: { identity: "refresh=1" } });
    expect(load).toHaveBeenCalledTimes(1);

    // Live refreshes arrive faster than the lookup answers.
    rerender({ identity: "refresh=2" });
    rerender({ identity: "refresh=3" });
    rerender({ identity: "refresh=4" });
    expect(load).toHaveBeenCalledTimes(1);

    await act(async () => answers[0](position(41, "z", "b")));
    // The first answer settles; the burst folds into exactly one more lookup.
    expect(load).toHaveBeenCalledTimes(2);
    expect(result.current).toMatchObject({ index: 41, total: 500, pending: false });
    result.current.onNext?.();
    expect(open).toHaveBeenCalledWith({ id: "b" });

    rerender({ identity: "refresh=5" });
    expect(result.current).toMatchObject({ index: 41, pending: false });
    await act(async () => answers[1](position(42, "y", "c")));
    expect(load).toHaveBeenCalledTimes(3);
    await act(async () => answers[2](position(43, "x", "d")));
    expect(result.current).toMatchObject({ index: 43, pending: false });
    expect(load).toHaveBeenCalledTimes(3);
  });

  it("reports a failed lookup, and keeps a settled answer when only a refresh fails", async () => {
    let fail = true;
    const { result, rerender } = renderHook(({ identity }) => useRecordPosition<Row>({
      key: "a",
      identity,
      load: () => (fail ? Promise.reject(new Error("offline")) : Promise.resolve(position(3, "x", "y"))),
      keyOf: (row) => row.id,
      open: () => {},
    }), { initialProps: { identity: "1" } });
    await waitFor(() => expect(result.current.error).toBe("offline"));
    fail = false;
    rerender({ identity: "2" });
    await waitFor(() => expect(result.current).toMatchObject({ index: 3, pending: false }));
    fail = true;
    rerender({ identity: "3" });
    await waitFor(() => expect(result.current).toMatchObject({ index: 3, pending: false }));
    expect(result.current.error).toBeUndefined();
  });
});
