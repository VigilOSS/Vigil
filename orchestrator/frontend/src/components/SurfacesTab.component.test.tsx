// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import {
  listAssessmentFindingLinks,
  listSurfaceRequestVariantLinks,
  patchAssessmentSurface,
} from "../lib/api";
import { SurfacesTab } from "./SurfacesTab";

vi.mock("../lib/api", () => ({
  listAssessmentFindingLinks: vi.fn().mockResolvedValue([]),
  listAssessmentSurfaces: vi.fn(),
  listSurfaceRequestVariantLinks: vi.fn(),
  patchAssessmentSurface: vi.fn(),
}));

// The grid is ag-grid in production; here a plain list exposes the rows in
// the order it shows them, marked with their record key. `gridSort.reverse`
// stands in for a header click: the grid reports the order it shows. Like
// ag-grid, the stand-in keeps a header sort only while it stays mounted.
const gridSort = { reverse: false };
vi.mock("./SurfacesGrid", async () => {
  const { useEffect, useState } = await import("react");
  return {
    default: function SurfacesGridMock({ rows, onRowOpen, onViewChange }: {
      rows: Array<{ id: number; target_descriptor: string }>;
      onRowOpen: (row: unknown, invoker: HTMLElement) => void;
      onViewChange?: (view: { ids: number[]; sort: { colId: string; sort: "asc" | "desc" }[] }) => void;
    }) {
      const [sort, setSort] = useState<{ colId: string; sort: "asc" | "desc" }>({ colId: "updated", sort: "desc" });
      const shown = gridSort.reverse ? [...rows].reverse() : rows;
      const order = shown.map((row) => row.id).join(",");
      useEffect(() => {
        onViewChange?.({ ids: order ? order.split(",").map(Number) : [], sort: [sort] });
      }, [order, sort, onViewChange]);
      return (
        <div>
          <span>surface grid</span>
          <button type="button" onClick={() => setSort({ colId: "target", sort: "asc" })}>Sort by target</button>
          {shown.map((row) => (
            <button key={row.id} type="button" data-record-key={row.id} onClick={(event) => onRowOpen(row, event.currentTarget)}>
              {row.target_descriptor}
            </button>
          ))}
        </div>
      );
    },
  };
});

const surface = (overrides: Record<string, unknown>) => ({
  id: 1,
  surface_type: "auth_entry",
  target_descriptor: "https://example.com/login",
  source_name: "recon",
  rationale: "Discovered during crawl",
  evidence_ref: "artifacts/recon.txt:14",
  status: "discovered",
  followup_condition: "",
  created_at: "2026-09-20T09:00:00Z",
  updated_at: "2026-09-21T12:00:00Z",
  // The server owns which surfaces are open (still need testing).
  open: !["covered", "not_applicable"].includes(String(overrides.status ?? "discovered")),
  ...overrides,
});

// The tab loads its grid lazily; load the stand-in once up front so no
// test's first wait includes the module import.
beforeAll(async () => {
  await import("./SurfacesGrid");
});

beforeEach(() => {
  window.sessionStorage.clear();
  gridSort.reverse = false;
  window.history.replaceState({}, "", "#/engagements");
  vi.mocked(listAssessmentFindingLinks).mockResolvedValue([]);
  vi.mocked(listSurfaceRequestVariantLinks).mockResolvedValue([]);
  vi.mocked(patchAssessmentSurface).mockImplementation(async (_key, _id, payload) => (
    surface({ id: _id, ...payload }) as never
  ));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("SurfacesTab evidence availability", () => {
  it("does not report absent findings while their association ledger is pending or unavailable", async () => {
    let rejectLinks!: (error: Error) => void;
    vi.mocked(listAssessmentFindingLinks).mockReturnValue(new Promise((_resolve, reject) => { rejectLinks = reject; }));
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[surface({})] as never} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/login" }));
    const record = await screen.findByRole("region", { name: "Surface record" });
    // The count stays unknown until the ledger answers.
    expect(within(record).getByRole("button", { name: "Linked findings" })).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Linked findings" }));
    expect(screen.getByText("Loading finding links…")).toBeTruthy();
    expect(screen.queryByText("No findings linked to this surface yet.")).toBeNull();
    rejectLinks(new Error("association ledger unavailable"));
    expect((await screen.findByRole("alert")).textContent).toContain("Finding links unavailable: association ledger unavailable");
    expect(screen.queryByText("No findings linked to this surface yet.")).toBeNull();
  });

  it("does not report absent request-variant relations while their ledger is loading", async () => {
    vi.mocked(listSurfaceRequestVariantLinks).mockReturnValue(new Promise(() => {}));
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[surface({})] as never} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/login" }));
    fireEvent.click(within(await screen.findByRole("region", { name: "Surface record" })).getByRole("button", { name: "Request variants" }));
    expect(screen.getByText("Loading request-variant links…")).toBeTruthy();
    expect(screen.queryByText("No durable request-variant links.")).toBeNull();
  });

  it("uses the stored surface identity rather than partially parsing a reference", async () => {
    vi.mocked(listAssessmentFindingLinks).mockResolvedValue([
      { id: 1, finding_slug: "VA-012", target_kind: "surface", target_id: 1, target_ref: "unstructured reference", role: "affected" },
      { id: 2, finding_slug: "VA-999", target_kind: "surface", target_id: null, target_ref: "1garbage", role: "affected" },
    ] as never);
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[surface({})] as never} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/login" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Linked findings\s*1$/ }));
    expect((await screen.findByRole("link", { name: /VA-012/ })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=findings&finding=VA-012");
    expect(screen.queryByRole("link", { name: /VA-999/ })).toBeNull();
  });

  it("warns when the surface snapshot reaches its fetch boundary", () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={Array.from({ length: 3 }, (_, id) => ({ id, open: true })) as never}
          snapshotLimit={3}
        />
      </ToastProvider>,
    );

    expect(screen.getByText(/surface limit reached · results may be incomplete/i)).toBeTruthy();
  });

  it("does not describe an unavailable surface ledger as empty", () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={[]}
          loadError="surface ledger unavailable"
        />
      </ToastProvider>,
    );

    expect(screen.getByRole("alert").textContent).toContain("surface ledger unavailable");
    expect(screen.queryByText("No surfaces discovered yet.")).toBeNull();
    expect(screen.queryByText("No surfaces match the current filters.")).toBeNull();
  });

  it("keeps a previously loaded surface grid visible with a refresh error", () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={[{ id: 1, open: true }] as never}
          loadError="surface refresh unavailable"
        />
      </ToastProvider>,
    );

    expect(screen.getByRole("alert").textContent).toContain("surface refresh unavailable");
    expect(screen.getByText("surface grid")).toBeTruthy();
  });
});

describe("SurfacesTab work queue", () => {
  const queue = () => [
    surface({ id: 1, target_descriptor: "https://example.com/discovered" }),
    surface({ id: 2, target_descriptor: "https://example.com/partial", status: "partially-covered", followup_condition: "Test as admin", source_name: "specialist-a" }),
    surface({ id: 3, target_descriptor: "https://example.com/admin-closed", status: "administratively-closed", source_name: "specialist-b" }),
    surface({ id: 4, target_descriptor: "https://example.com/covered", status: "covered", source_name: "specialist-c" }),
  ] as never;

  it("states its purpose, defaults to Needs attention with the server's open count, and retains All", async () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={queue()} /></ToastProvider>);

    expect(screen.getByRole("heading", { level: 1, name: "Surfaces" })).toBeTruthy();
    expect(screen.getByText(/entry point Vigil found/i)).toBeTruthy();
    expect(screen.getByRole("list", { name: "Summary" }).textContent).toMatch(/3\s*open.*4\s*surfaces/);
    const attention = screen.getByRole("button", { name: /^Needs attention\s*3/ });
    const all = screen.getByRole("button", { name: /^All\s*4/ });
    expect(attention.getAttribute("aria-pressed")).toBe("true");
    expect(all.getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByRole("button", { name: "https://example.com/partial" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "https://example.com/covered" })).toBeNull();

    fireEvent.click(all);
    expect(all.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "https://example.com/covered" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^specialist-a\s*1/ }));
    expect(screen.getByRole("button", { name: "https://example.com/partial" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "https://example.com/covered" })).toBeNull();
    expect(screen.getByRole("button", { name: "Clear filters (1)" })).toBeTruthy();
  });

  it("counts open surfaces by the server's open flag, never by re-deriving it from status", () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={[
            surface({ id: 1, status: "discovered", open: true }),
            surface({ id: 2, status: "administratively-closed", open: true, target_descriptor: "https://example.com/closed" }),
            surface({ id: 3, status: "discovered", open: false, target_descriptor: "https://example.com/settled" }),
          ] as never}
        />
      </ToastProvider>,
    );
    expect(screen.getByRole("button", { name: /^Needs attention\s*2/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: "https://example.com/closed" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "https://example.com/settled" })).toBeNull();
  });

  it("offers only filters that can match in the current view, counted within it", () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={queue()} /></ToastProvider>);
    const status = screen.getByRole("group", { name: "Status" });
    expect(within(status).queryByRole("button", { name: /^Covered/ })).toBeNull();
    expect(within(status).getByRole("button", { name: /^Discovered\s*1/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^All\s*4/ }));
    expect(within(screen.getByRole("group", { name: "Status" })).getByRole("button", { name: /^Covered\s*1/ })).toBeTruthy();
  });

  it("offers Clear filters when nothing matches", () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={queue()} /></ToastProvider>);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search surfaces" }), { target: { value: "no-such-surface" } });
    expect(screen.getByText("No surfaces match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByRole("button", { name: "https://example.com/partial" })).toBeTruthy();
  });

  it("says nothing was discovered without offering to clear filters", () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[]} /></ToastProvider>);
    expect(screen.getByText("No surfaces discovered yet.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Clear filters/ })).toBeNull();
  });
});

describe("SurfacesTab loading and saved view", () => {
  const queue = () => [
    surface({ id: 1, target_descriptor: "https://example.com/discovered" }),
    surface({ id: 2, target_descriptor: "https://example.com/partial", status: "partially-covered", source_name: "specialist-a" }),
    surface({ id: 3, target_descriptor: "https://example.com/covered", status: "covered" }),
  ] as never;

  it("shows a loading table until the surface ledger arrives", () => {
    const view = render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={null} /></ToastProvider>);
    expect(screen.getByRole("status", { name: "Loading table" })).toBeTruthy();
    view.rerender(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[]} /></ToastProvider>);
    expect(screen.getByText("No surfaces discovered yet.")).toBeTruthy();
  });

  it("opens on All when no surface needs attention", () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={[surface({ id: 4, status: "covered", target_descriptor: "https://example.com/covered" })] as never} /></ToastProvider>);
    expect(screen.getByRole("button", { name: /^All\s*1/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "https://example.com/covered" })).toBeTruthy();
  });

  it("keeps the scope, search and filters when the tab is left and reopened", () => {
    const first = render(<ToastProvider><SurfacesTab engagementKey="saved-demo" surfaces={queue()} /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: /^All\s*3/ }));
    fireEvent.click(screen.getByRole("button", { name: /^specialist-a\s*1/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search surfaces" }), { target: { value: "partial" } });
    first.unmount();

    render(<ToastProvider><SurfacesTab engagementKey="saved-demo" surfaces={queue()} /></ToastProvider>);
    expect(screen.getByRole("button", { name: /^All\s*3/ }).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByRole("searchbox", { name: "Search surfaces" }) as HTMLInputElement).value).toBe("partial");
    expect(screen.getByRole("button", { name: /^specialist-a\s*1/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "Clear filters (2)" })).toBeTruthy();
  });

  it("keeps the grid's sort through a search that matches nothing", async () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={queue()} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Sort by target" }));
    const summary = () => document.querySelector(".ui-results-summary")?.textContent ?? "";
    await waitFor(() => expect(summary()).toContain("Sorted by Target, A to Z"));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search surfaces" }), { target: { value: "no-such-surface" } });
    expect(screen.getByText("No surfaces match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("button", { name: "https://example.com/partial" })).toBeTruthy();
    expect(summary()).toContain("Sorted by Target, A to Z");
  });
});

describe("SurfacesTab lifecycle", () => {
  it("shows partial follow-up and requires it when marking partial coverage", async () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={[
            surface({
              id: 9,
              target_descriptor: "https://example.com/admin",
              status: "partially-covered",
              followup_condition: "Retest the admin path with an elevated identity",
            }),
          ] as never}
        />
      </ToastProvider>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/admin" }));
    const record = await screen.findByRole("region", { name: "Surface record" });
    expect(within(record).getAllByText("Retest the admin path with an elevated identity").length).toBeGreaterThan(0);
    expect(within(record).getAllByText("Partially covered").length).toBeGreaterThan(0);
    fireEvent.click(within(record).getByRole("button", { name: "Change status" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces&surface=9&dtab=status");
    expect(screen.getByText(/Administrative closure does not establish coverage/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Transition rationale"), {
      target: { value: "One identity tested" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mark partially covered" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/follow-up condition is required/i);

    const followup = "Retest with org admin. ".repeat(30);
    fireEvent.change(screen.getByLabelText("Required follow-up condition"), {
      target: { value: followup },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mark partially covered" }));

    expect(patchAssessmentSurface).toHaveBeenCalledWith("demo", 9, {
      status: "partially-covered",
      rationale: "One identity tested",
      followup_condition: followup.trim(),
    });
    expect(screen.getByRole("button", { name: "Mark administratively closed" })).toBeTruthy();
  });
});

describe("SurfacesTab request variants", () => {
  it("surfaces durable relations in the drawer and continues to HTTP", async () => {
    vi.mocked(listSurfaceRequestVariantLinks).mockResolvedValue([
      {
        id: 31,
        engagement_id: 1,
        surface_id: 12,
        request_variant_id: 44,
        relation: "primary-endpoint",
        evidence_ref: "artifacts/routes.json:8",
        created_at: "2026-09-21T12:00:00Z",
        updated_at: "2026-09-21T12:00:00Z",
      },
    ]);
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo key"
          surfaces={[surface({ id: 12, target_descriptor: "https://example.com/api" })] as never}
        />
      </ToastProvider>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/api" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Request variants\s*1$/ }));
    const variant = await screen.findByRole("link", { name: /Request variant #44/i });
    expect(variant.getAttribute("href")).toBe("#/engagements/demo%20key?tab=http&request=44");
    expect(screen.getByText("Primary endpoint")).toBeTruthy();
    expect(screen.getByText("artifacts/routes.json:8")).toBeTruthy();
    expect(listSurfaceRequestVariantLinks).toHaveBeenCalledWith("demo key", 12);
  });
});

describe("SurfacesTab record view", () => {
  const ledger = () => [
    surface({ id: 1, target_descriptor: "https://example.com/one" }),
    surface({ id: 2, target_descriptor: "https://example.com/two", source_name: "specialist-a" }),
    surface({ id: 3, target_descriptor: "https://example.com/three" }),
    surface({ id: 4, target_descriptor: "https://example.com/covered", status: "covered" }),
  ] as never;

  it("opens a surface in the shared record view and walks the grid's order", async () => {
    gridSort.reverse = true;
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} /></ToastProvider>);
    const row = await screen.findByRole("button", { name: "https://example.com/two" });
    fireEvent.click(row);

    const record = await screen.findByRole("region", { name: "Surface record" });
    expect(screen.queryByRole("dialog")).toBeNull();
    // The record replaces the results; they keep their state behind it.
    expect(screen.queryByRole("button", { name: /^Needs attention/ })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces&surface=2");
    expect(document.activeElement).toBe(within(record).getByRole("heading", { level: 2, name: "https://example.com/two" }));
    expect(within(record).getByText("Surface #2")).toBeTruthy();
    expect(within(record).getByText("2 of 3 results")).toBeTruthy();
    expect(within(record).getByLabelText("Surface dates").textContent).toContain("Created");
    expect(within(record).getByLabelText("Surface dates").textContent).toContain("Updated");

    // The grid shows 3, 2, 1: Next goes to 1, the last result.
    fireEvent.click(within(record).getByRole("button", { name: "Next surface" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "https://example.com/one" })).toBeTruthy();
    expect(within(record).getByText("3 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Next surface" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(document.body, { key: "[" });
    fireEvent.keyDown(document.body, { key: "[" });
    expect(await within(record).findByRole("heading", { level: 2, name: "https://example.com/three" })).toBeTruthy();
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Previous surface" }) as HTMLButtonElement).disabled).toBe(true);
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces&surface=3");

    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Surface record" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces");
    expect(screen.getByRole("button", { name: /^Needs attention/ }).getAttribute("aria-pressed")).toBe("true");
    // Back lands on the record last shown, not the row that opened the first one.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "https://example.com/three" })));
    expect(row).toBeTruthy();
  });

  it("keeps the open section while stepping and returns on Escape", async () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "https://example.com/one" }));
    const record = await screen.findByRole("region", { name: "Surface record" });
    fireEvent.click(within(record).getByRole("button", { name: /^Request variants/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces&surface=1&dtab=requests");
    fireEvent.click(within(record).getByRole("button", { name: "Next surface" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "https://example.com/two" })).toBeTruthy();
    expect(within(record).getByRole("button", { name: /^Request variants/ }).getAttribute("aria-current")).toBe("page");
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces&surface=2&dtab=requests");
    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Surface record" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces");
  });

  it("follows the URL: a deep link opens its section, shows a retired surface in All, and history leaves it", async () => {
    const view = render(
      <ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} initialSurfaceId={4} initialDrawerTab="status" /></ToastProvider>,
    );
    const record = await screen.findByRole("region", { name: "Surface record" });
    expect(within(record).getByRole("heading", { level: 2, name: "https://example.com/covered" })).toBeTruthy();
    expect(within(record).getByRole("button", { name: "Change status" }).getAttribute("aria-current")).toBe("page");
    // A covered surface is not in Needs attention; the deep link shows it among All.
    expect(within(record).getByText("4 of 4 results")).toBeTruthy();
    view.rerender(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("region", { name: "Surface record" })).toBeNull());
    expect(screen.getByRole("button", { name: /^All\s*4/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("reads a surface's request-variant links only once the record settles or its section opens", async () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} /></ToastProvider>);
    const row = await screen.findByRole("button", { name: "https://example.com/one" });
    // The settle delay is a timer; owning it keeps a slow run from settling a record early.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      fireEvent.click(row);
      const record = screen.getByRole("region", { name: "Surface record" });
      for (let step = 0; step < 2; step += 1) fireEvent.keyDown(document.body, { key: "]" });
      fireEvent.keyDown(document.body, { key: "[" });
      expect(listSurfaceRequestVariantLinks).not.toHaveBeenCalled();
      fireEvent.click(within(record).getByRole("button", { name: /^Request variants/ }));
      expect(listSurfaceRequestVariantLinks).toHaveBeenCalledTimes(1);
      expect(listSurfaceRequestVariantLinks).toHaveBeenCalledWith("demo", 2);

      // A record shown long enough reads its links without the section.
      fireEvent.click(within(record).getByRole("button", { name: "Overview" }));
      fireEvent.keyDown(document.body, { key: "]" });
      act(() => { vi.advanceTimersByTime(400); });
      expect(listSurfaceRequestVariantLinks).toHaveBeenLastCalledWith("demo", 3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("explains a deep link to a surface the ledger does not hold", () => {
    render(<ToastProvider><SurfacesTab engagementKey="demo" surfaces={ledger()} initialSurfaceId={404} /></ToastProvider>);
    expect(screen.getByRole("alert").textContent).toContain("Surface #404 is not in the loaded surface ledger");
    expect(screen.queryByRole("region", { name: "Surface record" })).toBeNull();
  });
});
