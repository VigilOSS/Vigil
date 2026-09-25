// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import {
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

vi.mock("./SurfacesGrid", () => ({
  default: ({ rows, onRowOpen }: { rows: Array<{ id: number; target_descriptor: string }>; onRowOpen: (row: unknown, invoker: HTMLElement) => void }) => rows.length === 0
    ? <span>No surfaces match the current filters.</span>
    : (
        <div>
          <span>surface grid</span>
          {rows.map((row) => (
            <button key={row.id} type="button" onClick={(event) => onRowOpen(row, event.currentTarget)}>
              {row.target_descriptor}
            </button>
          ))}
        </div>
      ),
}));

const surface = (overrides: Record<string, unknown>) => ({
  id: 1,
  surface_type: "auth_entry",
  target_descriptor: "https://example.test/login",
  source_name: "recon",
  rationale: "Discovered during crawl",
  evidence_ref: "artifacts/recon.txt:14",
  status: "discovered",
  followup_condition: "",
  updated_at: "2026-09-21T12:00:00Z",
  ...overrides,
});

beforeEach(() => {
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
  it("warns when the surface snapshot reaches its fetch boundary", () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={Array.from({ length: 5000 }, (_, id) => ({ id })) as never}
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
          surfaces={[{ id: 1 }] as never}
          loadError="surface refresh unavailable"
        />
      </ToastProvider>,
    );

    expect(screen.getByRole("alert").textContent).toContain("surface refresh unavailable");
    expect(screen.getByText("surface grid")).toBeTruthy();
  });
});

describe("SurfacesTab work queue", () => {
  it("defaults to Needs action, shows truthful open/total counts, and retains All", async () => {
    render(
      <ToastProvider>
        <SurfacesTab
          engagementKey="demo"
          surfaces={[
            surface({ id: 1, target_descriptor: "https://example.test/discovered" }),
            surface({ id: 2, target_descriptor: "https://example.test/partial", status: "partially-covered", followup_condition: "Test as admin", source_name: "specialist-a" }),
            surface({ id: 3, target_descriptor: "https://example.test/admin-closed", status: "administratively-closed", source_name: "specialist-b" }),
            surface({ id: 4, target_descriptor: "https://example.test/covered", status: "covered", source_name: "specialist-c" }),
          ] as never}
        />
      </ToastProvider>,
    );

    expect(await screen.findByLabelText("3 open / 4 total")).toBeTruthy();
    const needsAction = screen.getByRole("button", { name: "Needs action" });
    const all = screen.getByRole("button", { name: "All surfaces" });
    expect(needsAction.getAttribute("aria-pressed")).toBe("true");
    expect(all.getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByRole("button", { name: "https://example.test/partial" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "https://example.test/covered" })).toBeNull();

    fireEvent.click(all);
    expect(all.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "https://example.test/covered" })).toBeTruthy();

    const source = screen.getByRole("combobox", { name: "Source" });
    expect(screen.queryByRole("button", { name: /specialist-a/i })).toBeNull();
    fireEvent.change(source, { target: { value: "specialist-a" } });
    expect(screen.getByRole("button", { name: "https://example.test/partial" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "https://example.test/covered" })).toBeNull();

    const typeFilter = screen.getByRole("button", { name: /Filter type auth entry/i });
    expect(typeFilter.getAttribute("aria-pressed")).toBe("false");
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
              target_descriptor: "https://example.test/admin",
              status: "partially-covered",
              followup_condition: "Retest the admin path with an elevated identity",
            }),
          ] as never}
        />
      </ToastProvider>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "https://example.test/admin" }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Retest the admin path with an elevated identity")).toBeTruthy();
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
          surfaces={[surface({ id: 12, target_descriptor: "https://example.test/api" })] as never}
        />
      </ToastProvider>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "https://example.test/api" }));
    const variant = await screen.findByRole("link", { name: /Request variant #44/i });
    expect(variant.getAttribute("href")).toBe("#/engagements/demo%20key?tab=http&request=44");
    expect(screen.getByText("primary endpoint")).toBeTruthy();
    expect(screen.getByText("artifacts/routes.json:8")).toBeTruthy();
    expect(listSurfaceRequestVariantLinks).toHaveBeenCalledWith("demo key", 12);
  });
});
