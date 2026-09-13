// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import { SurfacesTab } from "./SurfacesTab";

vi.mock("../lib/api", () => ({
  listAssessmentFindingLinks: vi.fn().mockResolvedValue([]),
  listAssessmentSurfaces: vi.fn(),
  patchAssessmentSurface: vi.fn(),
}));

vi.mock("./SurfacesGrid", () => ({
  default: ({ rows }: { rows: unknown[] }) => rows.length === 0
    ? <span>No surfaces match the current filters.</span>
    : <div>surface grid</div>,
}));

afterEach(cleanup);

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
