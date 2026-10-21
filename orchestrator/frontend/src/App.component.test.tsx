// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { lazy, Suspense } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDashboardSummary, listEngagements } from "./lib/api";
import App from "./App";
import { EngagementPage } from "./routes/EngagementPage";

vi.mock("./lib/api", () => ({
  getDashboardSummary: vi.fn(),
  listEngagements: vi.fn(),
}));

vi.mock("./routes/EngagementPage", () => ({
  EngagementPage: vi.fn(({ initialRequestVariantId }: { initialRequestVariantId?: number }) => (
    <div>Request variant {initialRequestVariantId ?? "none"}</div>
  )),
}));

vi.mock("./routes/RemediationPage", () => ({
  RemediationPage: ({ engagementKey, initialCaseId }: { engagementKey: string; initialCaseId?: number }) => (
    <div>Remediation {engagementKey} case {initialCaseId ?? "none"}</div>
  ),
}));

beforeEach(() => {
  window.location.hash = "#/engagements";
  vi.mocked(getDashboardSummary).mockRejectedValue(new Error("dashboard unavailable"));
  vi.mocked(EngagementPage).mockImplementation(({ initialRequestVariantId }) => <div>Request variant {initialRequestVariantId ?? "none"}</div>);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("App engagement loading", () => {
  it("contains a render failure with the exact error and an explicit reload action", () => {
    window.location.hash = "#/engagements/demo?tab=surfaces";
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(EngagementPage).mockImplementation(() => { throw new Error("Stored surface render failed: row 168"); });
    expect(() => render(<App />)).not.toThrow();
    expect(screen.getByRole("alert").textContent).toContain("Error: Stored surface render failed: row 168");
    const reload = vi.fn();
    vi.stubGlobal("window", { location: { reload } });
    expect(reload).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Reload interface" }));
    expect(reload).toHaveBeenCalledOnce();
  });

  it("shows recovery after a rejected lazy module instead of leaving a blank workspace", async () => {
    window.location.hash = "#/engagements/demo?tab=surfaces";
    vi.spyOn(console, "error").mockImplementation(() => {});
    const FailedModule = lazy(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module: /assets/SurfacesTab-old.js")));
    vi.mocked(EngagementPage).mockImplementation(() => <Suspense fallback={<div>Loading surfaces</div>}><FailedModule /></Suspense>);
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain("TypeError: Failed to fetch dynamically imported module: /assets/SurfacesTab-old.js");
    expect(screen.getByRole("button", { name: "Reload interface" })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=surfaces");
  });
  it("surfaces a list failure instead of claiming there are no engagements", async () => {
    vi.mocked(listEngagements).mockRejectedValue(new Error("engagement API unavailable"));

    render(<App />);

    expect((await screen.findByRole("alert")).textContent).toContain("engagement API unavailable");
    expect(screen.queryByText(/No engagements discovered/)).toBeNull();
    await waitFor(() => expect(listEngagements).toHaveBeenCalledTimes(1));
  });

  it("passes an HTTP request deep link to the engagement page", async () => {
    window.location.hash = "#/engagements/demo?tab=http&request=19";

    render(<App />);

    expect(await screen.findByText("Request variant 19")).toBeTruthy();
  });

  it("passes proof-work and command deep links to the engagement page", async () => {
    vi.mocked(EngagementPage).mockImplementation(({ initialTab, initialWorkId, initialCommandId }) => (
      <div>Tab {initialTab} work {initialWorkId ?? "none"} command {initialCommandId ?? "none"}</div>
    ));
    window.location.hash = "#/engagements/demo?tab=proof&work=9";
    render(<App />);
    expect(await screen.findByText("Tab proof work 9 command none")).toBeTruthy();
    window.location.hash = "#/engagements/demo?tab=commands&command=77";
    expect(await screen.findByText("Tab commands work none command 77")).toBeTruthy();
  });

  it("does not turn an unsafe numeric deep link into a different rounded record ID", async () => {
    window.location.hash = "#/engagements/demo?tab=http&request=9007199254740993";
    render(<App />);
    expect(await screen.findByText("Request variant none")).toBeTruthy();
  });

  it("opens a remediation case on its dedicated route", async () => {
    window.location.hash = "#/remediation/acme?case=7";
    render(<App />);
    expect(await screen.findByText("Remediation acme case 7")).toBeTruthy();
    expect(listEngagements).not.toHaveBeenCalled();
  });

  it.each(["#/engagements/%E0%A4%A", "#/unknown/workspace"])("explains an invalid workspace route %s", async (hash) => {
    window.location.hash = hash;
    render(<App />);
    expect((await screen.findByRole("alert")).textContent).toContain("Workspace not found");
    expect(screen.getByRole("link", { name: "Open engagements" }).getAttribute("href")).toBe("#/engagements");
    expect(listEngagements).not.toHaveBeenCalled();
  });
});
