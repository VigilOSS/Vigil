// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDashboardSummary, listEngagements } from "./lib/api";
import App from "./App";

vi.mock("./lib/api", () => ({
  getDashboardSummary: vi.fn(),
  listEngagements: vi.fn(),
}));

vi.mock("./routes/EngagementPage", () => ({
  EngagementPage: ({ initialRequestVariantId }: { initialRequestVariantId?: number }) => (
    <div>Request variant {initialRequestVariantId ?? "none"}</div>
  ),
}));

vi.mock("./routes/RemediationPage", () => ({
  RemediationPage: ({ engagementKey, initialCaseId }: { engagementKey: string; initialCaseId?: number }) => (
    <div>Remediation {engagementKey} case {initialCaseId ?? "none"}</div>
  ),
}));

beforeEach(() => {
  window.location.hash = "#/engagements";
  vi.mocked(getDashboardSummary).mockRejectedValue(new Error("dashboard unavailable"));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("App engagement loading", () => {
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

  it("opens a remediation case on its dedicated route", async () => {
    window.location.hash = "#/remediation/Acme?case=7";
    render(<App />);
    expect(await screen.findByText("Remediation Acme case 7")).toBeTruthy();
    expect(listEngagements).not.toHaveBeenCalled();
  });
});
