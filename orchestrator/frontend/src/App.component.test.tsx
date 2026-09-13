// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDashboardSummary, listEngagements } from "./lib/api";
import App from "./App";

vi.mock("./lib/api", () => ({
  getDashboardSummary: vi.fn(),
  listEngagements: vi.fn(),
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
});
