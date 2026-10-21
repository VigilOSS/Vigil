// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { CardSkeleton, ChartSkeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";

afterEach(cleanup);

it.each(["donut", "bar", "line"] as const)("names the %s chart loading state without exposing placeholder geometry", variant => {
  render(<ChartSkeleton variant={variant} label="Severity mix" />);
  expect(screen.getByRole("status", { name: "Loading Severity mix" }).getAttribute("aria-busy")).toBe("true");
  expect(screen.queryByRole("img")).toBeNull();
});

it("names table and generic loading regions", () => {
  render(<><TableSkeleton rows={2} /><CardSkeleton /></>);
  expect(screen.getByRole("status", { name: "Loading table" })).toBeTruthy();
  expect(screen.getByRole("status", { name: "Loading content" })).toBeTruthy();
});

it("says a load is still working only after it has run for a while", () => {
  vi.useFakeTimers();
  try {
    const { rerender } = render(<SlowLoadHint active what="the finding ledger" />);
    act(() => { vi.advanceTimersByTime(1_999); });
    expect(screen.queryByText(/Still loading/)).toBeNull();
    act(() => { vi.advanceTimersByTime(1); });
    expect(screen.getByRole("status").textContent).toBe("Still loading the finding ledger…");
    rerender(<SlowLoadHint active={false} what="the finding ledger" />);
    expect(screen.queryByText(/Still loading/)).toBeNull();
  } finally {
    vi.useRealTimers();
  }
});
