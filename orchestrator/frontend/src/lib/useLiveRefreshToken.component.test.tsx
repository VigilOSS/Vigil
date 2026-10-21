// @vitest-environment jsdom

import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useLiveRefreshToken } from "./useLiveRefreshToken";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-01T00:00:00Z"));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("useLiveRefreshToken", () => {
  it("ignores the version it mounted with", () => {
    const { result } = renderHook(({ version }) => useLiveRefreshToken(version, 5_000), { initialProps: { version: 3 } });
    expect(result.current).toBe(0);
  });

  it("refreshes at once, then at most once per window with one trailing refresh for a burst", () => {
    const { result, rerender } = renderHook(({ version }) => useLiveRefreshToken(version, 5_000), { initialProps: { version: 0 } });
    rerender({ version: 1 });
    expect(result.current).toBe(1);

    act(() => { vi.advanceTimersByTime(1_000); });
    rerender({ version: 2 });
    rerender({ version: 3 });
    rerender({ version: 4 });
    expect(result.current).toBe(1);

    act(() => { vi.advanceTimersByTime(3_999); });
    expect(result.current).toBe(1);
    act(() => { vi.advanceTimersByTime(1); });
    expect(result.current).toBe(2);

    act(() => { vi.advanceTimersByTime(10_000); });
    expect(result.current).toBe(2);
    rerender({ version: 5 });
    expect(result.current).toBe(3);
  });
});
