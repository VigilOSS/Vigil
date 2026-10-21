// @vitest-environment jsdom

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TimeStamp, formatBytes } from "./formatting";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-20T18:07:07Z"));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("TimeStamp", () => {
  it("renders a zone-less database time as UTC with relative text and absolute hover", () => {
    render(<TimeStamp value="2026-10-20 14:07:07" />);
    const time = screen.getByText("4h ago");
    expect(time.tagName).toBe("TIME");
    expect(time.getAttribute("datetime")).toBe("2026-10-20T14:07:07.000Z");
    expect(time.getAttribute("title")).toBe("2026-10-20 14:07:07 UTC");
    expect(time.getAttribute("aria-label")).toBe("4h ago (2026-10-20 14:07:07 UTC)");
  });

  it("shows absolute UTC and age together for detail panes", () => {
    render(<TimeStamp value="2026-10-20T10:07:07-04:00" mode="both" />);
    const time = screen.getByLabelText("2026-10-20 14:07:07 UTC (4h ago)");
    expect(time.textContent).toBe("2026-10-20 14:07:07 UTC · 4h ago");
  });

  it("gives an older time its age instead of repeating the date beside it", () => {
    render(<TimeStamp value="2026-07-16 22:02:42" mode="both" />);
    const time = screen.getByLabelText("2026-07-16 22:02:42 UTC (3mo ago)");
    expect(time.textContent).toBe("2026-07-16 22:02:42 UTC · 3mo ago");
  });

  it("keeps an unparseable recorded value visible and renders the fallback when missing", () => {
    const { rerender } = render(<TimeStamp value="sometime last week" />);
    expect(screen.getByText("sometime last week").tagName).toBe("SPAN");
    rerender(<TimeStamp value="" fallback="Not recorded" />);
    expect(screen.getByText("Not recorded")).toBeTruthy();
  });

  it("advances the relative label on the shared clock tick", () => {
    render(<TimeStamp value="2026-10-20T18:06:40Z" />);
    expect(screen.getByText("27s ago")).toBeTruthy();
    act(() => { vi.advanceTimersByTime(60_000); });
    expect(screen.getByText("1m ago")).toBeTruthy();
  });
});

describe("formatBytes", () => {
  it("formats sizes with one decimal and the next unit at the boundary", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1024 * 1024 - 1)).toBe("1.0 MB");
    expect(formatBytes(24.6 * 1024 * 1024)).toBe("24.6 MB");
    expect(formatBytes(3 * 1024 ** 3)).toBe("3.0 GB");
  });

  it("shows the placeholder for an unknown size instead of claiming zero", () => {
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(undefined, "")).toBe("");
    expect(formatBytes(Number.NaN)).toBe("—");
    expect(formatBytes(-1)).toBe("—");
  });
});
