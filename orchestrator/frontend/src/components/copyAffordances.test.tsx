// @vitest-environment jsdom
//
// Behaviour pin for DrawerKit's CopyChip, the drawer-wide copy affordance.
// CopyInline's identity rules are already pinned in Clipboard.component.test.tsx;
// the chip's were not, and both are about to share one clipboard hook, so the
// chip's own rules are written down first: what it writes, when it claims
// success, how long the check stays, that a copy started against text the
// drawer has since replaced reports nothing, and what it says when the
// clipboard is not there.

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { CopyChip } from "./drawer/DrawerKit";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function clipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
}

const chip = () => screen.getByRole("button", { name: "Copy to clipboard" });

it("writes the exact text and claims success only once the write resolves", async () => {
  let resolve!: () => void;
  const writeText = vi.fn().mockReturnValue(new Promise<void>((done) => { resolve = done; }));
  clipboard(writeText);
  const toast = vi.fn();
  render(<CopyChip text="Authorization: Bearer full-token" toast={toast} />);
  fireEvent.click(chip());
  expect(writeText).toHaveBeenCalledWith("Authorization: Bearer full-token");
  expect(chip().className).not.toContain("is-copied");
  expect(toast).not.toHaveBeenCalled();
  await act(async () => resolve());
  expect(chip().className).toContain("is-copied");
  expect(toast).toHaveBeenCalledExactlyOnceWith("Copied", "success");
});

it("drops the check 1200ms after the copy", async () => {
  vi.useFakeTimers();
  clipboard(vi.fn().mockResolvedValue(undefined));
  render(<CopyChip text="token" toast={vi.fn()} />);
  fireEvent.click(chip());
  await act(async () => {});
  expect(chip().className).toContain("is-copied");
  await act(async () => { vi.advanceTimersByTime(1199); });
  expect(chip().className).toContain("is-copied");
  await act(async () => { vi.advanceTimersByTime(1); });
  expect(chip().className).not.toContain("is-copied");
});

it("reports nothing for a copy of text the drawer has since replaced", async () => {
  let resolve!: () => void;
  clipboard(vi.fn().mockReturnValue(new Promise<void>((done) => { resolve = done; })));
  const toast = vi.fn();
  const view = render(<CopyChip text="original-token" toast={toast} />);
  fireEvent.click(chip());
  view.rerender(<CopyChip text="different-token" toast={toast} />);
  await act(async () => resolve());
  expect(chip().className).not.toContain("is-copied");
  expect(toast).not.toHaveBeenCalled();
});

it("says so when the clipboard is unavailable", async () => {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  const toast = vi.fn();
  render(<CopyChip text="token" toast={toast} />);
  await act(async () => { fireEvent.click(chip()); });
  expect(toast).toHaveBeenCalledExactlyOnceWith("Could not copy to clipboard", "error");
  expect(chip().className).not.toContain("is-copied");
});

it("carries the caller's label into both the accessible name and the tooltip", () => {
  clipboard(vi.fn().mockResolvedValue(undefined));
  render(<CopyChip text="token" toast={vi.fn()} label="Copy summary" />);
  const button = screen.getByRole("button", { name: "Copy summary" });
  expect(button.getAttribute("title")).toBe("Copy summary");
});

it("titles the unlabelled chip Copy", () => {
  clipboard(vi.fn().mockResolvedValue(undefined));
  render(<CopyChip text="token" toast={vi.fn()} />);
  expect(chip().getAttribute("title")).toBe("Copy");
});
