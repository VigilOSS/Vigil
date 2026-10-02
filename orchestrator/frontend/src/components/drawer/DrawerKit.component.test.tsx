// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopyChip } from "./DrawerKit";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Evidence copy", () => {
  it("ignores an old copy after changing away and back to the same text", async () => {
    let resolve!: () => void;
    const writeText = vi.fn().mockReturnValueOnce(new Promise<void>((done) => { resolve = done; })).mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const toast = vi.fn();
    const view = render(<CopyChip text="Original token" toast={toast} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    view.rerender(<CopyChip text="Different token" toast={toast} />);
    view.rerender(<CopyChip text="Original token" toast={toast} />);
    await act(async () => resolve());
    expect(toast).not.toHaveBeenCalled();
    expect(screen.getByRole("button").classList.contains("is-copied")).toBe(false);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(toast).toHaveBeenCalledWith("Copied", "success"));
  });

  it.each(["success", "failure"])("does not emit stale %s feedback after leaving the drawer", async (outcome) => {
    let resolve!: () => void;
    let reject!: (error: Error) => void;
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockReturnValue(new Promise<void>((done, failure) => { resolve = done; reject = failure; })) } });
    const toast = vi.fn();
    const view = render(<CopyChip text="Exact token" toast={toast} />);
    fireEvent.click(screen.getByRole("button"));
    view.unmount();
    await act(async () => { if (outcome === "success") resolve(); else reject(new Error("denied")); });
    expect(toast).not.toHaveBeenCalled();
  });
  it("reports a rejected clipboard write without claiming success", async () => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    const toast = vi.fn();
    render(<CopyChip text="Authorization: Bearer exact-token" toast={toast} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith("Could not copy to clipboard", "error"));
    expect(toast).not.toHaveBeenCalledWith("Copied", "success");
  });

  it("copies the exact bytes and confirms only after the write completes", async () => {
    let resolveWrite!: () => void;
    const writeText = vi.fn(() => new Promise<void>((resolve) => { resolveWrite = resolve; }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const toast = vi.fn();
    const evidence = "Cookie: session=abc\nAuthorization: Bearer exact-token";
    render(<CopyChip text={evidence} toast={toast} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    expect(writeText).toHaveBeenCalledWith(evidence);
    expect(toast).not.toHaveBeenCalled();
    resolveWrite();
    await waitFor(() => expect(toast).toHaveBeenCalledWith("Copied", "success"));
  });
});
