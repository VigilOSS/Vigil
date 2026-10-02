// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopyInline } from "./formatting";
import { JsonView } from "./JsonView";

afterEach(cleanup);

describe("clipboard feedback identity", () => {
  it("does not claim a stale copy after the displayed text changes and returns", async () => {
    let resolve!: () => void;
    const writeText = vi.fn().mockReturnValueOnce(new Promise<void>((done) => { resolve = done; })).mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const onCopied = vi.fn();
    const view = render(<CopyInline text="original-token" onCopied={onCopied} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    view.rerender(<CopyInline text="different-token" onCopied={onCopied} />);
    view.rerender(<CopyInline text="original-token" onCopied={onCopied} />);
    await act(async () => resolve());
    expect(screen.queryByText("Copied")).toBeNull();
    expect(onCopied).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Copy to clipboard" }));
    await screen.findByText("Copied");
    expect(onCopied).toHaveBeenCalledOnce();
  });

  it("does not report an old JSON copy failure against a new displayed record", async () => {
    let reject!: (error: Error) => void;
    const writeText = vi.fn().mockReturnValue(new Promise<void>((_done, failure) => { reject = failure; }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const view = render(<JsonView value={{ token: "original-token" }} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy JSON to clipboard" }));
    view.rerender(<JsonView value={{ token: "different-token" }} />);
    await act(async () => reject(new Error("denied")));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText("Copied")).toBeNull();
  });
});

describe.each([
  ["inline text", () => <CopyInline text="Authorization: Bearer full-token" />, "Copy to clipboard", "Authorization: Bearer full-token"],
  ["JSON", () => <JsonView value={{ token: "full-token" }} />, "Copy JSON to clipboard", JSON.stringify({ token: "full-token" }, null, 2)],
] as const)("%s clipboard", (_name, content, label, expectedText) => {
  it("waits for the write to resolve before claiming success", async () => {
    let resolve!: () => void;
    const writeText = vi.fn().mockReturnValue(new Promise<void>((done) => { resolve = done; }));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(content());
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect(writeText).toHaveBeenCalledWith(expectedText);
    expect(screen.queryByText("Copied")).toBeNull();
    resolve();
    await screen.findByText("Copied");
  });

  it("offers a manual-copy fallback when the write is rejected", async () => {
    const failure = Promise.reject(new Error("denied"));
    void failure.catch(() => {});
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockReturnValue(failure) } });
    render(content());
    fireEvent.click(screen.getByRole("button", { name: label }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Select and copy the text manually"));
    expect(screen.queryByText("Copied")).toBeNull();
  });
});
