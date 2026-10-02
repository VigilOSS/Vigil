// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ToastProvider, ToastViewport, useToast } from "./ToastContext";

function Actions() {
  const { toast } = useToast();
  return <><button onClick={() => toast("Write failed; retry is required", "error")}>Fail</button><button onClick={() => toast("Copied", "success")}>Succeed</button></>;
}
afterEach(() => { cleanup(); vi.useRealTimers(); });
it("retains actionable failure notifications until dismissed, while successes expire", () => {
  vi.useFakeTimers();
  render(<ToastProvider><Actions /><ToastViewport /></ToastProvider>);
  fireEvent.click(screen.getByRole("button", { name: "Fail" }));
  fireEvent.click(screen.getByRole("button", { name: "Succeed" }));
  act(() => vi.advanceTimersByTime(6000));
  expect(screen.queryByText("Copied")).toBeNull();
  expect(screen.getByRole("alert").textContent).toContain("Write failed");
  fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
  expect(screen.queryByText("Write failed; retry is required")).toBeNull();
});
