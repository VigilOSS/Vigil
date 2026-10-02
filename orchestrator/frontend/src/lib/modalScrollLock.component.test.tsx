// @vitest-environment jsdom
import { useRef } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useModalFocus } from "./modalScrollLock";

function Dialog({ name, close }: { name: string; close: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useModalFocus(ref, close);
  return <div ref={ref} role="dialog" aria-label={name} tabIndex={-1}><button>{name} first</button><button>{name} last</button></div>;
}
afterEach(cleanup);

it("recaptures escaped keyboard focus and returns to the opener", async () => {
  const view = render(<button>Opener</button>);
  const opener = screen.getByRole("button", { name: "Opener" });
  opener.focus();
  view.rerender(<><button>Opener</button><Dialog name="Detail" close={vi.fn()} /></>);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("dialog")));
  opener.focus();
  fireEvent.keyDown(document, { key: "Tab" });
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Detail first" }));
  view.rerender(<button>Opener</button>);
  expect(document.activeElement).toBe(opener);
});

it("only closes the top dialog on Escape and restores the underlying selection", async () => {
  const outerClose = vi.fn();
  const innerClose = vi.fn();
  const view = render(<Dialog name="Outer" close={outerClose} />);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("dialog")));
  const prior = screen.getByRole("button", { name: "Outer last" });
  prior.focus();
  view.rerender(<><Dialog name="Outer" close={outerClose} /><Dialog name="Inner" close={innerClose} /></>);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("dialog", { name: "Inner" })));
  fireEvent.keyDown(document, { key: "Escape" });
  expect(innerClose).toHaveBeenCalledOnce();
  expect(outerClose).not.toHaveBeenCalled();
  view.rerender(<Dialog name="Outer" close={outerClose} />);
  expect(document.activeElement).toBe(prior);
});

it("keeps background search shortcuts from moving focus outside an open dialog", async () => {
  const view = render(<><input aria-label="Background search" /><Dialog name="Detail" close={vi.fn()} /></>);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("dialog")));
  const detailControl = screen.getByRole("button", { name: "Detail last" });
  detailControl.focus();
  screen.getByLabelText("Background search").focus();
  expect(document.activeElement).toBe(detailControl);
  view.rerender(<input aria-label="Background search" />);
  screen.getByLabelText("Background search").focus();
  expect(document.activeElement).toBe(screen.getByLabelText("Background search"));
});

it("includes disclosure summaries but skips their closed content in the focus loop", async () => {
  function DisclosureDialog() {
    const ref = useRef<HTMLDivElement>(null);
    useModalFocus(ref, vi.fn());
    return <div ref={ref} role="dialog" tabIndex={-1}>
      <button>First control</button>
      <details><summary>Raw receipt</summary><button>Hidden copy</button></details>
    </div>;
  }
  render(<DisclosureDialog />);
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("dialog")));
  screen.getByRole("button", { name: "First control" }).focus();
  fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
  expect(document.activeElement).toBe(screen.getByText("Raw receipt"));
  fireEvent.keyDown(document, { key: "Tab" });
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "First control" }));
});
