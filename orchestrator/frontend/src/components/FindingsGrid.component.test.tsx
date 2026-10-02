// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import FindingsGrid from "./FindingsGrid";
import type { Derived } from "./FindingsTab";

vi.mock("ag-grid-react", () => ({ AgGridReact: ({ onModelUpdated, animateRows }: { onModelUpdated: (event: unknown) => void; animateRows?: boolean }) => (
  <button data-row-animation={String(animateRows)} onClick={() => onModelUpdated({ api: { forEachNodeAfterFilterAndSort: (visit: (node: unknown) => void) => {
    visit({ data: { slug: "VA-003" } });
    visit({ data: undefined });
    visit({ data: { slug: "VA-001" } });
  } } })}>Update displayed model</button>
) }));

afterEach(cleanup);

it("reports the grid's filtered and sorted record identities rather than source row order", () => {
  const report = vi.fn();
  render(<FindingsGrid rows={[] as Derived[]} selected={null} onOpen={() => {}} onOrderChange={report} />);
  fireEvent.click(screen.getByRole("button", { name: "Update displayed model" }));
  expect(report).toHaveBeenCalledExactlyOnceWith(["VA-003", "VA-001"]);
});

it("updates filtered rows without a second animated row-position transition", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  expect(screen.getByRole("button", { name: "Update displayed model" }).getAttribute("data-row-animation")).toBe("false");
});
