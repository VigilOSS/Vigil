// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SeverityDonut } from "./SeverityDonut";
import { SeverityMiniBar } from "./SeverityMiniBar";
import { SummaryStatBar } from "./SummaryStatBar";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("exposes exact severity counts when the chart has no visual legend", () => {
  vi.stubGlobal("requestAnimationFrame", () => 1);
  vi.stubGlobal("cancelAnimationFrame", () => {});
  render(<SeverityDonut counts={{ high: 2, info: 1 }} />);
  expect(screen.getByRole("img").getAttribute("aria-label")).toContain("high: 2");
  expect(screen.getByRole("img").getAttribute("aria-label")).toContain("info: 1");
});

it("keeps the miniature distribution and summary counts readable without color", () => {
  render(<><SeverityMiniBar counts={{ high: 2, info: 1 }} /><SummaryStatBar items={[{ label: "Findings", value: 3 }]} /></>);
  expect(screen.getByRole("img").getAttribute("aria-label")).toContain("high: 2");
  expect(screen.getByText("Findings")).toBeTruthy();
  expect(screen.getByText("3")).toBeTruthy();
});
