// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { CardSkeleton, ChartSkeleton, TableSkeleton } from "./Skeletons";

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
