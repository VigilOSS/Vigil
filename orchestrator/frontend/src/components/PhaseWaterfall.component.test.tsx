// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { PhaseWaterfall } from "./PhaseWaterfall";

afterEach(cleanup);

it("shows independent canonical tracks without inferring completion from event history", () => {
  const props = { currentPhase: "complete", trackState: { web: { phase: "complete", complete: true }, code: { phase: "hunt", complete: false } }, aggregateComplete: false };
  render(<PhaseWaterfall {...props} />);
  expect(screen.getByRole("heading", { name: "Enabled tracks" })).toBeTruthy();
  expect(screen.getByText("hunt")).toBeTruthy();
  expect(screen.getByText("Tracks in progress")).toBeTruthy();
  expect(screen.queryByText("Recon")).toBeNull();
});

it("reports unavailable track state and preserves a legacy phase literally", () => {
  render(<PhaseWaterfall currentPhase="legacy-phase" />);
  expect(screen.getByText(/Track state unavailable/)).toBeTruthy();
  expect(screen.getByText("legacy-phase")).toBeTruthy();
  expect(screen.queryByText("Recon")).toBeNull();
});
