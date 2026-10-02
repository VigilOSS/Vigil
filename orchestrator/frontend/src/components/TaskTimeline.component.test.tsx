// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { TaskTimeline } from "./TaskTimeline";
import type { EventRecord } from "../lib/api";

afterEach(cleanup);
const activity: EventRecord = { id: -1, event_type: "activity.entry", phase: "", task_name: "operator", agent_name: "operator", summary: "Recorded command output", created_at: "2026-10-01T12:00:00Z" };

it("distinguishes a filtered lifecycle view from an engagement with no events", () => {
  render(<TaskTimeline engagementKey="one" events={[activity]} />);
  expect(screen.getByText("No lifecycle or decision events in the loaded history.")).toBeTruthy();
  expect(screen.queryByText("No activity yet.")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Include operational activity" }));
  expect(screen.getByText("Recorded command output", { exact: false })).toBeTruthy();
});

it("describes an empty loaded window without claiming complete history is absent", () => {
  render(<TaskTimeline engagementKey="one" events={[]} />);
  expect(screen.getByText("No events in the loaded history.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Open complete Audit log" })).toBeTruthy();
});
