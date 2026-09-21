// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { EventRecord } from "../lib/api";
import { ActivityTab } from "./ActivityTab";

function event(id: number, eventType: string, summary: string): EventRecord {
  return {
    id,
    event_type: eventType,
    phase: "hunt",
    task_name: eventType.startsWith("task.") ? "code-vuln-hunter" : "hunt",
    agent_name: eventType.startsWith("task.") ? "code-vuln-hunter" : "operator",
    summary,
    created_at: `2026-09-12T12:00:0${Math.abs(id)}Z`,
  };
}

afterEach(cleanup);

describe("ActivityTab event timeline", () => {
  it("defaults to persisted lifecycle and decision events and explicitly includes inferred activity", () => {
    render(
      <ActivityTab
        engagementKey="demo key"
        events={[
          event(1, "finding.created", "Finding confirmed"),
          event(2, "phase.completed", "Hunt completed"),
          event(3, "task.started", "Persisted task started"),
          event(-4, "task.completed", "Hunter activity summary"),
        ]}
        sessions={[]}
      />,
    );

    expect(screen.getByText("Finding confirmed")).toBeTruthy();
    expect(screen.getByText("Hunt completed")).toBeTruthy();
    expect(screen.queryByText("Persisted task started")).toBeNull();
    expect(screen.queryByText("Hunter activity summary")).toBeNull();
    expect(screen.getAllByText("Persisted structured event").length).toBeGreaterThan(0);
    expect(screen.getByText("2026-09-12T12:00:01Z")).toBeTruthy();

    const includeActivity = screen.getByRole("button", { name: "Include operational activity" });
    expect(includeActivity.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(includeActivity);
    expect(includeActivity.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText("Persisted task started")).toBeTruthy();
    expect(screen.getByText("Hunter activity summary")).toBeTruthy();
    expect(screen.getByText("Inferred from activity")).toBeTruthy();
  });

  it("states the bounded history honestly and offers an Audit handoff", () => {
    render(
      <ActivityTab
        engagementKey="demo key"
        events={[event(1, "finding.created", "Finding confirmed")]}
        sessions={[]}
      />,
    );

    expect(screen.getByText("Events shows at most the latest 200 rows; earlier history may exist.")).toBeTruthy();
    const audit = screen.getByRole("link", { name: "Open complete Audit log" });
    expect(audit.getAttribute("href")).toBe("#/engagements/demo%20key?tab=log");
    expect(screen.getByRole("button", { name: "Lifecycle and decisions only" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "Sessions" }).getAttribute("aria-expanded")).toBe("false");
  });
});
