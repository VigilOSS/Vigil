// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listActivityEntries, type ActivityEntry } from "../lib/api";
import { LogTab } from "./LogTab";

vi.mock("../lib/api", () => ({ listActivityEntries: vi.fn() }));

const entry = (id: number): ActivityEntry => ({
  id,
  engagement_id: 1,
  occurred_at: `2026-09-12T00:00:0${id}Z`,
  actor_kind: "operator",
  actor_name: "operator",
  title: `Entry ${id}`,
  action: "reviewed",
  result: "complete",
  artifact_ref: "",
  body_markdown: "",
  metadata: {},
  created_at: `2026-09-12T00:00:0${id}Z`,
  updated_at: `2026-09-12T00:00:0${id}Z`,
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("LogTab pagination", () => {
  it("loads the next bounded activity page without replacing earlier entries", async () => {
    vi.mocked(listActivityEntries)
      .mockResolvedValueOnce({ total: 2, items: [entry(2)] })
      .mockResolvedValueOnce({ total: 2, items: [entry(1)] });

    render(<LogTab engagementKey="demo" />);
    expect(await screen.findByText("Entry 2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load more activity" }));

    expect(await screen.findByText("Entry 1")).toBeTruthy();
    expect(screen.getByText("Entry 2")).toBeTruthy();
    await waitFor(() => {
      expect(listActivityEntries).toHaveBeenLastCalledWith(
        "demo",
        expect.objectContaining({ limit: 100, offset: 1 }),
      );
    });
  });

  it("refetches on revision without losing the mounted filter state", async () => {
    vi.mocked(listActivityEntries)
      .mockResolvedValueOnce({ total: 1, items: [entry(1)] })
      .mockResolvedValue({ total: 1, items: [entry(2)] });

    const { rerender } = render(<LogTab engagementKey="demo" refreshVersion={0} />);
    expect(await screen.findByText("Entry 1")).toBeTruthy();

    fireEvent.change(screen.getByRole("combobox", { name: "Actor" }), { target: { value: "agent" } });
    await waitFor(() => {
      expect(listActivityEntries).toHaveBeenLastCalledWith(
        "demo",
        expect.objectContaining({ actor_kind: "agent" }),
      );
    });

    rerender(<LogTab engagementKey="demo" refreshVersion={1} />);
    expect(screen.getByRole<HTMLSelectElement>("combobox", { name: "Actor" }).value).toBe("agent");
    await waitFor(() => {
      expect(listActivityEntries).toHaveBeenLastCalledWith(
        "demo",
        expect.objectContaining({ actor_kind: "agent", limit: 100 }),
      );
    });
  });

  it("defaults to meaningful narrative activity while retaining all raw hook and Bash entries", async () => {
    vi.mocked(listActivityEntries).mockResolvedValue({
      total: 3,
      items: [
        entry(1),
        { ...entry(2), actor_kind: "hook", title: "Hook fired" },
        { ...entry(3), title: "Bash command completed", action: "Bash" },
      ],
    });

    render(<LogTab engagementKey="demo" refreshVersion={0} />);

    expect(await screen.findByText("Entry 1")).toBeTruthy();
    expect(screen.queryByText("Hook fired")).toBeNull();
    expect(screen.queryByText("Bash command completed")).toBeNull();
    expect(screen.getByText(/narrative activity/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: /view structured events/i })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /all raw activity/i }));
    expect(screen.getByText("Hook fired")).toBeTruthy();
    expect(screen.getByText("Bash command completed")).toBeTruthy();
  });

  it("renders compact labeled verbatim details with identity, timing, and actor provenance", async () => {
    vi.mocked(listActivityEntries).mockResolvedValue({
      total: 1,
      items: [{
        ...entry(7),
        actor_kind: "agent",
        actor_name: "vuln-analyst",
        occurred_at: "2026-09-12T00:00:01Z",
        created_at: "2026-09-12T00:00:09Z",
        action: "ran --payload '$RAW'",
        result: "exit=2; unchanged",
        body_markdown: "# Verbatim\n`token=$RAW`",
      }],
    });

    render(<LogTab engagementKey="demo" refreshVersion={0} />);

    expect(await screen.findByText("Entry #7")).toBeTruthy();
    expect(screen.getByText("Occurred").parentElement?.textContent).toContain("2026-09-12T00:00:01Z");
    expect(screen.getByText("Recorded").parentElement?.textContent).toContain("2026-09-12T00:00:09Z");
    expect(screen.getAllByText("Actor")[1].parentElement?.textContent).toContain("agent · vuln-analyst");
    expect(screen.getByText("Action").parentElement?.textContent).toContain("ran --payload '$RAW'");
    expect(screen.getByText("Result").parentElement?.textContent).toContain("exit=2; unchanged");

    const details = screen.getByRole("button", { name: /show body details/i });
    expect(details.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(details);
    expect(details.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText(/token=\$RAW/)).toBeTruthy();
  });

  it("deep-links only verified metadata relation shapes and keeps malformed metadata copyable", async () => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    vi.mocked(listActivityEntries).mockResolvedValue({
      total: 2,
      items: [
        { ...entry(8), metadata: { finding_slug: "VIGIL-42", request_variant_id: 19 } },
        { ...entry(9), metadata: { finding_slug: "../../bad", request_variant_id: "19" } },
      ],
    });

    render(<LogTab engagementKey="demo key" refreshVersion={0} />);

    const finding = await screen.findByRole("link", { name: /finding VIGIL-42/i });
    expect(finding.getAttribute("href")).toBe("#/engagements/demo%20key?tab=findings&finding=VIGIL-42");
    expect(screen.getByRole("link", { name: /request variant 19/i }).getAttribute("href"))
      .toBe("#/engagements/demo%20key?tab=http&request=19");
    expect(screen.queryByRole("link", { name: /bad/i })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Copy metadata for entry 9" }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining("../../bad"));
  });

  it("refreshes on refreshVersion changes without resetting the selected lens", async () => {
    vi.mocked(listActivityEntries)
      .mockResolvedValueOnce({ total: 1, items: [{ ...entry(1), actor_kind: "hook", title: "Hook 1" }] })
      .mockResolvedValueOnce({ total: 1, items: [{ ...entry(2), actor_kind: "hook", title: "Hook 2" }] });

    const view = render(<LogTab engagementKey="demo" refreshVersion={0} />);
    fireEvent.click(await screen.findByRole("button", { name: /all raw activity/i }));
    expect(screen.getByText("Hook 1")).toBeTruthy();

    view.rerender(<LogTab engagementKey="demo" refreshVersion={1} />);
    expect(await screen.findByText("Hook 2")).toBeTruthy();
    expect(screen.getByRole("button", { name: /all raw activity/i }).getAttribute("aria-pressed")).toBe("true");
  });
});
