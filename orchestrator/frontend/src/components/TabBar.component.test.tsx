// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TabBar } from "./TabBar";

afterEach(cleanup);

describe("TabBar", () => {
  it("exposes tab semantics and activates only on click, Enter or Space", () => {
    const onChange = vi.fn();
    render(<TabBar active="intel" onChange={onChange} />);

    const intel = screen.getByRole("tab", { name: "Intel" });
    expect(screen.getByRole("tablist", { name: "Engagement views" })).toBeTruthy();
    expect(intel.getAttribute("aria-selected")).toBe("true");
    expect(intel.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(intel, { key: "Home" });
    expect(onChange).not.toHaveBeenCalled();
    const overview = screen.getByRole("tab", { name: "Overview" });
    expect(document.activeElement).toBe(overview);
    fireEvent.click(overview);
    expect(onChange).toHaveBeenCalledExactlyOnceWith("overview");
  });

  it("moves focus through the rail in its visual top-to-bottom order without switching views", () => {
    const onChange = vi.fn();
    render(<TabBar active="overview" onChange={onChange} />);
    expect(screen.getByRole("tablist").getAttribute("aria-orientation")).toBe("vertical");
    const tabs = screen.getAllByRole("tab");
    const keys = tabs.map((tab) => tab.id.replace("workspace-tab-", ""));
    expect(new Set(keys).size).toBe(tabs.length);
    tabs.forEach((tab, index) => {
      fireEvent.keyDown(tab, { key: "ArrowDown" });
      expect(document.activeElement).toBe(tabs[(index + 1) % tabs.length]);
      fireEvent.keyDown(tab, { key: "ArrowUp" });
      expect(document.activeElement).toBe(tabs[(index - 1 + tabs.length) % tabs.length]);
    });
    fireEvent.keyDown(tabs[3], { key: "End" });
    expect(document.activeElement).toBe(tabs.at(-1));
    expect(onChange).not.toHaveBeenCalled();
  });

  it("collapses into a menu button that names the open view and closes after a choice", () => {
    const onChange = vi.fn();
    render(<TabBar active="coverage" onChange={onChange} badges={{ coverage: { text: "1,441 open", label: "1,441 coverage items still open" } }} />);
    const toggle = screen.getByRole("button", { name: /^View: Coverage/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(screen.getByRole("tab", { name: "Runs" }));
    expect(onChange).toHaveBeenCalledWith("runs");
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    fireEvent.keyDown(screen.getByRole("tab", { name: "Runs" }), { key: "Escape" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(toggle);
  });

  it("moves focus into the opened menu and closes it on Escape from the menu button", () => {
    render(<TabBar active="coverage" onChange={vi.fn()} />);
    const toggle = screen.getByRole("button", { name: /^View: Coverage/ });
    toggle.focus();
    fireEvent.click(toggle);
    // The open view's tab takes focus, so the arrow keys walk the menu at once.
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: "Coverage" }));
    toggle.focus();
    fireEvent.keyDown(toggle, { key: "Escape" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(toggle);
  });

  it("groups deliverables, target knowledge, execution, and record views", () => {
    render(<TabBar active="overview" onChange={vi.fn()} />);
    const groupOf = (name: string) => screen.getByRole("tab", { name }).parentElement?.querySelector(".workspace-nav-label")?.textContent ?? null;
    expect(screen.getAllByRole("tab")[0].textContent).toBe("Overview");
    expect(groupOf("Overview")).toBeNull();
    for (const name of ["Findings", "Proof work", "Submissions"]) expect(groupOf(name)).toBe("Deliverables");
    for (const name of ["Intel", "Surfaces", "HTTP", "Coverage", "Code"]) expect(groupOf(name)).toBe("Target");
    for (const name of ["Runs", "Commands", "OAST"]) expect(groupOf(name)).toBe("Execution");
    for (const name of ["Activity", "Files"]) expect(groupOf(name)).toBe("Record");
  });

  it("shows each badge's short text and names what it counts", () => {
    render(<TabBar active="overview" onChange={vi.fn()} badges={{ coverage: { text: "1,441 open", label: "1,441 coverage items still open" } }} />);
    const coverage = screen.getByRole("tab", { name: "Coverage 1,441 coverage items still open" });
    expect(coverage.querySelector(".tab-count")?.getAttribute("title")).toBe("1,441 coverage items still open");
    expect(coverage.querySelector("[aria-hidden='true']")?.textContent).toBe("1,441 open");
    expect(screen.getByRole("tab", { name: "Intel" }).querySelector(".tab-count")).toBeNull();
  });
});
