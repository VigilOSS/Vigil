// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TabBar } from "./TabBar";

afterEach(cleanup);

describe("TabBar", () => {
  it("exposes tab semantics and supports arrow-key navigation", () => {
    const onChange = vi.fn();
    render(<TabBar active="intel" onChange={onChange} />);

    const intel = screen.getByRole("tab", { name: "Intel" });
    expect(screen.getByRole("tablist", { name: "Engagement views" })).toBeTruthy();
    expect(intel.getAttribute("aria-selected")).toBe("true");
    expect(intel.getAttribute("tabindex")).toBe("0");

    fireEvent.keyDown(intel, { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith("findings");

    fireEvent.keyDown(intel, { key: "Home" });
    expect(onChange).toHaveBeenCalledWith("overview");
  });
});
