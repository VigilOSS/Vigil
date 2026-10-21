// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CoverageFacetMenu } from "./CoverageFacetMenu";

afterEach(cleanup);

const hosts = {
  values: [
    { value: "shop.acme.example", count: 12_000 },
    { value: "api.acme.example", count: 8_411 },
  ],
  distinct: 3,
  omitted_count: 4,
};

describe("CoverageFacetMenu", () => {
  it("lists a typed value that is filtering the items, so it can be unchecked from the menu", () => {
    const onToggle = vi.fn();
    render(
      <CoverageFacetMenu
        label="Host"
        group={hosts}
        active={["rare.acme.example"]}
        formatValue={(value) => value}
        onToggle={onToggle}
        allowCustom={(typed) => typed.trim().toLowerCase() || null}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Host/ }));
    const panel = screen.getByRole("group", { name: "Host filter" });
    const custom = within(panel).getByRole("checkbox", { name: /rare\.acme\.example/ }) as HTMLInputElement;
    expect(custom.checked).toBe(true);
    fireEvent.click(custom);
    expect(onToggle).toHaveBeenCalledWith("rare.acme.example");
  });
});
