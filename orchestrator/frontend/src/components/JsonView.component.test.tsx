// @vitest-environment jsdom

import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { JsonView } from "./JsonView";

afterEach(cleanup);

describe("exact JSON rendering", () => {
  it("preserves repeated noncyclic objects in every location", () => {
    const receipt = { authorization: "Bearer full-token", command: "curl --header 'Cookie: exact-cookie'" };
    const value = { original: receipt, copies: [receipt, { receipt }] };
    const { container } = render(<JsonView value={value} />);
    expect(container.querySelector("pre")?.textContent).toBe(JSON.stringify(value, null, 2));
  });

  it("marks only an ancestor cycle while preserving separate repeated branches", () => {
    const receipt: Record<string, unknown> = { token: "full-token" };
    receipt.self = receipt;
    const { container } = render(<JsonView value={{ original: receipt, repeated: receipt }} />);
    expect(container.querySelector("pre")?.textContent).toBe(JSON.stringify({ original: { token: "full-token", self: "[Circular]" }, repeated: { token: "full-token", self: "[Circular]" } }, null, 2));
  });
});
