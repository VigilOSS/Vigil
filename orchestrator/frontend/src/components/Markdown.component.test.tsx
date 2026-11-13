// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { MarkdownBlock } from "./Markdown";

afterEach(cleanup);

describe("MarkdownBlock task lists", () => {
  it("names each task checkbox by its state", () => {
    render(<MarkdownBlock text={"- [x] Scope confirmed\n- [ ] Report drafted"} />);
    const boxes = screen.getAllByRole("checkbox");
    expect(boxes.map((box) => [box.getAttribute("aria-label"), (box as HTMLInputElement).checked])).toEqual([
      ["Done", true],
      ["Not done", false],
    ]);
  });
});
