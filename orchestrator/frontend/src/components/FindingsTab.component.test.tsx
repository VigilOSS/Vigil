// @vitest-environment jsdom

// The PoC pane renders the operator's own captures. Two properties are pinned
// here and neither is styling: the page shows the recorded bytes, and the copy
// chip beside them hands back the same bytes. A capture that the pane rewrites
// is a capture the reader cannot check against the target, and it puts the page
// out of step with lib/findingMarkdown.ts — which fences these same fields
// verbatim (AGENTS.md: never degrade the operator's own data; ADR 0019).

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PocPane } from "./FindingsTab";
import type { Derived } from "./FindingsTab";

const writeText = vi.fn();

function derived(over: Partial<Derived>): Derived {
  return { slug: "VA-001", title: "T", references: [], links: [], ...over } as unknown as Derived;
}

function renderPane(over: Partial<Derived>) {
  return render(<PocPane d={derived(over)} proseMode="rendered" toast={() => {}} />);
}

beforeEach(() => {
  writeText.mockReset();
  Object.defineProperty(window.navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

afterEach(cleanup);

describe("PocPane evidence", () => {
  it("renders and copies a capture byte for byte", () => {
    // Leading and trailing whitespace is the finding on a padding or
    // header-stripping bug, and the clipboard has to carry it.
    const capture = "\n  leading and trailing whitespace is the finding   \n\n";
    renderPane({ evidence: capture });

    const copy = screen.getByRole("button", { name: /copy evidence/i });
    copy.click();
    expect(writeText).toHaveBeenCalledWith(capture);
    expect(screen.getByText(capture.trim()).textContent).toBe(capture);
  });

  it("shows a capture that is nothing but whitespace", () => {
    // The PoC tab badge counts `d.evidence` on plain truthiness, so a
    // whitespace-only capture was counted and then rendered as nothing at all —
    // the section, its heading and its copy chip all disappeared. A blank or
    // padded response body IS the proof on a whitespace-sensitive finding.
    const { container } = renderPane({ evidence: "   " });

    expect(screen.getByText("Evidence")).toBeTruthy();
    const pre = container.querySelector("pre.pre.resp");
    expect(pre?.textContent).toBe("   ");
    screen.getByRole("button", { name: /copy evidence/i }).click();
    expect(writeText).toHaveBeenCalledWith("   ");
  });
});

describe("PocPane request", () => {
  it("shows the recorded method in the case it was recorded", () => {
    // A case-sensitive-routing probe records `get` on purpose. Upper-casing it
    // showed a request the finding never made, and disagreed with this
    // component's own Copy-as-Markdown, which keeps the case (see
    // lib/findingMarkdown.test.ts).
    const { container } = renderPane({
      poc_request: { method: "get", url: "https://t.example/x" },
    });

    const pre = container.querySelector("pre.pre.req");
    expect(pre?.textContent).toContain("get https://t.example/x");
    expect(pre?.textContent).not.toContain("GET https://t.example/x");
  });
});
