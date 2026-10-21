// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const appStyles = readFileSync(resolve("src/app.css"), "utf8");
const findingStyles = readFileSync(resolve("src/styles/findings.css"), "utf8");
const uiStyles = readFileSync(resolve("src/styles/ui.css"), "utf8");
const workspaceStyles = readFileSync(resolve("src/styles/workspace.css"), "utf8");
const startup = readFileSync(resolve("src/main.tsx"), "utf8");
const baseImportIndex = startup.search(/import\s+["']\.\/app\.css["']/);
const appImportIndex = startup.search(/import\s+App\s+from/);
const baseFirst = baseImportIndex >= 0 && appImportIndex >= 0 && baseImportIndex < appImportIndex;

afterEach(() => {
  cleanup();
  document.documentElement.removeAttribute("data-theme");
});

// JSDOM does not evaluate media queries; apply the matching source rules explicitly.
function responsiveStyles(width: number): string {
  const style = document.createElement("style");
  style.textContent = findingStyles;
  document.head.append(style);
  const rules = Array.from(style.sheet!.cssRules).flatMap((rule) => {
    if (rule.type !== CSSRule.MEDIA_RULE) return [];
    const media = rule as CSSMediaRule;
    const maximum = media.conditionText.match(/max-width:\s*(\d+)px/);
    return maximum && width <= Number(maximum[1]) ? Array.from(media.cssRules, nested => nested.cssText) : [];
  });
  style.remove();
  return rules.join("\n");
}

// JSDOM does not resolve var() in computed colors; use the actual selected root tokens.
function resolvedThemeStyles(styles: string): string {
  const style = document.createElement("style");
  style.textContent = styles;
  document.head.append(style);
  const tokens = getComputedStyle(document.documentElement);
  const resolved = styles.replace(/var\((--[\w-]+)\)/g, (value, token) => tokens.getPropertyValue(token).trim() || value);
  style.remove();
  return resolved;
}

function layout(width?: number, resolveTheme = false) {
  // The shared primitives' sheet loads before the findings sheet (the shell
  // imports the primitives first); JSDOM cascades by order, not specificity.
  const styles = (baseFirst ? appStyles + uiStyles + findingStyles + workspaceStyles : uiStyles + findingStyles + workspaceStyles + appStyles) + (width === undefined ? "" : responsiveStyles(width));
  return render(<>
    <style>{resolveTheme ? resolvedThemeStyles(styles) : styles}</style>
    <div className="findings-redesign findings-workspace">
      <div className="filter-row" data-testid="filters">
        <div className="ui-filter-group" role="group" aria-label="Severity"><span className="ui-filter-label">Severity</span><button className="ui-chip" aria-pressed="false">High</button><button className="ui-chip" aria-pressed="true">Critical</button></div>
        <div className="ui-filter-group" role="group" aria-label="Workflow"><span className="ui-filter-label">Workflow</span><button className="ui-chip" aria-pressed="false">Draft</button></div>
        <div className="ui-filter-group" role="group" aria-label="Verification"><span className="ui-filter-label">Verification</span><button className="ui-chip" aria-pressed="false">Verified</button></div>
        <button className="ui-clear-filters" disabled>Clear filters</button>
      </div>
      <div className="findings-shell" data-testid="shell">
        <section className="list-panel" data-testid="queue">
          <div className="grouping-status">1 finding visible<div className="grouping-status-meta"><span className="tag" data-testid="group-count">10 engagement root-cause groups</span></div></div>
          <div className="grouped-findings"><div className="standalone-group" data-testid="group">
            <button className="mini-finding-row" data-testid="finding-row"><span className="sev-dot" /><span className="mini-main"><strong data-testid="title">Matching finding with its full authored title</strong><span className="meta-text">https://target.example/recorded-location</span></span><span className="mini-badges" data-testid="badges"><span className="pill" data-testid="workflow">False positive</span><span className="pill" data-testid="verification">Unreviewed</span></span><span className="finding-row-time" data-testid="row-time"><span className="finding-row-time-label">Changed</span><time className="timestamp">3h ago</time></span></button>
          </div></div>
        </section>
      </div>
      <div className="cmd-list" data-testid="palette-list">
        <button className="cmd-item" data-testid="palette-result"><span className="sev-dot" /><span data-testid="palette-main"><span className="cmd-title" data-testid="palette-title">Finding title</span><span className="cmd-sub" data-testid="palette-subtitle">finding-slug · high</span></span><span className="cmd-sub" data-testid="palette-location">https://target.example/full-recorded-location?token=verbatim-recorded-token</span></button>
        <button className="cmd-item is-active" data-testid="active-palette-result">Active finding</button>
      </div>
      <button className="qa-btn" data-testid="idle-action">Jump to finding</button>
      <button className="qa-btn primary" data-testid="primary-action">Primary action</button>
      <span className="search-kbd" data-testid="keyboard-hint">esc</span>
    </div>
  </>);
}

it("keeps a short finding queue content-sized", () => {
  layout();
  expect(Number.parseFloat(getComputedStyle(screen.getByTestId("shell")).minHeight)).toBe(0);
  expect(getComputedStyle(screen.getByTestId("queue")).display).toBe("block");
});

it("lets the finding workspace styles override shared base styles at startup", () => {
  expect(baseImportIndex).toBeGreaterThanOrEqual(0);
  expect(appImportIndex).toBeGreaterThanOrEqual(0);
  layout();
  expect(getComputedStyle(screen.getByTestId("queue")).display).toBe("block");
  expect(getComputedStyle(screen.getByTestId("group")).borderRadius).toBe("0");
});

it("keeps active and inactive filter typography dimensionally identical", () => {
  layout();
  expect(getComputedStyle(screen.getByRole("button", { name: "High" })).fontWeight).toBe(getComputedStyle(screen.getByRole("button", { name: "Critical" })).fontWeight);
});

it("gives finding filter groups independent tracks rather than wrapping whole groups on selection", () => {
  layout();
  expect(getComputedStyle(screen.getByTestId("filters")).display).toBe("grid");
  expect(getComputedStyle(screen.getByRole("button", { name: "Clear filters" })).minWidth).toBe("9rem");
});

it("keeps narrow finding text in a flexible track with all badges and the row time below it", () => {
  layout(390);
  expect(getComputedStyle(screen.getByTestId("finding-row")).gridTemplateColumns).toBe("auto minmax(0, 1fr)");
  expect(getComputedStyle(screen.getByTestId("badges")).gridColumn).toBe("2");
  expect(getComputedStyle(screen.getByTestId("row-time")).gridColumn).toBe("2");
  expect(getComputedStyle(screen.getByTestId("workflow")).whiteSpace).toBe("normal");
  expect(getComputedStyle(screen.getByTestId("title")).whiteSpace).toBe("normal");
});

it("lets narrow grouping counts wrap instead of clipping their recorded scope", () => {
  layout(390);
  expect(getComputedStyle(screen.getByTestId("group-count")).whiteSpace).toBe("normal");
  expect(getComputedStyle(screen.getByTestId("group-count")).overflowWrap).toBe("anywhere");
});

it("retains the dense four-column finding row, with an aligned time column, at full desktop width", () => {
  layout(2560);
  expect(getComputedStyle(screen.getByTestId("finding-row")).gridTemplateColumns).toBe("auto minmax(0, 1fr) auto 8.5rem");
  expect(getComputedStyle(screen.getByTestId("row-time")).whiteSpace).toBe("nowrap");
});

it("resets native palette buttons while preserving their active background", () => {
  layout();
  const result = getComputedStyle(screen.getByTestId("palette-result"));
  expect(result.width).toBe("100%");
  expect(result.borderTopWidth).toBe("0px");
  expect(result.textAlign).toBe("left");
  expect(result.backgroundColor).toBe("rgba(0, 0, 0, 0)");
  expect(result.display).toBe("grid");
  expect(result.gridTemplateColumns).toBe("12px minmax(0, 1fr)");
  expect(getComputedStyle(screen.getByTestId("active-palette-result")).backgroundColor).toBe("rgba(23, 53, 76, 0.08)");
  screen.getByTestId("palette-result").closest(".findings-workspace")!.classList.remove("findings-workspace");
  expect(getComputedStyle(screen.getByTestId("palette-result")).width).toBe("100%");
  expect(getComputedStyle(screen.getByTestId("palette-title")).display).toBe("block");
});

it("keeps native palette title and subtitle on separate lines", () => {
  layout();
  expect(getComputedStyle(screen.getByTestId("palette-title")).display).toBe("block");
  expect(getComputedStyle(screen.getByTestId("palette-subtitle")).display).toBe("block");
});

it("gives palette titles the flexible track and wraps complete locations beneath them", () => {
  layout();
  expect(getComputedStyle(screen.getByTestId("palette-result")).gridTemplateColumns).toBe("12px minmax(0, 1fr)");
  expect(getComputedStyle(screen.getByTestId("palette-main")).minWidth).toBe("0");
  const location = getComputedStyle(screen.getByTestId("palette-location"));
  expect(location.gridColumn).toBe("2");
  expect(location.overflowWrap).toBe("anywhere");
  expect(location.whiteSpace).toBe("normal");
  expect(screen.getByTestId("palette-location").textContent).toBe("https://target.example/full-recorded-location?token=verbatim-recorded-token");
  expect(getComputedStyle(screen.getByTestId("palette-list")).minWidth).toBe("0");
});

it.each(["light", "dark"])("uses %s theme surfaces for idle actions and keyboard hints and keeps primary action text legible", (theme) => {
  document.documentElement.dataset.theme = theme;
  layout(undefined, true);
  expect(getComputedStyle(screen.getByTestId("idle-action")).backgroundColor).toBe(theme === "dark" ? "rgb(27, 35, 45)" : "rgb(255, 255, 255)");
  expect(getComputedStyle(screen.getByTestId("keyboard-hint")).backgroundColor).toBe(theme === "dark" ? "rgb(20, 26, 34)" : "rgb(247, 249, 251)");
  const primary = getComputedStyle(screen.getByTestId("primary-action"));
  expect(primary.backgroundColor).toBe(theme === "dark" ? "rgb(121, 169, 212)" : "rgb(23, 53, 76)");
  // Dark text on the light dark-theme accent (7.6:1); white on the light-theme accent.
  expect(primary.color).toBe(theme === "dark" ? "rgb(13, 17, 23)" : "rgb(255, 255, 255)");
  const tokens = getComputedStyle(document.documentElement);
  expect(tokens.getPropertyValue("--panel-strong").trim()).toBe(theme === "dark" ? "#1b232d" : "#fff");
  expect(tokens.getPropertyValue("--panel-soft").trim()).toBe(theme === "dark" ? "#141a22" : "#f7f9fb");
});
