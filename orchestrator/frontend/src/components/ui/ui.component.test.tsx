// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ClearFiltersButton,
  EmptyState,
  FacetChipGroup,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  SegmentedControl,
  StatusPill,
  compareStatus,
  describeSort,
  statusEntry,
  statusOrder,
  type StatusDomain,
} from ".";

afterEach(cleanup);

const DOMAINS: StatusDomain[] = [
  "finding-workflow", "finding-verification", "finding-submission", "run", "run-health", "dispatch", "job", "command",
  "coverage", "surface", "intel-lead", "intel-cve", "intel-confidence", "liveness", "credential", "oast",
  "code-disposition", "code-queue", "submission", "submission-version", "proof-work", "proof-work-status",
  "receipt-health", "engagement", "remediation", "remediation-verification", "http-response", "code-file", "code-repo",
  "finding-source-snapshot",
];

describe("status vocabulary", () => {
  it("gives every listed value a sentence-case label and a styled tone", () => {
    for (const domain of DOMAINS) {
      for (const value of statusOrder(domain)) {
        const { label } = statusEntry(domain, value);
        expect(label.charAt(0), `${domain}:${value}`).toBe(label.charAt(0).toUpperCase());
        expect(label, `${domain}:${value}`).not.toMatch(/_/);
        // Each tone has a color and a glyph (ui.css, StatusPill).
        const { container, unmount } = render(<StatusPill domain={domain} value={value} />);
        expect(container.querySelector(".ui-status")?.getAttribute("data-tone"), `${domain}:${value}`).toMatch(/^(danger|warning|paused|progress|pending|info|success|neutral)$/);
        expect(container.querySelector(".ui-status svg"), `${domain}:${value}`).toBeTruthy();
        unmount();
      }
    }
  });

  it("labels the values tabs used to print raw", () => {
    expect(statusEntry("finding-workflow", "draft").label).toBe("Draft");
    expect(statusEntry("finding-verification", "pending_runtime_proof").label).toBe("Pending runtime proof");
    expect(statusEntry("finding-verification", "blocked").label).toBe("Blocked");
    expect(statusEntry("finding-submission", "withdrawn").label).toBe("Withdrawn");
    expect(statusEntry("engagement", "archived")).toMatchObject({ label: "Archived", tone: "neutral" });
    expect(statusEntry("surface", "administratively-closed").label).toBe("Administratively closed");
    expect(statusEntry("http-response", "4xx")).toMatchObject({ label: "Client error", tone: "warning" });
    expect(statusEntry("code-file", "classified").label).toBe("Risk-ranked, not queued");
    expect(statusEntry("code-repo", "context_built").label).toBe("Context built");
    expect(statusEntry("finding-source-snapshot", "stale")).toMatchObject({ label: "Source stale", tone: "warning" });
  });

  it("keeps an unlisted value visible as a neutral humanized label", () => {
    expect(statusEntry("command", "quarantined_by_host")).toEqual({ label: "Quarantined by host", tone: "neutral" });
    expect(statusEntry("engagement", "")).toEqual({ label: "Not recorded", tone: "neutral" });
  });

  it("orders statuses most urgent first, unlisted values last", () => {
    const sorted = ["archived", "zeta", "completed", "in_progress"].sort((a, b) => compareStatus("engagement", a, b));
    expect(sorted).toEqual(["in_progress", "completed", "archived", "zeta"]);
    expect(statusOrder("command")).toEqual(["failed", "timed_out", "killed", "lost", "running", "queued", "completed"]);
  });

  it("lists problems before open work and settled values last in every status domain", () => {
    // Confidence is a ranking, not an urgency order.
    const urgencyDomains = DOMAINS.filter((domain) => domain !== "intel-confidence");
    const band = (domain: StatusDomain, value: string) => {
      const { tone } = statusEntry(domain, value);
      return tone === "danger" || tone === "warning" ? 0 : tone === "success" || tone === "neutral" ? 2 : 1;
    };
    for (const domain of urgencyDomains) {
      const bands = statusOrder(domain).map((value) => band(domain, value));
      expect(bands, domain).toEqual([...bands].sort((a, b) => a - b));
    }
  });
});

describe("StatusPill", () => {
  it("renders the vocabulary label, tone and meaning", () => {
    render(<StatusPill domain="coverage" value="blocked" />);
    const pill = screen.getByText("Blocked").closest(".ui-status");
    expect(pill?.getAttribute("data-tone")).toBe("danger");
    expect(pill?.getAttribute("title")).toBe("Can't be tested with the current access or conditions.");
    expect(pill?.querySelector("svg")).toBeTruthy();
  });

  it("shows the reason as text beside the pill", () => {
    render(<StatusPill domain="run" value="partial" reason="2 open obligations" />);
    const group = screen.getByText("Partial").closest(".ui-status-group") as HTMLElement;
    expect(within(group).getByText("2 open obligations")).toBeTruthy();
  });

  it("accepts an explicit tone and label without a domain", () => {
    render(<StatusPill value="attention" tone="warning" label="Needs attention" size="sm" />);
    const pill = screen.getByText("Needs attention").closest(".ui-status");
    expect(pill?.getAttribute("data-tone")).toBe("warning");
    expect(pill?.classList.contains("ui-status-sm")).toBe(true);
  });
});

describe("PageHeader", () => {
  it("renders the title, purpose, counts and actions, skipping unknown counts", () => {
    render(
      <PageHeader
        title="Runs"
        purpose="Each run is one evidence-gathering session."
        stats={[{ value: 4800, label: "runs" }, { value: null, label: "running" }, { value: 12, label: "need attention", tone: "warning" }]}
        actions={<button type="button">Jump to…</button>}
      />,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Runs" })).toBeTruthy();
    expect(screen.getByText("Each run is one evidence-gathering session.")).toBeTruthy();
    const stats = screen.getByRole("list", { name: "Summary" });
    expect(within(stats).getAllByRole("listitem").map((item) => item.textContent)).toEqual(["4,800 runs", "12 need attention"]);
    expect(screen.getByRole("button", { name: "Jump to…" })).toBeTruthy();
  });

  it("hides while a record replaces the page", () => {
    render(<PageHeader title="Runs" purpose="Purpose." hidden />);
    expect(screen.queryByRole("heading", { name: "Runs" })).toBeNull();
  });
});

describe("ScopeToggle", () => {
  it("offers Needs attention and All with counts and the rule behind the scope", () => {
    const onChange = vi.fn();
    render(<ScopeToggle scope="attention" onChange={onChange} attentionCount={30} allCount={4800} attentionRule="Failed or timed-out runs." />);
    const attention = screen.getByRole("button", { name: /^Needs attention 30/ });
    expect(attention.getAttribute("aria-pressed")).toBe("true");
    expect(attention.getAttribute("title")).toBe("Failed or timed-out runs.");
    fireEvent.click(attention);
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "All 4,800" }));
    expect(onChange).toHaveBeenCalledWith("all");
  });

  it("marks counts taken over loaded rows only", () => {
    render(<ScopeToggle scope="all" onChange={vi.fn()} attentionCount={30} allCount={1000} partial attentionRule="Rule." />);
    expect(screen.getByRole("button", { name: "All 1,000+" })).toBeTruthy();
  });
});

describe("SegmentedControl", () => {
  it("presses exactly the current option", () => {
    render(<SegmentedControl label="HTTP view" value="inventory" onChange={vi.fn()} options={[{ value: "inventory", label: "Endpoint inventory", count: 3200 }, { value: "exchanges", label: "Captured exchanges" }]} />);
    const group = screen.getByRole("group", { name: "HTTP view" });
    expect(within(group).getAllByRole("button").map((button) => button.getAttribute("aria-pressed"))).toEqual(["true", "false"]);
  });
});

describe("EmptyState", () => {
  it("offers Clear filters only when filters hide the records", () => {
    const clear = vi.fn();
    const { rerender } = render(<EmptyState variant="filtered" title="No command runs match these filters." onClearFilters={clear} />);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(clear).toHaveBeenCalledOnce();
    rerender(<EmptyState variant="empty" title="No command runs recorded yet.">Agents record each tool call here.</EmptyState>);
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
    expect(screen.getByRole("status").getAttribute("data-variant")).toBe("empty");
  });
});

describe("FilterChip", () => {
  it("toggles as a pressed button with its count", () => {
    const onToggle = vi.fn();
    render(<FilterGroup label="Severity"><FilterChip label="High" color="var(--sev-high)" count={7} selected onToggle={onToggle} /></FilterGroup>);
    const chip = within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: "High 7" });
    expect(chip.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(chip);
    expect(onToggle).toHaveBeenCalledOnce();
  });

  it("marks counts taken over loaded rows only", () => {
    render(
      <FacetChipGroup label="Method" values={[{ value: "GET", count: 1200 }, { value: "POST", count: 3 }]} selected={new Set()} onToggle={vi.fn()} partial />,
    );
    const group = screen.getByRole("group", { name: "Method" });
    expect(within(group).getByRole("button", { name: "GET 1,200+" })).toBeTruthy();
    expect(within(group).getByRole("button", { name: "POST 3+" })).toBeTruthy();
  });

  it("carries a status chip's tone and meaning", () => {
    render(<FilterChip label="Timed out" status={{ domain: "command", value: "timed_out" }} selected={false} onToggle={vi.fn()} />);
    const chip = screen.getByRole("button", { name: "Timed out" });
    expect(chip.getAttribute("data-tone")).toBe("warning");
    expect(chip.getAttribute("title")).toBe("Stopped at its time limit.");
  });

  it("disables Clear filters when nothing is set", () => {
    const { rerender } = render(<ClearFiltersButton count={0} onClear={vi.fn()} />);
    expect((screen.getByRole("button", { name: "Clear filters" }) as HTMLButtonElement).disabled).toBe(true);
    rerender(<ClearFiltersButton count={3} onClear={vi.fn()} />);
    expect((screen.getByRole("button", { name: "Clear filters (3)" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("ResultsSummary", () => {
  it("names the shown count, the total and the order", () => {
    render(<ResultsSummary shown={18} total={25} noun="findings" sort={describeSort("Severity", "desc", "rank")} />);
    expect(screen.getByRole("status").textContent).toBe("18 of 25 findings · Sorted by Severity, most severe first");
  });

  it("names a status order by urgency", () => {
    expect(describeSort("Status", "desc", "status")).toBe("Status, most urgent first");
    expect(describeSort("Status", "asc", "status")).toBe("Status, least urgent first");
  });

  it("marks a windowed total", () => {
    render(<ResultsSummary shown={62} total={1000} partial noun="command runs" sort={describeSort("Started", "desc", "time")} />);
    expect(screen.getByRole("status").textContent).toBe("62 of 1,000+ command runs · Sorted by Started, newest first");
  });
});
