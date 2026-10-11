// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type {
  AssessmentCoverageItem,
  AssessmentService,
  AssessmentSummary,
  AssessmentTarget,
} from "../lib/api";
import { CoverageTab } from "./CoverageTab";

const target: AssessmentTarget = {
  id: 1,
  identity: "api.example.test",
  kind: "host",
  host: "api.example.test",
  ip_address: null,
  hostname: "api.example.test",
  notes: "",
  discovered_by: "recon",
  created_at: "2026-09-20T10:00:00Z",
  updated_at: "2026-09-20T10:00:00Z",
};

const service: AssessmentService = {
  id: 2,
  target_id: 1,
  endpoint: "https://api.example.test",
  port: 443,
  protocol: "https",
  service: "api",
  state: "open",
  coverage_status: "partial",
  banner: "",
  notes: "",
  discovered_by: "recon",
  created_at: "2026-09-20T10:00:00Z",
  updated_at: "2026-09-20T10:00:00Z",
};

const item: AssessmentCoverageItem = {
  id: 3,
  request_variant_id: 44,
  service_id: 2,
  auth_context: "member",
  input_slot: "query:id",
  attack_family: "idor",
  status: "blocked",
  notes: "Blocked by missing second account; retry after provisioning.",
  created_at: "2026-09-20T10:00:00Z",
  updated_at: "2026-09-21T12:30:00Z",
  method: "GET",
  canonical_url: "https://api.example.test/orders?id=1",
  service_endpoint: "https://api.example.test",
  service_name: "api",
};

const summary = {
  coverage_statuses: {
    pending: 1,
    queued: 1,
    deferred: 1,
    covered: 1,
    not_applicable: 1,
    blocked: 1,
  },
  open_coverage_items: [{
    status: "blocked",
    input_slot: "query:id",
    attack_family: "idor",
    auth_context: "member",
    updated_at: item.updated_at,
    method: "GET",
    canonical_url: item.canonical_url,
  }],
  service_coverage_gaps: [{
    endpoint: service.endpoint,
    service: service.service,
    coverage_status: "partial",
    updated_at: service.updated_at,
  }],
} as unknown as AssessmentSummary;

afterEach(cleanup);

describe("CoverageTab", () => {
  it("groups and filters by the stored canonical host when its service is not loaded", () => {
    render(<CoverageTab engagementKey="demo" summary={summary} targets={[]} services={[]} coverageItems={[item]} />);
    fireEvent.click(screen.getByRole("button", { name: /^Full ledger/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search coverage ledger" }), { target: { value: "host:api.example.test" } });
    const host = screen.getByRole("button", { name: /api\.example\.test/i });
    fireEvent.click(host);
    expect(screen.getByRole("button", { name: /GET.*orders.*idor/i })).toBeTruthy();
    expect(screen.queryByText("No coverage items match the current filters.")).toBeNull();
  });
  it("shows actionable debt first and retains an accessible full ledger", () => {
    render(
      <CoverageTab
        engagementKey="demo engagement"
        summary={summary}
        targets={[target]}
        services={[service]}
        coverageItems={[item]}
      />,
    );

    expect(screen.getByRole("button", { name: /^Needs action/ }).getAttribute("aria-pressed")).toBe("true");
    for (const status of ["pending", "queued", "deferred", "covered", "not applicable", "blocked"]) {
      expect(screen.getByText(new RegExp(`${status}: 1`, "i"))).toBeTruthy();
    }

    fireEvent.click(screen.getByRole("button", { name: /^Full ledger/ }));
    const host = screen.getByRole("button", { name: /api\.example\.test/i });
    expect(host.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(host);
    expect(host.getAttribute("aria-expanded")).toBe("true");

    const row = screen.getByRole("button", { name: /GET.*orders.*idor/i });
    expect(row.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(row);
    expect(screen.getByText(/Blocked by missing second account/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open request variant #44" }).getAttribute("href")).toBe(
      "#/engagements/demo%20engagement?tab=http&request=44",
    );
    expect(screen.getByText(/Updated/)).toBeTruthy();

    const search = screen.getByRole("searchbox", { name: "Search coverage ledger" });
    expect(search.getAttribute("placeholder")).not.toMatch(/payload/i);
    fireEvent.change(search, { target: { value: "host:no-match.example" } });
    expect(screen.queryByRole("button", { name: /api\.example\.test/i })).toBeNull();
    expect(screen.getByText("No coverage items match the current filters.")).toBeTruthy();
  });

  it("labels loaded rows honestly when the summary is unavailable", () => {
    render(
      <CoverageTab
        engagementKey="demo"
        summary={null}
        targets={[target]}
        services={[service]}
        coverageItems={[item]}
      />,
    );

    expect(screen.getByRole("status").textContent).toMatch(
      /Summary unavailable.*1 loaded row.*totals.*unknown/i,
    );
    expect(screen.queryByText("No coverage data recorded yet.")).toBeNull();
    expect(screen.queryByText("No coverage debt in the available summary.")).toBeNull();
    expect(screen.getByText(/Coverage debt summary unavailable/)).toBeTruthy();
  });
});
