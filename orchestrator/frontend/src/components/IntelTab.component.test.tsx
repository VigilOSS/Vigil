// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import {
  getIntelReadiness,
  intelByUrl,
  listIntel,
  listIntelCredentials,
  searchIntel,
} from "../lib/api";
import { IntelTab } from "./IntelTab";

vi.mock("../lib/api", () => ({
  getIntelReadiness: vi.fn(),
  intelByUrl: vi.fn(),
  listIntel: vi.fn(),
  listIntelCredentials: vi.fn(),
  searchIntel: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
    entity_type: entityType,
    total: 0,
    items: [],
  }));
  vi.mocked(listIntelCredentials).mockResolvedValue([]);
  vi.mocked(getIntelReadiness).mockResolvedValue({
    applicable: true,
    engagement_type: "red",
    open_high_cves: [],
    open_leads: [],
    exploited_unlinked_cves: [],
    dangling_links: [],
  });
  vi.mocked(searchIntel).mockResolvedValue([]);
  vi.mocked(intelByUrl).mockResolvedValue({
    domains: [],
    services: [],
    surfaces: [],
    request_variants: [],
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("IntelTab deep links", () => {
  it("opens the exact typed record after its entity cache loads", async () => {
    const onInitialRecordConsumed = vi.fn();
    const hashChange = vi.fn();
    window.addEventListener("hashchange", hashChange);
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
      entity_type: entityType,
      total: entityType === "note" ? 1 : 0,
      items: entityType === "note"
        ? [{ id: 42, title: "OAuth boundary research", body_markdown: "Research body" } as never]
        : [],
    }));
    vi.mocked(listIntelCredentials).mockResolvedValue([]);

    const view = render(
      <ToastProvider>
        <IntelTab
          engagementKey="demo"
          summary={{ counts: { notes: 1 } }}
          initialIntelType="note"
          initialIntelId={42}
          onInitialRecordConsumed={onInitialRecordConsumed}
        />
      </ToastProvider>,
    );

    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "OAuth boundary research" })).toBeTruthy();
    expect(onInitialRecordConsumed).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: /close detail/i }));
    expect(hashChange).toHaveBeenCalledOnce();
    view.rerender(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: { notes: 1 } }} />
      </ToastProvider>,
    );
    view.rerender(
      <ToastProvider>
        <IntelTab
          engagementKey="demo"
          summary={{ counts: { notes: 1 } }}
          initialIntelType="note"
          initialIntelId={42}
          onInitialRecordConsumed={onInitialRecordConsumed}
        />
      </ToastProvider>,
    );
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(onInitialRecordConsumed).toHaveBeenCalledTimes(2);
    window.removeEventListener("hashchange", hashChange);
  });

  it("opens and deep-links an FTS result instead of only selecting it", async () => {
    vi.mocked(searchIntel).mockResolvedValue([
      {
        entity_type: "note",
        source_id: 77,
        key: "Lead: cache poisoning",
        body: "Host header ambiguity",
        source_name: "recon",
        rank: -1,
        record: {
          id: 77,
          title: "Lead: cache poisoning",
          body_markdown: "Host header ambiguity",
          lead_status: "open",
        },
      },
    ]);

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo key" summary={{ counts: {} }} />
      </ToastProvider>,
    );

    fireEvent.change(screen.getByPlaceholderText(/Search any field/i), {
      target: { value: "cache poisoning" },
    });
    fireEvent.click(screen.getByRole("button", { name: "FTS" }));
    fireEvent.click(await screen.findByRole("button", { name: /Lead: cache poisoning/i }));

    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "Lead: cache poisoning" })).toBeTruthy();
    expect(window.location.hash).toContain("tab=intel");
    expect(window.location.hash).toContain("intel_type=note");
    expect(window.location.hash).toContain("intel_id=77");
  });
});

describe("IntelTab active work", () => {
  it("treats note lead_status as first-class status and prioritizes active leads", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
      entity_type: entityType,
      total: entityType === "note" ? 2 : 0,
      items: entityType === "note"
        ? ([
            {
              id: 1,
              title: "Reference history",
              body_markdown: "Keep this visible",
              updated_at: "2026-09-21T13:00:00Z",
              lead_status: null,
            },
            {
              id: 2,
              title: "Lead: authorization bypass",
              body_markdown: "Test tenant boundary",
              updated_at: "2026-09-20T13:00:00Z",
              lead_status: "in_progress",
            },
          ] as never[])
        : [],
    }));

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: { notes: 2 } }} />
      </ToastProvider>,
    );

    const leadRow = await screen.findByRole("button", { name: /Lead: authorization bypass/i });
    const referenceRow = screen.getByRole("button", { name: /Reference history/i });
    expect(leadRow.compareDocumentPosition(referenceRow) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getAllByText("in progress").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /in progress\s+1/i }));
    expect(screen.getByText("1 of 2 records")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Reference history/i })).toBeNull();

    fireEvent.click(leadRow);
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Lead status")).toBeTruthy();
    expect(screen.getAllByText("in progress").length).toBeGreaterThan(0);
  });

  it("loads the advisory readiness summary and uses active leads as a record entry", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
      entity_type: entityType,
      total: entityType === "note" ? 1 : 0,
      items: entityType === "note"
        ? [{ id: 9, title: "Lead: SSRF", lead_status: "open" } as never]
        : [],
    }));
    vi.mocked(getIntelReadiness).mockResolvedValue({
      applicable: true,
      engagement_type: "red",
      open_high_cves: [{ id: 4, cve_id: "CVE-2025-0001", cvss_score: 9.1, validation_status: "unverified", affected_component: "gateway" }],
      open_leads: [{ id: 9, title: "Lead: SSRF", lead_status: "open" }],
      exploited_unlinked_cves: [],
      dangling_links: [],
    });

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: { notes: 1, cves: 1 } }} />
      </ToastProvider>,
    );

    expect(await screen.findByText("Active work")).toBeTruthy();
    expect(screen.getByText("1 open lead")).toBeTruthy();
    expect(screen.getByText("1 high-risk CVE")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Review Lead: SSRF/i }));
    expect(await screen.findByRole("heading", { level: 2, name: "Lead: SSRF" })).toBeTruthy();
    expect(getIntelReadiness).toHaveBeenCalledWith("demo");
  });

  it("uses the plural summary contract keys before entity caches load", () => {
    vi.mocked(listIntel).mockImplementation(() => new Promise(() => {}));
    vi.mocked(listIntelCredentials).mockImplementation(() => new Promise(() => {}));

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: { tech_components: 3, notes: 2 } }} />
      </ToastProvider>,
    );

    expect(screen.getByRole("button", { name: /Tech stack\s+3/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Notes\s+2/i })).toBeTruthy();
  });
});

describe("IntelTab by-URL continuations", () => {
  it("opens domain records and routes assessment rows to their owning workspaces", async () => {
    vi.mocked(intelByUrl).mockResolvedValue({
      domains: [{ id: 3, identity: "api.example.test", kind: "subdomain", value: "api.example.test" } as never],
      services: [{ id: 4, endpoint: "https://api.example.test:443", service: "https" }],
      surfaces: [{ id: 5, target_descriptor: "https://api.example.test/admin", surface_type: "web" }],
      request_variants: [{ id: 6, canonical_url: "https://api.example.test/v1", method: "GET" }],
    });

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: {} }} />
      </ToastProvider>,
    );
    fireEvent.change(screen.getByPlaceholderText(/Lookup anything/i), {
      target: { value: "https://api.example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Go" }));

    const domain = await screen.findByRole("button", { name: /api.example.test/i });
    fireEvent.click(domain);
    expect(await screen.findByRole("heading", { level: 2, name: "api.example.test" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /close detail/i }));

    expect(screen.getByRole("link", { name: /https:\/\/api.example.test:443/i }).getAttribute("href")).toContain("tab=coverage");
    expect(screen.getByRole("link", { name: /https:\/\/api.example.test\/admin/i }).getAttribute("href")).toContain("tab=surfaces");
    expect(screen.getByRole("link", { name: /https:\/\/api.example.test\/v1/i }).getAttribute("href")).toContain("tab=http");
  });
});
