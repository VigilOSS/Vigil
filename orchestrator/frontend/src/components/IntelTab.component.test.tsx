// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
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
  window.history.replaceState({}, "", "#/engagements");
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
  it("restores a credential deep link and closes/reopens it with history", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([{ id: 42, identity: "operator@example.test", secret: "exact-token" }]);
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=credentials&intel_id=42");
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    expect(await screen.findByRole("heading", { level: 2, name: "operator@example.test" })).toBeTruthy();
    expect(screen.getByText("exact-token")).toBeTruthy();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.queryByRole("dialog")).toBeNull();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=credentials&intel_id=42");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    expect(await screen.findByRole("heading", { level: 2, name: "operator@example.test" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_type=credentials&intel_id=42");
  });

  it("closes a clicked credential when history returns to the intel ledger", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([{ id: 42, identity: "operator@example.test" }]);
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /operator@example.test/ }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("contains intel-palette focus and restores its opener on Escape", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 1 : 0, items: entityType === "cve" ? [{ id: 44, cve_id: "CVE-2026-4444" }] as never[] : [] }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    screen.getByRole("button", { name: "FTS" }).focus();
    expect(document.querySelector(".cmd-box")?.contains(document.activeElement)).toBe(true);
    const dialog = screen.getByRole("dialog", { name: "Jump to intel" });
    const input = within(dialog).getByRole("textbox", { name: "Search intel to jump to" });
    expect(document.body.classList.contains("detail-modal-open")).toBe(true);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: /CVE-2026-4444/ }));
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(input);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
  });
  it("opens the arrow-selected intel record with its exact canonical identity", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 2 : 0, items: entityType === "cve" ? [{ id: 44, cve_id: "CVE-2026-4444" }, { id: 45, cve_id: "CVE-2026-5555" }] as never[] : [] }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 2 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    const input = screen.getByPlaceholderText(/Jump to intel ·/);
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("heading", { name: "CVE-2026-5555" })).toBeTruthy();
    expect(document.querySelector(".cmd-overlay")).toBeNull();
    expect(window.location.hash).toContain("intel_type=cve");
    expect(window.location.hash).toContain("intel_id=45");
  });
  it("clears the detail route when CmdK hands off to the palette", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 1 : 0, items: entityType === "cve" ? [{ id: 44, cve_id: "CVE-2026-4444" }] as never[] : [] }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Search intel to jump to" }), { key: "Enter" });
    await screen.findByRole("heading", { name: "CVE-2026-4444" });
    expect(window.location.hash).toContain("intel_id=44");
    fireEvent.keyDown(screen.getByRole("button", { name: /close detail/i }), { key: "k", metaKey: true });
    const palette = screen.getByRole("dialog", { name: "Jump to intel" });
    expect(screen.queryByRole("heading", { name: "CVE-2026-4444" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel");
    fireEvent.keyDown(within(palette).getByRole("textbox"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel");
  });
  it("closes the palette when history restores an authoritative intel selection", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 1 : 0, items: entityType === "cve" ? [{ id: 44, cve_id: "CVE-2026-4444" }] as never[] : [] }));
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Search intel to jump to" }), { key: "Enter" });
    await screen.findByRole("heading", { name: "CVE-2026-4444" });
    fireEvent.keyDown(screen.getByRole("button", { name: /close detail/i }), { key: "k", metaKey: true });
    expect(screen.getByRole("dialog", { name: "Jump to intel" })).toBeTruthy();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=cve&intel_id=44");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    expect(await screen.findByRole("heading", { name: "CVE-2026-4444" })).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull();
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(window.location.hash).toContain("intel_id=44");
  });
  it("leaves an empty filtered ledger alone when next/previous shortcuts are pressed", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByText(/0 records · page/);
    const errors: string[] = [];
    const record = (event: ErrorEvent) => { errors.push(event.message); event.preventDefault(); };
    window.addEventListener("error", record);
    try { for (const key of ["j", "k", "[", "]"]) fireEvent.keyDown(window, { key }); }
    finally { window.removeEventListener("error", record); }
    expect(errors).toEqual([]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("does not move the record while a detail control handles a native key", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 2 : 0, items: entityType === "cve" ? [{ id: 44, cve_id: "CVE-2026-4444" }, { id: 45, cve_id: "CVE-2026-5555" }] as never[] : [] }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 2 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    await screen.findByRole("dialog");
    fireEvent.keyDown(screen.getByRole("button", { name: /close detail/i }), { key: "j" });
    expect(screen.getByRole("heading", { level: 2, name: "CVE-2026-4444" })).toBeTruthy();
  });
  it("opens a recorded linked finding without inferring provenance from the intel text", async () => {
    vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
      entity_type: entityType,
      total: entityType === "cve" ? 1 : 0,
      items: entityType === "cve"
        ? [{ id: 44, cve_id: "CVE-2026-4444", linked_finding_slug: "VA-012" } as never]
        : [],
    }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    await screen.findByRole("dialog");
    fireEvent.click(screen.getByRole("button", { name: /Links & tags/i }));
    expect((await screen.findByRole("link", { name: "VA-012" })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=findings&finding=VA-012");
  });

  it("opens the exact typed record after its entity cache loads", async () => {
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
        />
      </ToastProvider>,
    );

    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "OAuth boundary research" })).toBeTruthy();
    expect(hashChange).not.toHaveBeenCalled();
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
        />
      </ToastProvider>,
    );
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "OAuth boundary research" })).toBeTruthy();
    expect(hashChange).toHaveBeenCalledOnce();
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
