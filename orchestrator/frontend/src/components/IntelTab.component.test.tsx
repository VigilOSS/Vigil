// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

/**
 * Answer `listIntel` per entity type: a type named in `items` reads its rows,
 * every other type reads none. The ledger shows the server's own `total`
 * rather than the loaded window, so a test that asserts a count passes it.
 */
function mockIntel(items: Record<string, unknown[]>, total: Record<string, number> = {}) {
  vi.mocked(listIntel).mockImplementation(async (_key, entityType) => ({
    entity_type: entityType,
    total: total[entityType] ?? 0,
    items: (items[entityType] ?? []) as never[],
  }));
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState({}, "", "#/engagements");
  mockIntel({});
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

/** The line above the list: "3 of 4 intel records · Sorted by …". */
const resultsText = () => document.querySelector(".ui-results-summary")?.textContent ?? "";

describe("IntelTab deep links", () => {
  it("restores a credential deep link and closes/reopens it with history", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([{ id: 42, identity: "operator@example.com", secret: "exact-token" }]);
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=credentials&intel_id=42");
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    expect(await screen.findByRole("heading", { level: 2, name: "operator@example.com" })).toBeTruthy();
    expect(screen.getByText("exact-token")).toBeTruthy();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=credentials&intel_id=42");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    expect(await screen.findByRole("heading", { level: 2, name: "operator@example.com" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_type=credentials&intel_id=42");
  });

  it("closes a clicked credential when history returns to the intel ledger", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([{ id: 42, identity: "operator@example.com" }]);
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /operator@example.com/ }));
    expect(await screen.findByRole("region", { name: "Intel record" })).toBeTruthy();
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="credentials" initialIntelId={42} /></ToastProvider>);
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull();
  });

  it("contains intel-palette focus and restores its opener on Escape", async () => {
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444" }] }, { cve: 1 });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    screen.getByRole("button", { name: "Full-text search" }).focus();
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
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444" }, { id: 45, cve_id: "CVE-2026-5555" }] }, { cve: 2 });
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
  it("opens the palette over an open record and keeps its route", async () => {
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444" }, { id: 45, cve_id: "CVE-2026-5555" }] }, { cve: 2 });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 2 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Search intel to jump to" }), { key: "Enter" });
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByRole("heading", { level: 2, name: "CVE-2026-4444" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_id=44");
    fireEvent.keyDown(within(record).getByRole("button", { name: "Back to results" }), { key: "k", metaKey: true });
    const palette = screen.getByRole("dialog", { name: "Jump to intel" });
    // The record stays open under the palette; its Escape belongs to the palette.
    expect(within(record).getByRole("heading", { level: 2, name: "CVE-2026-4444" })).toBeTruthy();
    fireEvent.keyDown(within(palette).getByRole("textbox"), { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull();
    expect(screen.getByRole("region", { name: "Intel record" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_id=44");
    // Choosing from the palette moves the open record.
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = within(screen.getByRole("dialog", { name: "Jump to intel" })).getByRole("textbox");
    fireEvent.change(input, { target: { value: "5555" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-5555" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_id=45");
  });
  it("closes the palette when history restores an authoritative intel selection", async () => {
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444" }] }, { cve: 1 });
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} /></ToastProvider>);
    await screen.findAllByText("CVE-2026-4444");
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Search intel to jump to" }), { key: "Enter" });
    await screen.findByRole("heading", { name: "CVE-2026-4444" });
    fireEvent.keyDown(screen.getByRole("button", { name: "Back to results" }), { key: "k", metaKey: true });
    expect(screen.getByRole("dialog", { name: "Jump to intel" })).toBeTruthy();
    window.history.replaceState({}, "", "#/engagements/demo?tab=intel&intel_type=cve&intel_id=44");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    expect(await screen.findByRole("heading", { name: "CVE-2026-4444" })).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull();
    expect(screen.getByRole("region", { name: "Intel record" })).toBeTruthy();
    expect(window.location.hash).toContain("intel_id=44");
  });
  it("leaves an empty filtered ledger alone when next/previous shortcuts are pressed", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByText("No intel recorded yet.");
    const errors: string[] = [];
    const record = (event: ErrorEvent) => { errors.push(event.message); event.preventDefault(); };
    window.addEventListener("error", record);
    try { for (const key of ["j", "k", "[", "]"]) fireEvent.keyDown(window, { key }); }
    finally { window.removeEventListener("error", record); }
    expect(errors).toEqual([]);
    expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull();
  });
  it("does not move the record while a detail control handles a native key", async () => {
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444" }, { id: 45, cve_id: "CVE-2026-5555" }] }, { cve: 2 });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 2 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    await screen.findByRole("region", { name: "Intel record" });
    fireEvent.keyDown(screen.getByRole("button", { name: "Back to results" }), { key: "j" });
    expect(screen.getByRole("heading", { level: 2, name: "CVE-2026-4444" })).toBeTruthy();
  });
  it("opens a recorded linked finding without inferring provenance from the intel text", async () => {
    mockIntel({ cve: [{ id: 44, cve_id: "CVE-2026-4444", linked_finding_slug: "VA-012" } as never] }, { cve: 1 });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: { cves: 1 } }} initialIntelType="cve" initialIntelId={44} /></ToastProvider>);
    await screen.findByRole("region", { name: "Intel record" });
    fireEvent.click(screen.getByRole("button", { name: /Links & tags/i }));
    expect((await screen.findByRole("link", { name: "VA-012" })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=findings&finding=VA-012");
  });

  it("opens the exact typed record after its entity cache loads", async () => {
    const hashChange = vi.fn();
    window.addEventListener("hashchange", hashChange);
    mockIntel({ note: [{ id: 42, title: "OAuth boundary research", body_markdown: "Research body" } as never] }, { note: 1 });
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

    expect(await screen.findByRole("region", { name: "Intel record" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "OAuth boundary research" })).toBeTruthy();
    expect(hashChange).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
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
    expect(await screen.findByRole("region", { name: "Intel record" })).toBeTruthy();
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

    fireEvent.change(screen.getByRole("searchbox", { name: "Search intel" }), {
      target: { value: "cache poisoning" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Full-text search" }));
    fireEvent.click(await screen.findByRole("button", { name: /Lead: cache poisoning/i }));

    expect(await screen.findByRole("region", { name: "Intel record" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "Lead: cache poisoning" })).toBeTruthy();
    expect(window.location.hash).toContain("tab=intel");
    expect(window.location.hash).toContain("intel_type=note");
    expect(window.location.hash).toContain("intel_id=77");
  });
});

describe("IntelTab record view", () => {
  const cves = [
    { id: 1, cve_id: "CVE-2026-0001", tags: ["edge"] },
    { id: 2, cve_id: "CVE-2026-0002" },
    { id: 3, cve_id: "CVE-2026-0003", tags: ["gateway"] },
  ];
  beforeEach(() => {
    mockIntel({ cve: cves, note: [{ id: 9, title: "Reference note" }] });
  });

  it("walks the filtered results with previous and next, and Back returns to them intact", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^CVEs\s+3/ }));
    expect(resultsText()).toContain("3 of 4 intel records");
    const row = screen.getByRole("button", { name: /CVE-2026-0002/ });
    fireEvent.click(row);

    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(screen.queryByRole("dialog")).toBeNull();
    // The record replaces the results; they keep their state behind it.
    expect(screen.queryByRole("button", { name: /^CVEs\s+3/ })).toBeNull();
    expect(screen.queryByRole("heading", { level: 1, name: "Intel" })).toBeNull();
    expect(document.activeElement).toBe(within(record).getByRole("heading", { level: 2, name: "CVE-2026-0002" }));
    expect(within(record).getByText("2 of 3 results")).toBeTruthy();
    expect(within(record).getByText("CVE #2")).toBeTruthy();
    expect(within(record).getByLabelText("Intel record dates").textContent).toContain("Created");
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel&intel_type=cve&intel_id=2");

    fireEvent.click(within(record).getByRole("button", { name: "Next intel record" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0003" })).toBeTruthy();
    expect(within(record).getByText("3 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Next intel record" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(document.body, { key: "]" });
    expect(within(record).getByText("3 of 3 results")).toBeTruthy();
    fireEvent.keyDown(document.body, { key: "[" });
    fireEvent.click(within(record).getByRole("button", { name: "Previous intel record" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0001" })).toBeTruthy();
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Previous intel record" }) as HTMLButtonElement).disabled).toBe(true);
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel&intel_type=cve&intel_id=1");

    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel");
    expect(screen.getByRole("button", { name: /^CVEs\s+3/ }).getAttribute("aria-pressed")).toBe("true");
    expect(resultsText()).toContain("3 of 4 intel records");
    // Back lands on the record last shown (stepped to), not the row that opened the first.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /CVE-2026-0001/ })));
    expect(row.isConnected).toBe(true);
  });

  it("restores a deep-linked section, keeps it while stepping, and Escape returns to the results", async () => {
    const view = render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={3} initialDrawerTab="references" />
      </ToastProvider>,
    );
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByRole("button", { name: /^Links & tags/ }).getAttribute("aria-current")).toBe("page");
    expect(within(record).getByText("gateway")).toBeTruthy();

    // Stepping keeps the section where the next record has it, else Overview.
    fireEvent.click(within(record).getByRole("button", { name: "Previous intel record" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0002" })).toBeTruthy();
    expect(within(record).queryByRole("button", { name: /^Links & tags/ })).toBeNull();
    expect(within(record).getByRole("button", { name: /^Overview/ }).getAttribute("aria-current")).toBe("page");
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel&intel_type=cve&intel_id=2");

    fireEvent.click(within(record).getByRole("button", { name: "Raw" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel&intel_type=cve&intel_id=2&dtab=raw");
    expect(within(record).getByText("Raw record")).toBeTruthy();

    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.getByRole("button", { name: /CVE-2026-0003/ })).toBeTruthy();
  });

  it("moves the open record with j and k", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    await within(record).findByText("2 of 4 results");
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "j" });
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0003" })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel&intel_type=cve&intel_id=3");
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "k" });
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0002" })).toBeTruthy();
  });

  it("locates the record only once every entity type has loaded", async () => {
    let resolveCredentials!: (rows: never[]) => void;
    vi.mocked(listIntelCredentials).mockReturnValue(new Promise((resolve) => { resolveCredentials = resolve; }));
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByText("Locating in results…")).toBeTruthy();
    expect(within(record).getByRole("button", { name: "Next intel record" }).getAttribute("aria-disabled")).toBe("true");
    resolveCredentials([]);
    expect(await within(record).findByText("2 of 4 results")).toBeTruthy();
  });

  it("finishes its first load when a live refresh arrives during it", async () => {
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} refreshVersion={0} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    // The workspace says intel changed before the first reads have answered.
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} refreshVersion={1} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(await within(record).findByText("2 of 4 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Next intel record" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "CVE-2026-0003" })).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(resultsText()).toMatch(/^4 of 4 intel records/));
  });

  it("leaves the open record when the link moves to a record the ledger does not hold", async () => {
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByRole("heading", { level: 2, name: "CVE-2026-0002" })).toBeTruthy();
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={99999999} /></ToastProvider>);
    expect((await screen.findByRole("alert")).textContent).toContain("Intel record cve #99999999 was not found");
    // The results show again, so the old record no longer stands in for the link.
    expect(await screen.findByRole("button", { name: /CVE-2026-0002/ })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Intel" })).toBeTruthy();
  });

  it("links a recorded web address and shows any other scheme as text", async () => {
    mockIntel({
      social_profile: [
        { id: 7, platform: "web", handle: "acme", url: "https://social.example/acme" },
        { id: 8, platform: "web", handle: "acme-script", url: "javascript:alert(1)" },
      ],
    });
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="social_profile" initialIntelId={7} initialDrawerTab="references" /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect((await within(record).findByRole("link", { name: /social\.example\/acme/ })).getAttribute("href")).toBe("https://social.example/acme");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="social_profile" initialIntelId={8} initialDrawerTab="references" /></ToastProvider>);
    const address = await within(record).findByText("javascript:alert(1)");
    expect(address.closest("a")).toBeNull();
  });

  it("keeps a record without a stored id open when the link leaves the routed record", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([{ identity: "svc-reader@example.com" }]);
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={2} /></ToastProvider>);
    await screen.findByRole("region", { name: "Intel record" });
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = within(screen.getByRole("dialog", { name: "Jump to intel" })).getByRole("textbox");
    fireEvent.change(input, { target: { value: "svc-reader" } });
    fireEvent.keyDown(input, { key: "Enter" });
    // A record without a stored id has no link of its own: the URL drops the routed one.
    expect(window.location.hash).toBe("#/engagements/demo?tab=intel");
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByRole("heading", { level: 2, name: "svc-reader@example.com" })).toBeTruthy();
  });

  it("titles a credential by who it authenticates as, and keeps its secret verbatim", async () => {
    vi.mocked(listIntelCredentials).mockResolvedValue([
      { id: 42, credential_key: "acme-portal-api-key", principal: "svc-portal@example.com", kind: "api-key", identity: "", secret: "exact-token", status: "confirmed" },
      { id: 43, credential_key: "acme-backup-token", principal: "", kind: "api-token", identity: "", secret: "other-token", status: "unverified" },
    ]);
    render(<ToastProvider><IntelTab engagementKey="acme" summary={{ counts: {} }} /></ToastProvider>);
    // Each credential reads as itself in the list: its principal, else its key.
    const row = await screen.findByRole("row", { name: /svc-portal@example\.com/ });
    expect(within(row).getByText(/acme-portal-api-key/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /acme-backup-token/ })).toBeTruthy();
    fireEvent.click(within(row).getByRole("button", { name: /svc-portal@example\.com/ }));
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByRole("heading", { level: 2, name: "svc-portal@example.com" })).toBeTruthy();
    expect(within(record).getByText("exact-token")).toBeTruthy();
  });

  it("links a superseded record to the record that replaced it", async () => {
    mockIntel({
      note: [
        { id: 11, title: "Acme SSO uses SAML", superseded_by_id: 12, superseded_at: "2026-09-21T10:00:00Z" },
        { id: 12, title: "Acme SSO uses SAML and OIDC" },
      ],
    });
    render(<ToastProvider><IntelTab engagementKey="acme" summary={{ counts: {} }} /></ToastProvider>);
    const row = await screen.findByRole("row", { name: /Acme SSO uses SAML\b(?! and)/ });
    const replacement = "#/engagements/acme?tab=intel&intel_type=note&intel_id=12";
    expect(within(row).getByRole("link", { name: /#12/ }).getAttribute("href")).toBe(replacement);
    fireEvent.click(within(row).getByRole("button", { name: /Acme SSO uses SAML/ }));
    const record = await screen.findByRole("region", { name: "Intel record" });
    const links = within(record).getAllByRole("link", { name: /#12/ });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) expect(link.getAttribute("href")).toBe(replacement);
  });

  it("keeps Previous / Next for a lead that a refresh takes out of Needs attention", async () => {
    const leads = (second: string) => [
      { id: 21, title: "Acme lead one", lead_status: "open", updated_at: "2026-09-28T03:00:00Z" },
      { id: 22, title: "Acme lead two", lead_status: second, updated_at: "2026-09-28T02:00:00Z" },
      { id: 23, title: "Acme lead three", lead_status: "open", updated_at: "2026-09-28T01:00:00Z" },
    ];
    mockIntel({ note: leads("open") });
    const view = render(<ToastProvider><IntelTab engagementKey="acme" summary={{ counts: {} }} refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^Needs attention\s*3/ }));
    fireEvent.click(screen.getByRole("button", { name: "Acme lead two" }));
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(await within(record).findByText("2 of 3 results")).toBeTruthy();

    // An agent resolves the lead while it is open.
    mockIntel({ note: leads("resolved") });
    view.rerender(<ToastProvider><IntelTab engagementKey="acme" summary={{ counts: {} }} refreshVersion={1} /></ToastProvider>);
    expect(await within(record).findByText("Outside current results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Next intel record" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "Acme lead three" })).toBeTruthy();
    expect(within(record).getByText("2 of 2 results")).toBeTruthy();
  });

  it("explains a deep link to a record the ledger does not hold", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="cve" initialIntelId={404} /></ToastProvider>);
    expect((await screen.findByRole("alert")).textContent).toContain("Intel record cve #404 was not found");
    expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull();
  });
});

describe("IntelTab active work", () => {
  it("treats note lead_status as first-class status and prioritizes active leads", async () => {
    mockIntel({
      note: [
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
      ],
    }, { note: 2 });

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: { notes: 2 } }} />
      </ToastProvider>,
    );

    const leadRow = await screen.findByRole("button", { name: /Lead: authorization bypass/i });
    const referenceRow = screen.getByRole("button", { name: /Reference history/i });
    expect(leadRow.compareDocumentPosition(referenceRow) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getAllByText("In progress").length).toBeGreaterThan(0);

    fireEvent.click(within(screen.getByRole("group", { name: "Lead status" })).getByRole("button", { name: /In progress\s+1/ }));
    expect(resultsText()).toContain("1 of 2 intel records");
    expect(screen.queryByRole("button", { name: /Reference history/i })).toBeNull();

    fireEvent.click(leadRow);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(within(record).getByText("Lead status")).toBeTruthy();
    expect(within(record).getAllByText("In progress").length).toBeGreaterThan(0);
  });

  it("loads the advisory readiness summary and uses active leads as a record entry", async () => {
    mockIntel({ note: [{ id: 9, title: "Lead: SSRF", lead_status: "open" } as never] }, { note: 1 });
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
      domains: [{ id: 3, identity: "api.example.com", kind: "subdomain", value: "api.example.com" } as never],
      services: [{ id: 4, endpoint: "https://api.example.com:443", service: "https" }],
      surfaces: [{ id: 5, target_descriptor: "https://api.example.com/admin", surface_type: "web" }],
      request_variants: [{ id: 6, canonical_url: "https://api.example.com/v1", method: "GET" }],
    });

    render(
      <ToastProvider>
        <IntelTab engagementKey="demo" summary={{ counts: {} }} />
      </ToastProvider>,
    );
    fireEvent.change(screen.getByRole("searchbox", { name: "Look up intel by URL" }), {
      target: { value: "https://api.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Go" }));

    const domain = await screen.findByRole("button", { name: /api.example.com/i });
    fireEvent.click(domain);
    expect(await screen.findByRole("heading", { level: 2, name: "api.example.com" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));

    // Services have no record view: the row says what it is without pretending to link.
    expect(screen.getByText("https://api.example.com:443")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /https:\/\/api.example.com:443/i })).toBeNull();
    // Surfaces and request variants open their exact record.
    expect(screen.getByRole("link", { name: /https:\/\/api.example.com\/admin/i }).getAttribute("href"))
      .toBe("#/engagements/demo?tab=surfaces&surface=5");
    expect(screen.getByRole("link", { name: /https:\/\/api.example.com\/v1/i }).getAttribute("href"))
      .toBe("#/engagements/demo?tab=http&request=6");
  });
});

describe("IntelTab by-URL heading", () => {
  it("names the URL that was looked up, whatever the box holds since", async () => {
    vi.mocked(intelByUrl).mockResolvedValue({
      domains: [],
      services: [],
      surfaces: [{ id: 5, target_descriptor: "https://app.example.com/a", surface_type: "web" }],
      request_variants: [],
    });
    render(<ToastProvider><IntelTab engagementKey="acme" summary={{ counts: {} }} /></ToastProvider>);
    const box = screen.getByRole("searchbox", { name: "Look up intel by URL" });
    fireEvent.change(box, { target: { value: "https://app.example.com/a" } });
    fireEvent.click(screen.getByRole("button", { name: "Go" }));
    await screen.findByRole("link", { name: /https:\/\/app\.example\.com\/a/ });
    const heading = () => document.querySelector(".intel-lookups .section-title code")?.textContent;
    expect(heading()).toBe("https://app.example.com/a");
    fireEvent.change(box, { target: { value: "https://app.example.com/b" } });
    expect(heading()).toBe("https://app.example.com/a");
  });
});

describe("IntelTab page and filters", () => {
  // Note 01 is the most recently updated, so priority order is Note 01, 02, …
  const notes = (count: number) => Array.from({ length: count }, (_, index) => ({
    id: index + 1,
    title: `Note ${String(index + 1).padStart(2, "0")}`,
    updated_at: new Date(Date.UTC(2026, 8, 28) - index * 60_000).toISOString(),
  }));

  it("states its purpose in the shared page header", async () => {
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    expect(screen.getByRole("heading", { level: 1, name: "Intel" })).toBeTruthy();
    expect(screen.getByText(/What Vigil learned about the target/)).toBeTruthy();
  });

  it("re-reads records and readiness when the workspace says intel changed", async () => {
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} refreshVersion={0} /></ToastProvider>);
    await screen.findByText("No intel recorded yet.");
    const reads = vi.mocked(listIntel).mock.calls.length;
    mockIntel({ note: [{ id: 5, title: "Fresh lead", lead_status: "open" } as never] }, { note: 1 });
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} refreshVersion={1} /></ToastProvider>);
    expect(await screen.findByRole("button", { name: /Fresh lead/ })).toBeTruthy();
    expect(vi.mocked(listIntel).mock.calls.length).toBeGreaterThan(reads);
    expect(vi.mocked(getIntelReadiness).mock.calls.length).toBeGreaterThan(1);
  });

  it("shows exactly the readiness open leads from the Active work count", async () => {
    mockIntel({
      note: [
        { id: 1, title: "Live lead", lead_status: "open" },
        { id: 2, title: "Replaced lead", lead_status: "open", superseded_by_id: 1 },
        { id: 3, title: "Reference", lead_status: null },
      ],
    });
    vi.mocked(getIntelReadiness).mockResolvedValue({
      applicable: true,
      engagement_type: "red",
      open_high_cves: [],
      open_leads: [{ id: 1, title: "Live lead", lead_status: "open" }],
      exploited_unlinked_cves: [],
      dangling_links: [],
    });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "1 open lead" }));
    expect(resultsText()).toMatch(/^1 of 3 intel records/);
    const list = document.querySelector<HTMLElement>(".list-scroll")!;
    expect(within(list).getByRole("button", { name: /Live lead/ })).toBeTruthy();
    expect(within(list).queryByRole("button", { name: /Replaced lead/ })).toBeNull();
  });

  it("groups statuses by what they describe and never cuts off sources", async () => {
    mockIntel({
      note: Array.from({ length: 10 }, (_, index) => ({ id: index + 1, title: `Lead ${index + 1}`, lead_status: "open", source_name: `source-${index + 1}` })),
      tech_component: [{ id: 20, component: "nginx", confidence: "high", source_name: "source-1" }],
    });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const leads = await screen.findByRole("group", { name: "Lead status" });
    expect(within(leads).getByRole("button", { name: /^Open\s*10/ })).toBeTruthy();
    expect(within(screen.getByRole("group", { name: "Confidence" })).getByRole("button", { name: /^High confidence\s*1/ })).toBeTruthy();
    const sources = screen.getByRole("group", { name: "Source" });
    expect(within(sources).queryByRole("button", { name: /^source-9\s/ })).toBeNull();
    fireEvent.click(within(sources).getByRole("button", { name: "Show all 10" }));
    fireEvent.click(within(sources).getByRole("button", { name: /^source-9\s*1/ }));
    expect(resultsText()).toMatch(/^1 of 11 intel records/);
  });

  it("lists each tag once", async () => {
    mockIntel({ note: [{ id: 1, title: "Architecture map", source_agent: "code-architect", tags: ["code-architect", "auth"] } as never] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const row = await screen.findByRole("row", { name: /Architecture map/ });
    expect(within(row).getAllByText("code-architect")).toHaveLength(1);
  });

  it("tells an empty engagement apart from filters that match nothing", async () => {
    mockIntel({ note: [{ id: 1, title: "Only note" } as never] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByRole("button", { name: /Only note/ });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search intel" }), { target: { value: "zzz-no-match" } });
    expect(screen.getByText("No intel records match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByRole("button", { name: /Only note/ })).toBeTruthy();
  });

  it("runs the full-text search on Enter and says how it differs from the list filter", async () => {
    vi.mocked(searchIntel).mockResolvedValue([]);
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const search = screen.getByRole("searchbox", { name: "Search intel" });
    fireEvent.change(search, { target: { value: "acme" } });
    fireEvent.keyDown(search, { key: "Enter" });
    await waitFor(() => expect(searchIntel).toHaveBeenCalledWith("demo", { q: "acme" }));
    expect(await screen.findByText(/Full-text matches for/)).toBeTruthy();
    expect(screen.getByText(/ranked by relevance/i)).toBeTruthy();
  });

  it("shows the full-text answer for the latest search when an earlier one answers last", async () => {
    let answerFirst!: (hits: never[]) => void;
    const hit = (id: number, key: string) => ({ entity_type: "note", source_id: id, key, body: key, source_name: "recon", rank: -1, record: { id, title: key } });
    vi.mocked(searchIntel)
      .mockReturnValueOnce(new Promise((resolve) => { answerFirst = resolve as (hits: never[]) => void; }))
      .mockResolvedValueOnce([hit(2, "Second search hit")] as never);
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const search = screen.getByRole("searchbox", { name: "Search intel" });
    fireEvent.change(search, { target: { value: "first" } });
    fireEvent.keyDown(search, { key: "Enter" });
    fireEvent.change(search, { target: { value: "second" } });
    fireEvent.keyDown(search, { key: "Enter" });
    expect(await screen.findByRole("button", { name: /Second search hit/ })).toBeTruthy();
    await act(async () => { answerFirst([hit(1, "First search hit")] as never); });
    const lookups = document.querySelector<HTMLElement>(".intel-lookups")!;
    expect(within(lookups).getByText(/Full-text matches for/).textContent).toContain("second");
    expect(within(lookups).getAllByRole("button").map((button) => button.textContent)).toEqual([expect.stringContaining("Second search hit")]);
  });

  it("follows j and k across result pages", async () => {
    mockIntel({ note: notes(45) });
    // Note 40 is the last row of the first page; Back returns to it there.
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="note" initialIntelId={40} /></ToastProvider>);
    const record = await screen.findByRole("region", { name: "Intel record" });
    expect(await within(record).findByText("40 of 45 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(await screen.findByText(/page 1 \/ 2/)).toBeTruthy();
    fireEvent.keyDown(window, { key: "j" });
    expect(await screen.findByText(/page 2 \/ 2/)).toBeTruthy();
    expect(within(screen.getByRole("table", { name: "Intel records" })).getByRole("row", { name: /Note 41/ }).className).toContain("is-selected");
  });

  it("returns from a stepped record to that record's row", async () => {
    mockIntel({ note: notes(3) });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /Note 01/ }));
    const record = await screen.findByRole("region", { name: "Intel record" });
    fireEvent.click(within(record).getByRole("button", { name: "Next intel record" }));
    await within(record).findByRole("heading", { level: 2, name: "Note 02" });
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 02/ })));
  });

  it("moves the selection with j and k from the row that has focus", async () => {
    mockIntel({ note: notes(3) });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /Note 01/ }));
    const record = await screen.findByRole("region", { name: "Intel record" });
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    // Back leaves focus on the row; the list keys continue from it.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 01/ })));
    const table = screen.getByRole("table", { name: "Intel records" });
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(within(table).getByRole("row", { name: /Note 02/ }).className).toContain("is-selected"));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 02/ })));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "]" });
    await waitFor(() => expect(within(table).getByRole("row", { name: /Note 03/ }).className).toContain("is-selected"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "k" });
    await waitFor(() => expect(within(table).getByRole("row", { name: /Note 02/ }).className).toContain("is-selected"));
  });

  it("steps from the focused row when another row, or none, is highlighted", async () => {
    mockIntel({ note: notes(5) });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const table = screen.getByRole("table", { name: "Intel records" });
    const selected = () => within(table).getAllByRole("row").filter((row) => row.className.includes("is-selected")).map((row) => row.textContent);
    // Tab reaches a row without highlighting it.
    (await screen.findByRole("button", { name: /Note 03/ })).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 04/ })));
    expect(selected()).toEqual([expect.stringContaining("Note 04")]);
    // Focus moved on by Tab while Note 04 stays highlighted.
    screen.getByRole("button", { name: /Note 02/ }).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "[" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 01/ })));
    expect(selected()).toEqual([expect.stringContaining("Note 01")]);
  });

  it("moves focus onto the highlighted row when a list key steps to it from the row beside it", async () => {
    mockIntel({ note: notes(45) });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const table = screen.getByRole("table", { name: "Intel records" });
    // Note 04 is highlighted and has focus; Shift+Tab then puts focus on Note 03.
    (await screen.findByRole("button", { name: /Note 03/ })).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 04/ })));
    screen.getByRole("button", { name: /Note 03/ }).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 04/ })));

    // The highlighted row is on the next page: stepping onto it from the last row shown turns the page.
    screen.getByRole("button", { name: /Note 40/ }).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 41/ })));
    fireEvent.click(screen.getByRole("button", { name: "Prev" }));
    (await screen.findByRole("button", { name: /Note 40/ })).focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "]" });
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /Note 41/ })));
    expect(within(table).getByRole("row", { name: /Note 41/ }).className).toContain("is-selected");
  });

  it("states a tech component's structured WAF measurement: the verdict, the hosts measured and the run behind it", async () => {
    mockIntel({
      tech_component: [
        { id: 41, component: "wafw00f sweep", provenance: { command_run_id: 8, waf: { verdict: "none_detected", hosts: ["api.acme.example", "shop.acme.example"] } } },
        { id: 42, component: "Acme Edge WAF", provenance: { command_run_id: 7, waf: { verdict: "detected", hosts: ["www.acme.example"] } } },
        { id: 43, component: "nginx", provenance: { agent_name: "recon-specialist" } },
      ] as never[],
    });
    const view = render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="tech_component" initialIntelId={41} /></ToastProvider>);
    const measured = await screen.findByRole("group", { name: "WAF measurement" });
    // A measured negative reads as a result, not as a missing one.
    expect(within(measured).getByText("No WAF detected")).toBeTruthy();
    expect(within(measured).getAllByRole("listitem").map((item) => item.textContent)).toEqual(["api.acme.example", "shop.acme.example"]);
    expect(within(measured).getByRole("link", { name: "Command run #8" }).getAttribute("href")).toBe("#/engagements/demo?tab=commands&command=8");

    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="tech_component" initialIntelId={42} /></ToastProvider>);
    await waitFor(() => expect(within(screen.getByRole("group", { name: "WAF measurement" })).getByText("WAF detected")).toBeTruthy());
    // A component without a measurement has no such section.
    view.rerender(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="tech_component" initialIntelId={43} /></ToastProvider>);
    await screen.findByRole("heading", { level: 2, name: "nginx" });
    expect(screen.queryByRole("group", { name: "WAF measurement" })).toBeNull();
  });

  it("says in the list which tech components are WAF measurements, with the verdict and how many hosts it covers", async () => {
    mockIntel({
      tech_component: [
        { id: 41, component: "wafw00f sweep", evidence_ref: "recon/wafw00f.json", provenance: { command_run_id: 8, waf: { verdict: "none_detected", hosts: ["api.acme.example", "shop.acme.example"] } } },
        { id: 42, component: "Acme Edge WAF", provenance: { command_run_id: 7, waf: { verdict: "detected", hosts: ["www.acme.example"] } } },
        { id: 43, component: "nginx", evidence_ref: "recon/httpx.json", provenance: { agent_name: "recon-specialist" } },
      ] as never[],
    });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const table = screen.getByRole("table", { name: "Intel records" });
    const negative = await within(table).findByRole("row", { name: /wafw00f sweep/ });
    expect(negative.textContent).toContain("WAF measurement: No WAF detected on 2 hosts · recon/wafw00f.json");
    expect(within(table).getByRole("row", { name: /Acme Edge WAF/ }).textContent).toContain("WAF measurement: WAF detected on 1 host");
    expect(within(table).getByRole("row", { name: /nginx/ }).textContent).not.toContain("WAF measurement");
  });

  it("shows a WAF measurement the readiness check cannot read as it was recorded", async () => {
    mockIntel({
      tech_component: [{ id: 44, component: "Edge", provenance: { waf: { verdict: "maybe", hosts: "www.acme.example" } } }] as never[],
    });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="tech_component" initialIntelId={44} /></ToastProvider>);
    const measured = await screen.findByRole("group", { name: "WAF measurement" });
    expect(measured.textContent).toContain("maybe");
    expect(measured.textContent).toContain("No command run is cited");
    expect(measured.textContent).toContain("\"www.acme.example\"");
  });

  it("says a WAF measurement names no hosts, and where an unreadable measurement is reported", async () => {
    mockIntel({
      tech_component: [{ id: 45, component: "Edge", provenance: { command_run_id: 9, waf: { verdict: "detected", hosts: [] } } }] as never[],
    });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} initialIntelType="tech_component" initialIntelId={45} /></ToastProvider>);
    const measured = await screen.findByRole("group", { name: "WAF measurement" });
    expect(within(measured).getByText("No hosts recorded")).toBeTruthy();
    // A measurement that names no hosts closes no host's WAF tier; the view points at where the check says so.
    expect(measured.textContent).toContain("A measurement it cannot read closes none");
    expect(within(measured).getByRole("link", { name: "Report checks" }).getAttribute("href")).toBe("#/engagements/demo");
  });

  it("says how many tags a row leaves out and names them", async () => {
    mockIntel({ note: [{ id: 1, title: "Acme auth map", tags: ["sso", "saml", "oidc", "mfa", "session-fixation", "password-reset"] } as never] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const row = await screen.findByRole("row", { name: /Acme auth map/ });
    expect(within(row).getByText("sso")).toBeTruthy();
    expect(within(row).queryByText("password-reset")).toBeNull();
    const more = within(row).getByText(/\+\s*2/);
    expect(more.getAttribute("title")).toContain("session-fixation");
    expect(more.getAttribute("title")).toContain("password-reset");
  });

  it("says how many records match in the palette when it lists only the first of them", async () => {
    mockIntel({ note: notes(35) });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByRole("button", { name: /Note 01/ });
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    const dialog = screen.getByRole("dialog", { name: "Jump to intel" });
    const input = within(dialog).getByRole("textbox", { name: "Search intel to jump to" });
    fireEvent.change(input, { target: { value: "note" } });
    const listed = dialog.querySelectorAll(".cmd-item").length;
    expect(listed).toBeLessThan(35);
    expect(within(dialog).getByRole("status").textContent).toMatch(new RegExp(`${listed}\\D+35`));
    // A search that lists every match has nothing to add.
    fireEvent.change(input, { target: { value: "Note 07" } });
    expect(dialog.querySelectorAll(".cmd-item")).toHaveLength(1);
    expect(within(dialog).queryByRole("status")).toBeNull();
  });

  it("lays the list out as a table of records with sortable column headers", async () => {
    mockIntel({ note: [{ id: 1, title: "Bravo", tags: ["edge"] }] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    const table = screen.getByRole("table", { name: "Intel records" });
    expect(within(table).getAllByRole("columnheader").map((header) => header.textContent)).toEqual(["Type", "Title / subtitle", "Location", "Tags", "Status"]);
    const row = await within(table).findByRole("row", { name: /Bravo/ });
    expect(within(row).getAllByRole("cell").map((cell) => cell.textContent)).toEqual([
      "Notes", expect.stringContaining("Bravo"), "", "edge", "",
    ]);
    fireEvent.click(within(row).getByRole("button", { name: "Bravo" }));
    expect(await screen.findByRole("heading", { level: 2, name: "Bravo" })).toBeTruthy();
  });

  it("offers open leads as the Needs attention scope and keeps the view across visits", async () => {
    mockIntel({
      note: [
        { id: 1, title: "Live lead", lead_status: "open" },
        { id: 2, title: "Replaced lead", lead_status: "open", superseded_by_id: 1 },
        { id: 3, title: "Reference", lead_status: null },
      ],
    });
    const first = render(<ToastProvider><IntelTab engagementKey="scope-demo" summary={{ counts: {} }} /></ToastProvider>);
    const all = await screen.findByRole("button", { name: /^All\s*3/ });
    expect(all.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: /^Needs attention\s*1/ }));
    expect(resultsText()).toMatch(/^1 of 3 intel records/);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search intel" }), { target: { value: "live" } });
    first.unmount();

    render(<ToastProvider><IntelTab engagementKey="scope-demo" summary={{ counts: {} }} /></ToastProvider>);
    expect((await screen.findByRole("button", { name: /^Needs attention\s*1/ })).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByRole("searchbox", { name: "Search intel" }) as HTMLInputElement).value).toBe("live");
    expect(await screen.findByRole("button", { name: "Live lead" })).toBeTruthy();
  });

  it("sorts by status with the most urgent first and records without a status last", async () => {
    mockIntel({ note: [{ id: 1, title: "Settled lead", lead_status: "resolved" }, { id: 2, title: "Plain note" }, { id: 3, title: "Fresh lead", lead_status: "open" }] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByRole("button", { name: "Plain note" });
    fireEvent.click(screen.getByRole("button", { name: /^Status/ }));
    expect(screen.getByRole("columnheader", { name: /Status/ }).getAttribute("aria-sort")).toBe("descending");
    expect(resultsText()).toContain("Sorted by Status, most urgent first");
    const titles = () => [...document.querySelectorAll(".intel-row-open")].map((button) => button.textContent);
    expect(titles()).toEqual(["Fresh lead", "Settled lead", "Plain note"]);
    fireEvent.click(screen.getByRole("button", { name: /^Status/ }));
    expect(resultsText()).toContain("Sorted by Status, least urgent first");
    expect(titles()).toEqual(["Settled lead", "Fresh lead", "Plain note"]);
  });

  it("sorts by a column header and says so", async () => {
    mockIntel({ note: [{ id: 1, title: "Bravo" }, { id: 2, title: "Alpha" }] });
    render(<ToastProvider><IntelTab engagementKey="demo" summary={{ counts: {} }} /></ToastProvider>);
    await screen.findByRole("button", { name: /Bravo/ });
    fireEvent.click(screen.getByRole("button", { name: /^Title/ }));
    expect(screen.getByRole("columnheader", { name: /Title/ }).getAttribute("aria-sort")).toBe("ascending");
    expect(resultsText()).toContain("Sorted by Title, A to Z");
    const rows = screen.getAllByRole("button", { name: /Alpha|Bravo/ });
    expect(rows[0].textContent).toContain("Alpha");
  });
});
