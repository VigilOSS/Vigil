// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import { listIntel, listIntelCredentials } from "../lib/api";
import { IntelTab } from "./IntelTab";

vi.mock("../lib/api", () => ({
  intelByUrl: vi.fn(),
  listIntel: vi.fn(),
  listIntelCredentials: vi.fn(),
  searchIntel: vi.fn(),
}));

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
});
