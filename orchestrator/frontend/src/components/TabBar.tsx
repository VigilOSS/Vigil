import { useEffect, useRef, useState } from "react";

import { ChevronDown, Menu } from "lucide-react";

import type { RailBadge } from "../lib/railBadges";

// Rail groups, in visual order. Keyboard navigation follows this order too.
//   Overview      — at-a-glance dashboard, always first and ungrouped
//   Deliverables  — what the engagement produces for a human to review:
//                   Findings, the Proof work that settles them, and the
//                   immutable Submissions filed from them
//   Target        — what we know about the target and how far testing has
//                   reached it: Intel (pre-attack context), Surfaces (what we
//                   can attack), HTTP (observed request variants), Coverage
//                   (where we have tested), Code (source-analysis results)
//   Execution     — what actually ran: Runs (code/web/blue audit and
//                   comparison), Commands (per-tool argv, exit codes, output
//                   retention), OAST (out-of-band probes and callbacks)
//   Record        — the engagement's history and working documents: Activity
//                   (the audit log and structured events as one newest-first
//                   record) and Files (the brief, handoff, memory, and
//                   snapshots in the engagement root)
// Badges say what needs the operator (see lib/railBadges.ts), never a raw total.
export const TABS = [
  { key: "overview", label: "Overview" },
  { key: "findings", label: "Findings" },
  { key: "proof", label: "Proof work" },
  { key: "submissions", label: "Submissions" },
  { key: "intel", label: "Intel" },
  { key: "surfaces", label: "Surfaces" },
  { key: "http", label: "HTTP" },
  { key: "coverage", label: "Coverage" },
  { key: "code", label: "Code" },
  { key: "runs", label: "Runs" },
  { key: "commands", label: "Commands" },
  { key: "oast", label: "OAST" },
  { key: "activity", label: "Activity" },
  { key: "artifacts", label: "Files" },
] as const;

export type TabKey = (typeof TABS)[number]["key"];

const TAB_GROUPS: ReadonlyArray<{ label: string | null; keys: readonly TabKey[] }> = [
  { label: null, keys: ["overview"] },
  { label: "Deliverables", keys: ["findings", "proof", "submissions"] },
  { label: "Target", keys: ["intel", "surfaces", "http", "coverage", "code"] },
  { label: "Execution", keys: ["runs", "commands", "oast"] },
  { label: "Record", keys: ["activity", "artifacts"] },
];

// Keyboard order is the rendered order: groups top to bottom.
const RAIL_ORDER: readonly (typeof TABS)[number][] = TAB_GROUPS.flatMap((group) =>
  group.keys.map((key) => TABS.find((tab) => tab.key === key)!),
);

type TabBarProps = {
  active: TabKey;
  onChange: (tab: TabKey) => void;
  badges?: Partial<Record<TabKey, RailBadge>>;
};

// ARIA tabs with manual activation: arrow keys, Home and End move focus only;
// Enter, Space or a click opens the view, so walking the rail never loads
// each view or adds a history entry per key press. Below the narrow
// breakpoint (workspace.css) the rail collapses behind a "View: …" button.
export function TabBar({ active, onChange, badges }: TabBarProps) {
  const buttonsRef = useRef<Array<HTMLButtonElement | null>>([]);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const activeTab = TABS.find((tab) => tab.key === active);
  const activeBadge = badges?.[active];

  // A click or focus outside the open menu closes it.
  useEffect(() => {
    if (!menuOpen) return undefined;
    const close = (event: Event) => {
      if (event.target instanceof Node && wrapRef.current?.contains(event.target)) return;
      setMenuOpen(false);
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("focusin", close);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("focusin", close);
    };
  }, [menuOpen]);

  // Opening the menu moves focus to the open view's tab, so the arrow keys
  // walk the menu at once.
  useEffect(() => {
    if (!menuOpen) return;
    buttonsRef.current[RAIL_ORDER.findIndex((tab) => tab.key === active)]?.focus();
    // Only on opening: `active` changes only with a choice, which closes the menu.
  }, [menuOpen]);

  function moveFrom(index: number, key: string) {
    let nextIndex: number | null = null;
    if (key === "ArrowRight" || key === "ArrowDown") nextIndex = (index + 1) % RAIL_ORDER.length;
    if (key === "ArrowLeft" || key === "ArrowUp") nextIndex = (index - 1 + RAIL_ORDER.length) % RAIL_ORDER.length;
    if (key === "Home") nextIndex = 0;
    if (key === "End") nextIndex = RAIL_ORDER.length - 1;
    if (nextIndex == null) return;
    buttonsRef.current[nextIndex]?.focus();
  }

  function choose(tab: TabKey) {
    setMenuOpen(false);
    onChange(tab);
  }

  return (
    <div
      className="workspace-rail-wrap"
      ref={wrapRef}
      data-open={menuOpen || undefined}
      onKeyDown={(event) => {
        // Escape from the menu button or any tab closes the open menu.
        if (event.key !== "Escape" || !menuOpen) return;
        event.preventDefault();
        setMenuOpen(false);
        toggleRef.current?.focus();
      }}
    >
      <button
        ref={toggleRef}
        type="button"
        className="workspace-rail-toggle"
        aria-expanded={menuOpen}
        aria-controls="workspace-rail-tabs"
        onClick={() => setMenuOpen((open) => !open)}
      >
        <Menu size={16} aria-hidden="true" />
        <span className="workspace-rail-toggle-label">View: <strong>{activeTab?.label}</strong></span>
        {activeBadge && (
          <span className="tab-count" title={activeBadge.label}>
            <span aria-hidden="true">{activeBadge.text}</span>
            <span className="sr-only">{activeBadge.label}</span>
          </span>
        )}
        <ChevronDown size={14} aria-hidden="true" className="workspace-rail-toggle-chevron" />
      </button>
      <nav id="workspace-rail-tabs" className="tab-bar workspace-rail" role="tablist" aria-label="Engagement views" aria-orientation="vertical">
        {TAB_GROUPS.map(group => <div className="workspace-nav-group" key={group.label ?? "top"} role="presentation">
          {group.label && <p className="workspace-nav-label">{group.label}</p>}
          {group.keys.map((key) => {
            const index = RAIL_ORDER.findIndex(item => item.key === key);
            const tab = RAIL_ORDER[index];
            const badge = badges?.[tab.key];
            return (
          <button
            key={tab.key}
            ref={(node) => { buttonsRef.current[index] = node; }}
            type="button"
            role="tab"
            id={`workspace-tab-${tab.key}`}
            aria-controls="workspace-panel"
            aria-selected={active === tab.key}
            tabIndex={active === tab.key ? 0 : -1}
            className={`tab-button ${active === tab.key ? "tab-active" : ""}`}
            onClick={() => choose(tab.key)}
            onKeyDown={(event) => {
              if (["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
                event.preventDefault();
                moveFrom(index, event.key);
              }
            }}
          >
            {tab.label}
            {badge && (
              <span className="tab-count" title={badge.label}>
                <span aria-hidden="true">{badge.text}</span>
                <span className="sr-only">{badge.label}</span>
              </span>
            )}
          </button>
        ); })}
        </div>)}
      </nav>
    </div>
  );
}
