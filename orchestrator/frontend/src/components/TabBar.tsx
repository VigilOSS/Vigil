import { useRef } from "react";

// Rationale for the order:
//   Overview   — at-a-glance dashboard, always first
//   Runs       — shared code/web/blue audit and comparison surface
//   Intel      — "what do we know about the target" (pre-attack context),
//                sits next to Overview because operators triage intel before
//                they attack surfaces or dig into findings
//   Findings   — the primary deliverable, high up
//   Submissions — human review and immutable filing packages, directly after
//                 the finding records they snapshot
//   Surfaces   — what we can attack (bridges intel → findings)
//   HTTP       — observed request traffic (one row per request variant);
//                surface-adjacent because a variant IS an attackable
//                endpoint, so it sits right after Surfaces
//   Coverage   — where we've tested (quantitative companion to Surfaces)
//   Code       — code-analysis results, own domain
//   Commands   — vigil assess command-run audit; a deeper cut of Activity that
//                exposes per-tool exit codes, output retention, and argv
//                so operators can audit what actually ran
//   OAST       — out-of-band callback probes + interactions; execution
//                evidence like Commands, so it sits right after it
//   Events     — compact structured state-change timeline
//   Audit log  — searchable narrative ledger
//   Engagement files — the small set of root working documents. This is not
//                the canonical assessment-artifact ledger.
export const TABS = [
  { key: "overview", label: "Overview" },
  { key: "runs", label: "Runs" },
  { key: "intel", label: "Intel" },
  { key: "findings", label: "Findings" },
  { key: "submissions", label: "Submissions" },
  { key: "surfaces", label: "Surfaces" },
  { key: "http", label: "HTTP" },
  { key: "coverage", label: "Coverage" },
  { key: "code", label: "Code" },
  { key: "commands", label: "Commands" },
  { key: "oast", label: "OAST" },
  { key: "activity", label: "Events" },
  { key: "log", label: "Audit log" },
  { key: "artifacts", label: "Engagement files" },
] as const;

export type TabKey = (typeof TABS)[number]["key"];

const TAB_GROUPS = [
  { label: "Workspace", keys: ["overview", "runs", "intel"] },
  { label: "Assessment", keys: ["findings", "submissions", "surfaces", "http", "coverage", "code"] },
  { label: "Evidence", keys: ["commands", "oast", "activity", "log", "artifacts"] },
] as const;

type TabBarProps = {
  active: TabKey;
  onChange: (tab: TabKey) => void;
  counts?: Partial<Record<TabKey, number | string>>;
};

export function TabBar({ active, onChange, counts }: TabBarProps) {
  const buttonsRef = useRef<Array<HTMLButtonElement | null>>([]);

  function moveFrom(index: number, key: string) {
    let nextIndex: number | null = null;
    if (key === "ArrowRight" || key === "ArrowDown") nextIndex = (index + 1) % TABS.length;
    if (key === "ArrowLeft" || key === "ArrowUp") nextIndex = (index - 1 + TABS.length) % TABS.length;
    if (key === "Home") nextIndex = 0;
    if (key === "End") nextIndex = TABS.length - 1;
    if (nextIndex == null) return;
    onChange(TABS[nextIndex].key);
    buttonsRef.current[nextIndex]?.focus();
  }

  return (
    <nav className="tab-bar workspace-rail" role="tablist" aria-label="Engagement views" aria-orientation="vertical">
      {TAB_GROUPS.map(group => <div className="workspace-nav-group" key={group.label} role="presentation">
        <p className="workspace-nav-label">{group.label}</p>
        {TABS.filter(tab => (group.keys as readonly string[]).includes(tab.key)).map((tab) => {
          const index = TABS.findIndex(item => item.key === tab.key);
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
          onClick={() => onChange(tab.key)}
          onKeyDown={(event) => {
            if (["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
              event.preventDefault();
            }
            moveFrom(index, event.key);
          }}
        >
          {tab.label}
          {counts?.[tab.key] != null && (typeof counts[tab.key] === "string" || Number(counts[tab.key]) > 0) && (
            <span className="tab-count">{counts[tab.key]}</span>
          )}
        </button>
      ); })}
      </div>)}
    </nav>
  );
}
