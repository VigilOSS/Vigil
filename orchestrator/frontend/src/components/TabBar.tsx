// Rationale for the order:
//   Overview   — at-a-glance dashboard, always first
//   Intel      — "what do we know about the target" (pre-attack context),
//                sits next to Overview because operators triage intel before
//                they attack surfaces or dig into findings
//   Findings   — the primary deliverable, high up
//   Surfaces   — what we can attack (bridges intel → findings)
//   Coverage   — where we've tested (quantitative companion to Surfaces)
//   Code       — code-analysis results, own domain
//   Commands   — aith assess command-run audit; a deeper cut of Activity that
//                exposes per-tool exit codes, output retention, and argv
//                so operators can audit what actually ran
//   Activity   — structured state-change timeline
//   Log        — narrative prose activity (sits next to Activity so the
//                two log-style tabs are adjacent)
//   Artifacts  — raw files, last (catch-all archive)
export const TABS = [
  { key: "overview", label: "Overview" },
  { key: "intel", label: "Intel" },
  { key: "findings", label: "Findings" },
  { key: "surfaces", label: "Surfaces" },
  { key: "coverage", label: "Coverage" },
  { key: "code", label: "Code" },
  { key: "commands", label: "Commands" },
  { key: "activity", label: "Activity" },
  { key: "log", label: "Log" },
  { key: "artifacts", label: "Artifacts" },
] as const;

export type TabKey = (typeof TABS)[number]["key"];

type TabBarProps = {
  active: TabKey;
  onChange: (tab: TabKey) => void;
  counts?: Partial<Record<TabKey, number>>;
};

export function TabBar({ active, onChange, counts }: TabBarProps) {
  return (
    <nav className="tab-bar">
      {TABS.map((tab) => (
        <button
          key={tab.key}
          type="button"
          className={`tab-button ${active === tab.key ? "tab-active" : ""}`}
          onClick={() => onChange(tab.key)}
        >
          {tab.label}
          {counts?.[tab.key] != null && counts[tab.key]! > 0 && (
            <span className="tab-count">{counts[tab.key]}</span>
          )}
        </button>
      ))}
    </nav>
  );
}
