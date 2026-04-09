export const TABS = [
  { key: "overview", label: "Overview" },
  { key: "findings", label: "Findings" },
  { key: "coverage", label: "Coverage" },
  { key: "code", label: "Code" },
  { key: "activity", label: "Activity" },
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
