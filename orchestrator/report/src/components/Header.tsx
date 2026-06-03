import { BarChart3, FileText, Printer, Shield, ShieldCheck } from "lucide-react";
import { ThemeSwitcher } from "./ThemeSwitcher";

export type TabId = "statistics" | "findings" | "report";

interface Props {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  engagementTarget: string;
  findingCount: number;
  mode: "draft" | "final";
}

const TABS: { id: TabId; label: string; icon: typeof BarChart3 }[] = [
  { id: "statistics", label: "Statistics", icon: BarChart3 },
  { id: "findings", label: "Findings", icon: Shield },
  { id: "report", label: "Full Report", icon: FileText },
];

export function Header({ activeTab, onTabChange, engagementTarget, findingCount, mode }: Props) {
  return (
    <header className="rpt-topbar no-print">
      <div className="rpt-topbar-in">
        <div className="rpt-brand">
          <ShieldCheck size={18} aria-hidden="true" />
          <span className="rpt-brand-name">Vigil</span>
          <span className="rpt-brand-sep">/</span>
          <span className="rpt-brand-target" title={engagementTarget}>
            {engagementTarget}
          </span>
          <span className={`rpt-mode-badge rpt-mode-${mode}`}>{mode}</span>
        </div>

        <nav className="rpt-nav">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              className={`rpt-nav-btn${activeTab === id ? " is-active" : ""}`}
              onClick={() => onTabChange(id)}
            >
              <Icon size={14} />
              {label}
              {id === "findings" && findingCount > 0 && <span className="rpt-pill">{findingCount}</span>}
            </button>
          ))}
        </nav>

        <div className="rpt-topbar-right">
          <button
            type="button"
            className="rpt-icon-btn no-print"
            onClick={() => window.print()}
            aria-label="Print report"
          >
            <Printer size={14} />
            <span>Print</span>
          </button>
          <ThemeSwitcher />
        </div>
      </div>
    </header>
  );
}

export default Header;
