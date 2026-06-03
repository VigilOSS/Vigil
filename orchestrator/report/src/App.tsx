import { useEffect, useState } from "react";
import type { ReportData } from "./types";
import { devData } from "./devData";
import { Header, type TabId } from "./components/Header";
import { Footer } from "./components/Footer";
import { BackToTop } from "./components/BackToTop";
import { StatisticsTab } from "./components/StatisticsTab";
import { FindingsTab } from "./components/FindingsTab";
import { FullReport } from "./components/FullReport";

// The sentinel the backend replaces with the real JSON payload. It is itself a
// valid JSON string, so an un-injected template parses to exactly this value
// and we fall back to the committed dev fixture.
const SENTINEL = "__VIGIL_REPORT_DATA__";

function loadReportData(): ReportData {
  const node = document.getElementById("vigil-report-data");
  if (node?.textContent) {
    try {
      const parsed = JSON.parse(node.textContent);
      if (parsed && typeof parsed === "object" && parsed !== SENTINEL) {
        return parsed as ReportData;
      }
    } catch {
      /* malformed injection — fall through to dev fixture */
    }
  }
  return devData;
}

const HASH_TO_TAB: Record<string, TabId> = {
  "#Statistics": "statistics",
  "#Findings": "findings",
  "#Full-Report": "report",
};

const TAB_TO_HASH: Record<TabId, string> = {
  statistics: "#Statistics",
  findings: "#Findings",
  report: "#Full-Report",
};

function getTabFromHash(): TabId {
  return HASH_TO_TAB[window.location.hash] ?? "statistics";
}

const data = loadReportData();

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>(getTabFromHash);

  // Sync hash -> tab on back/forward navigation.
  useEffect(() => {
    const onHashChange = () => setActiveTab(getTabFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // Sync tab -> hash; statistics is the default (no hash). Scroll to top on
  // tab switch so the hero / first section is visible.
  useEffect(() => {
    const desired = activeTab === "statistics" ? "" : TAB_TO_HASH[activeTab];
    if (window.location.hash !== desired) {
      const url = desired || window.location.pathname + window.location.search;
      window.history.replaceState(null, "", url);
    }
    window.scrollTo({ top: 0 });
  }, [activeTab]);

  const findingCount = data.finding_groups.finding_count ?? 0;

  return (
    <div className="rpt-app">
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        engagementTarget={data.engagement.target}
        findingCount={findingCount}
        mode={data.mode}
      />
      <main className="rpt-main">
        {activeTab === "statistics" && <StatisticsTab data={data} />}
        {activeTab === "findings" && <FindingsTab data={data} />}
        {activeTab === "report" && <FullReport data={data} />}
      </main>
      <Footer generatedAt={data.generated_at} vigilVersion={data.vigil_version} mode={data.mode} />
      <BackToTop />
    </div>
  );
}
