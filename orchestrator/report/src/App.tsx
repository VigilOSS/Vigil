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

// The hash is shared by two kinds of link: the three tab hashes, and the
// in-document anchors the Full Report's table of contents points at
// (`#finding-…`, `#appendix-…`). Only the first kind may move the tab. Treating
// every hash as a tab request is what made the contents links destructive —
// an unrecognized hash fell back to `statistics`, which flipped the tab out from
// under the reader, and the tab->hash effect below then erased the anchor and
// scrolled to the top of a document they were no longer looking at.
function tabForHash(hash: string): TabId | null {
  return HASH_TO_TAB[hash] ?? null;
}

// A deep link to a finding names a place inside the Full Report, so it selects
// that tab even though it is not a tab hash.
function initialTab(): TabId {
  const hash = window.location.hash;
  const tab = tabForHash(hash);
  if (tab) return tab;
  if (hash.startsWith("#finding-") || hash.startsWith("#appendix-")) return "report";
  return "statistics";
}

const data = loadReportData();

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>(initialTab);

  // Sync hash -> tab on back/forward navigation. An anchor hash is left alone:
  // the browser has already scrolled to it.
  useEffect(() => {
    const onHashChange = () => {
      const tab = tabForHash(window.location.hash);
      if (tab) setActiveTab(tab);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // A deep-linked anchor cannot be resolved by the browser on first paint,
  // because the document it names is rendered by this component. Resolve it once
  // the first render has committed.
  useEffect(() => {
    const hash = window.location.hash;
    if (!hash || tabForHash(hash)) return;
    document.getElementById(hash.slice(1))?.scrollIntoView();
  }, []);

  // Selecting a tab owns the hash and the scroll reset. Doing this in an effect
  // keyed on `activeTab` instead would also fire for anchor navigation, which is
  // the bug above.
  const selectTab = (tab: TabId) => {
    setActiveTab(tab);
    const desired = tab === "statistics" ? "" : TAB_TO_HASH[tab];
    const url = desired || window.location.pathname + window.location.search;
    window.history.replaceState(null, "", url);
    window.scrollTo({ top: 0 });
  };

  const findingCount = data.finding_groups.finding_count ?? 0;

  return (
    <div className="rpt-app">
      <Header
        activeTab={activeTab}
        onTabChange={selectTab}
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
