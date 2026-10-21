import { useEffect, type ComponentProps } from "react";
import { engagementHref } from "../lib/workspaceRoutes";
import { RecordHeader } from "./record/RecordView";
import { SeverityTag, StatusPill } from "./ui";
import "../styles/findingRecord.css";

type Workspace = "findings" | "submissions";
const defaultSection = { findings: "overview", submissions: "body" };
const sectionKey = (engagement: string, slug: string, workspace: Workspace) =>
  `finding.section.${JSON.stringify([engagement, slug, workspace])}`;

/** Shared identity and status axes; each queue retains its own data and actions. */
export function FindingRecordHeader({ engagementKey, slug, severity, workflow, verification, submission,
  workspace, section, children, pills, ...header
}: Omit<ComponentProps<typeof RecordHeader>, "id" | "copyId" | "accent"> & {
  engagementKey: string; slug: string; severity: string;
  workflow?: string; verification?: string; submission?: string;
  workspace: Workspace; section: string;
}) {
  useEffect(() => {
    try { window.sessionStorage.setItem(sectionKey(engagementKey, slug, workspace), section); }
    catch { /* Navigation still works when browser storage is unavailable. */ }
  }, [engagementKey, slug, workspace, section]);
  const href = (target: Workspace) => {
    let selected = target === workspace ? section : defaultSection[target];
    if (target !== workspace) {
      try {
        const saved = window.sessionStorage.getItem(sectionKey(engagementKey, slug, target));
        // The destination owns section validation (including conditional Code).
        if (saved) selected = saved;
      } catch { /* Use the target's default section. */ }
    }
    return engagementHref(engagementKey, { tab: target, [target === "findings" ? "finding" : "submission"]: slug,
      dtab: selected === defaultSection[target] ? undefined : selected });
  };
  return <RecordHeader {...header} id={slug} copyId={slug} accent={`var(--sev-${severity})`}
    pills={<>
      <SeverityTag severity={severity} />
      <span className="finding-status-axis" role="group" aria-label="Workflow status">Workflow <StatusPill domain="finding-workflow" value={workflow ?? "unknown"} /></span>
      <span className="finding-status-axis" role="group" aria-label="Verification status">Verification <StatusPill domain="finding-verification" value={verification ?? "unknown"} /></span>
      <span className="finding-status-axis" role="group" aria-label="External submission status">External <StatusPill domain="finding-submission" value={submission ?? "none"} /></span>
      {pills}
    </>}>
    <nav className="finding-workflow-nav" aria-label="Finding workflow">
      <a href={href("findings")} aria-current={workspace === "findings" ? "page" : undefined}>Review finding</a>
      <a href={href("submissions")} aria-current={workspace === "submissions" ? "page" : undefined}>Disclosure package</a>
    </nav>
    {children}
  </RecordHeader>;
}
