import { useMemo, useState } from "react";
import { Check, Copy } from "lucide-react";
import type { ReportAttackChain, ReportData, ReportFinding } from "../types";
import { formatDateTime, formatLabel, SEVERITY_RANK } from "../lib/format";
import { findingToMarkdown } from "../lib/findingMarkdown";
import { stepsText } from "../lib/steps";
import { Markdown } from "./Markdown";

interface Props {
  data: ReportData;
}

// Ordered report sections: each group (root + siblings) and each standalone
// finding becomes one numbered section, ordered by highest severity. We keep
// groups intact (root then siblings) rather than splitting them across the
// severity ordering so the root-cause story reads top-to-bottom.
interface Section {
  anchor: string;
  number: string;
  title: string;
  severity: string;
  root: ReportFinding;
  siblings: ReportFinding[];
}

function sectionAnchor(finding: ReportFinding): string {
  return `finding-${finding.slug ?? finding.report_id ?? finding.title ?? "x"}`
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-");
}

function CopyMarkdownButton({ finding }: { finding: ReportFinding }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    const md = findingToMarkdown(finding);
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API unavailable (e.g. file:// without permission) — fall back
      // to a hidden textarea + execCommand so the button still works offline.
      const ta = document.createElement("textarea");
      ta.value = md;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      } catch {
        /* give up silently */
      }
      document.body.removeChild(ta);
    }
  };
  return (
    <button type="button" className="rpt-copy-btn no-print" onClick={onCopy}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
      {copied ? "Copied" : "Copy as Markdown"}
    </button>
  );
}

function FindingBlock({ finding, kind }: { finding: ReportFinding; kind: "root" | "sibling" | "standalone" }) {
  const sev = finding.severity ?? "info";
  return (
    <article className="rpt-doc-finding" id={kind !== "sibling" ? sectionAnchor(finding) : undefined}>
      <header className="rpt-doc-finding-head">
        <h3>
          <span className="rpt-mono">{finding.report_id ?? finding.slug}</span> {finding.title}
          {kind === "sibling" && <span className="rpt-sibling-tag">shares root cause</span>}
        </h3>
        <div className="rpt-doc-finding-tags">
          <span className={`rpt-sev-badge rpt-sev-${sev}`}>{formatLabel(sev)}</span>
          {finding.cvss_score != null && (
            <span className="rpt-chip">CVSS {Number(finding.cvss_score).toFixed(1)}</span>
          )}
          {finding.cwe_id && <span className="rpt-chip">{finding.cwe_id}</span>}
          <CopyMarkdownButton finding={finding} />
        </div>
      </header>
      {finding.canonical_location && (
        <p className="rpt-doc-location rpt-mono">{finding.canonical_location}</p>
      )}
      {finding.summary && (
        <div className="rpt-doc-block">
          <h4>Summary</h4>
          <Markdown text={finding.summary} />
        </div>
      )}
      {finding.impact && (
        <div className="rpt-doc-block">
          <h4>Impact</h4>
          <Markdown text={finding.impact} />
        </div>
      )}
      {finding.evidence_detail && (
        <div className="rpt-doc-block">
          <h4>Evidence</h4>
          <Markdown text={finding.evidence_detail} />
        </div>
      )}
      {stepsText(finding.steps_to_reproduce) && (
        <div className="rpt-doc-block">
          <h4>Steps to reproduce</h4>
          {/* Verbatim — the author's numbering is what other sections cite. */}
          <div className="rpt-steps">{stepsText(finding.steps_to_reproduce)}</div>
        </div>
      )}
      {finding.poc_code && (
        <div className="rpt-doc-block">
          <h4>Proof of concept</h4>
          <pre className="rpt-code">{finding.poc_code}</pre>
        </div>
      )}
      {finding.remediation && (
        <div className="rpt-doc-block">
          <h4>Remediation</h4>
          <Markdown text={finding.remediation} />
        </div>
      )}
    </article>
  );
}

function AttackChainBlock({ chain }: { chain: ReportAttackChain }) {
  const sev = chain.severity ?? "info";
  return (
    <article className="rpt-doc-chain">
      <header className="rpt-doc-finding-head">
        <h3>{chain.title ?? chain.chain_key}</h3>
        <div className="rpt-doc-finding-tags">
          <span className={`rpt-sev-badge rpt-sev-${sev}`}>{formatLabel(sev)}</span>
          {chain.status && <span className="rpt-chip">{formatLabel(chain.status)}</span>}
          {chain.updated_at && <span className="rpt-chip">{formatDateTime(chain.updated_at)}</span>}
        </div>
      </header>
      {chain.narrative && <Markdown text={chain.narrative} />}
    </article>
  );
}

export function FullReport({ data }: Props) {
  const { finding_groups, attack_chains, engagement } = data;

  const sections = useMemo<Section[]>(() => {
    const built: Section[] = [];
    for (const group of finding_groups.groups) {
      built.push({
        anchor: sectionAnchor(group.root),
        number: "",
        title: group.root.title ?? group.root.slug ?? "Finding",
        severity: group.highest_severity ?? group.root.severity ?? "info",
        root: group.root,
        siblings: group.siblings,
      });
    }
    for (const finding of finding_groups.standalone) {
      built.push({
        anchor: sectionAnchor(finding),
        number: "",
        title: finding.title ?? finding.slug ?? "Finding",
        severity: finding.severity ?? "info",
        root: finding,
        siblings: [],
      });
    }
    built.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return String(a.root.report_id ?? "").localeCompare(String(b.root.report_id ?? ""));
    });
    return built.map((section, i) => ({ ...section, number: String(i + 1) }));
  }, [finding_groups]);

  return (
    <div className="rpt-doc">
      <div className="rpt-doc-titlepage">
        <p className="rpt-eyebrow">Security Assessment Report</p>
        <h1>{engagement.target}</h1>
        <p className="rpt-doc-subtitle">
          {engagement.customer ? `${engagement.customer} · ` : ""}
          {engagement.key}
        </p>
        <p className="rpt-doc-subtitle">
          {formatLabel(data.mode)} · Generated {formatDateTime(data.generated_at)}
        </p>
      </div>

      <nav className="rpt-toc">
        <h2>Contents</h2>
        <ol>
          {sections.map((section) => (
            <li key={section.anchor}>
              <a href={`#${section.anchor}`}>
                <span className={`rpt-sev-dot rpt-sev-${section.severity}`} aria-hidden="true" />
                {section.title}
              </a>
            </li>
          ))}
          {attack_chains.length > 0 && (
            <li>
              <a href="#appendix-attack-chains">Appendix A — Attack chains</a>
            </li>
          )}
        </ol>
      </nav>

      {sections.length === 0 && (
        <p className="rpt-empty">No reportable findings in this {data.mode} report.</p>
      )}

      {sections.map((section) => (
        <section key={section.anchor} className="rpt-doc-section">
          <FindingBlock finding={section.root} kind={section.siblings.length > 0 ? "root" : "standalone"} />
          {section.siblings.map((sibling) => (
            <FindingBlock key={String(sibling.slug ?? sibling.report_id)} finding={sibling} kind="sibling" />
          ))}
        </section>
      ))}

      {attack_chains.length > 0 && (
        <section className="rpt-doc-section" id="appendix-attack-chains">
          <h2 className="rpt-appendix-title">Appendix A — Attack chains</h2>
          {attack_chains.map((chain) => (
            <AttackChainBlock key={String(chain.chain_key ?? chain.title)} chain={chain} />
          ))}
        </section>
      )}
    </div>
  );
}

export default FullReport;
