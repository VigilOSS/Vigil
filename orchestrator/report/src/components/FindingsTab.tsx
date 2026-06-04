import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import type { ReportData, ReportFinding } from "../types";
import { flattenFindings, formatLabel, SEVERITY_ORDER, SEVERITY_RANK } from "../lib/format";
import { Markdown } from "./Markdown";

interface Props {
  data: ReportData;
}

type SortKey = "severity" | "report_id" | "title";
type SortDir = "asc" | "desc";

function severityRank(finding: ReportFinding): number {
  return SEVERITY_RANK[finding.severity ?? "info"] ?? 0;
}

function FindingDetail({ finding }: { finding: ReportFinding }) {
  return (
    <div className="rpt-finding-detail">
      {finding.summary && (
        <section>
          <h4>Summary</h4>
          <Markdown text={finding.summary} />
        </section>
      )}
      {finding.impact && (
        <section>
          <h4>Impact</h4>
          <Markdown text={finding.impact} />
        </section>
      )}
      {finding.evidence_detail && (
        <section>
          <h4>Evidence</h4>
          <Markdown text={finding.evidence_detail} />
        </section>
      )}
      {Array.isArray(finding.steps_to_reproduce) && finding.steps_to_reproduce.length > 0 && (
        <section>
          <h4>Steps to reproduce</h4>
          <ol className="rpt-steps">
            {finding.steps_to_reproduce.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </section>
      )}
      {finding.poc_code && (
        <section>
          <h4>Proof of concept</h4>
          <pre className="rpt-code">{finding.poc_code}</pre>
        </section>
      )}
      {finding.remediation && (
        <section>
          <h4>Remediation</h4>
          <Markdown text={finding.remediation} />
        </section>
      )}
      <dl className="rpt-finding-meta">
        {finding.canonical_location && (
          <div>
            <dt>Location</dt>
            <dd className="rpt-mono">{finding.canonical_location}</dd>
          </div>
        )}
        {finding.cwe_id && (
          <div>
            <dt>CWE</dt>
            <dd>{finding.cwe_id}</dd>
          </div>
        )}
        {finding.owasp_category && (
          <div>
            <dt>OWASP</dt>
            <dd>{finding.owasp_category}</dd>
          </div>
        )}
        {finding.cvss_vector && (
          <div>
            <dt>CVSS vector</dt>
            <dd className="rpt-mono">{finding.cvss_vector}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

export function FindingsTab({ data }: Props) {
  const flat = useMemo(() => flattenFindings(data.finding_groups), [data.finding_groups]);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let filtered = flat.map((entry) => entry.finding);
    if (severityFilter !== "all") {
      filtered = filtered.filter((f) => (f.severity ?? "info") === severityFilter);
    }
    if (needle) {
      filtered = filtered.filter((f) =>
        [f.title, f.slug, f.canonical_location, f.cwe_id, f.summary]
          .filter(Boolean)
          .some((field) => String(field).toLowerCase().includes(needle)),
      );
    }
    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") cmp = severityRank(a) - severityRank(b);
      else if (sortKey === "report_id")
        cmp = String(a.report_id ?? "").localeCompare(String(b.report_id ?? ""));
      else cmp = String(a.title ?? "").localeCompare(String(b.title ?? ""));
      return sortDir === "asc" ? cmp : -cmp;
    });
    return sorted;
  }, [flat, severityFilter, query, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "severity" ? "desc" : "asc");
    }
  };

  const toggleExpand = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const sortIndicator = (key: SortKey) => (sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "");

  return (
    <div className="rpt-section">
      <div className="rpt-table-controls no-print">
        <label className="rpt-search">
          <Search size={14} aria-hidden="true" />
          <input
            type="search"
            placeholder="Search findings…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search findings"
          />
        </label>
        <label className="rpt-select">
          <span>Severity</span>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All</option>
            {SEVERITY_ORDER.map((sev) => (
              <option key={sev} value={sev}>
                {formatLabel(sev)}
              </option>
            ))}
          </select>
        </label>
        <span className="rpt-result-count">
          {rows.length} of {flat.length}
        </span>
      </div>

      <table className="rpt-table">
        <thead>
          <tr>
            <th aria-hidden="true" className="rpt-col-toggle" />
            <th>
              <button type="button" className="rpt-th-btn" onClick={() => toggleSort("report_id")}>
                ID{sortIndicator("report_id")}
              </button>
            </th>
            <th>
              <button type="button" className="rpt-th-btn" onClick={() => toggleSort("severity")}>
                Severity{sortIndicator("severity")}
              </button>
            </th>
            <th>
              <button type="button" className="rpt-th-btn" onClick={() => toggleSort("title")}>
                Title{sortIndicator("title")}
              </button>
            </th>
            <th>CVSS</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={6} className="rpt-empty">
                No findings match the current filters.
              </td>
            </tr>
          )}
          {rows.map((finding) => {
            const key = String(finding.slug ?? finding.report_id ?? finding.title);
            const isOpen = expanded.has(key);
            return (
              <FindingRow
                key={key}
                finding={finding}
                isOpen={isOpen}
                onToggle={() => toggleExpand(key)}
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FindingRow({
  finding,
  isOpen,
  onToggle,
}: {
  finding: ReportFinding;
  isOpen: boolean;
  onToggle: () => void;
}) {
  const sev = finding.severity ?? "info";
  return (
    <>
      <tr className="rpt-row" onClick={onToggle}>
        <td className="rpt-col-toggle">
          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </td>
        <td className="rpt-mono">{finding.report_id ?? finding.slug ?? "—"}</td>
        <td>
          <span className={`rpt-sev-badge rpt-sev-${sev}`}>{formatLabel(sev)}</span>
        </td>
        <td>{finding.title ?? "Untitled finding"}</td>
        <td className="rpt-mono">{finding.cvss_score != null ? Number(finding.cvss_score).toFixed(1) : "—"}</td>
        <td>{formatLabel(finding.workflow_status)}</td>
      </tr>
      {isOpen && (
        <tr className="rpt-detail-row">
          <td colSpan={6}>
            <FindingDetail finding={finding} />
          </td>
        </tr>
      )}
    </>
  );
}

export default FindingsTab;
