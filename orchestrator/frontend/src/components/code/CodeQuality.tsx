import type { ReactNode } from "react";

import type {
  CodeCoverage,
  CodeDepthAdvisory,
  CodeEffortGaps,
  CodeOptionalFamilies,
  CodeReadiness,
  CodeUntriggeredDepthShortfalls,
} from "../../lib/api";
import {
  CLASSIFICATION_LABELS,
  QUALITY_GROUP_LABELS,
  familyLabel,
  parseQualityWarning,
  underReviewedLabel,
  type QualityWarning,
} from "./codeLabels";
import { codeViewHref } from "./useCodeRoute";

/** Readiness carries the merged quality warnings; coverage is the fallback. */
export function qualityWarnings(readiness: CodeReadiness | null, coverage: CodeCoverage | null): QualityWarning[] {
  const raw = readiness?.quality_gate.warnings ?? [
    ...(coverage?.gate.effort_warnings ?? []),
    ...(coverage?.gate.coverage_integrity ?? []).flatMap((item) =>
      (item.warnings ?? []).map((warning) => `${item.file_path ?? "unknown file"}: ${warning}`),
    ),
  ];
  return [...new Set(raw)].map(parseQualityWarning);
}

/** The coverage summary's grouped effort gaps, when it carries any. */
export function effortGapGroups(coverage: CodeCoverage | null): CodeEffortGaps | null {
  const gaps = coverage?.gate.effort_gaps;
  return gaps && gaps.groups.length > 0 ? gaps : null;
}

/**
 * The section's badge count: each warning once, with the grouped effort lines
 * counted as the gaps they stand for.
 */
export function qualityCount(warnings: QualityWarning[], gaps: CodeEffortGaps | null): number {
  if (!gaps) return warnings.length;
  return gaps.total + warnings.filter((warning) => warning.kind !== "effort_group").length;
}

const FULL_LIST_COMMAND = "vigil assess code-coverage --cwe-matrix";

type EffortWarning = Extract<QualityWarning, { kind: "effort" }>;

type Props = {
  engagementKey: string;
  warnings: QualityWarning[];
  effortGaps?: CodeEffortGaps | null;
  /** Signal files read only wide (`coverage.gate.depth_advisories`): a pointer, not a warning. */
  depthAdvisories?: CodeDepthAdvisory[];
  /** Families below their floor that no lead tracks (`coverage.gate.untriggered_depth_shortfalls`): a pointer, not a warning. */
  untriggeredShortfalls?: CodeUntriggeredDepthShortfalls | null;
  /** Server-only families `client-bundle` tags make optional (`coverage.gate.optional_families`): a pointer, not a warning. */
  optionalFamilies?: CodeOptionalFamilies | null;
};

export function CodeQuality({ engagementKey, warnings, effortGaps = null, depthAdvisories = [], untriggeredShortfalls = null, optionalFamilies = null }: Props) {
  const optionalByFamily = Object.entries(optionalFamilies?.by_family ?? {});
  const untriggered = untriggeredShortfalls && untriggeredShortfalls.groups.length > 0 ? untriggeredShortfalls : null;
  const effortByFamily = new Map<string, EffortWarning[]>();
  const other = new Map<Exclude<QualityWarning["kind"], "effort">, QualityWarning[]>();
  for (const warning of warnings) {
    // The grouped lines restate `effortGaps`, which renders as the table below;
    // without it they stay listed as text so nothing is dropped.
    if (warning.kind === "effort_group" && effortGaps) continue;
    if (warning.kind === "effort") {
      const list = effortByFamily.get(warning.family) ?? [];
      list.push(warning);
      effortByFamily.set(warning.family, list);
    } else {
      const list = other.get(warning.kind) ?? [];
      list.push(warning);
      other.set(warning.kind, list);
    }
  }
  const families = [...effortByFamily.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));

  return (
    <section className="panel cv-section" aria-labelledby="cv-quality-title">
      <header className="cv-section-head">
        <h3 id="cv-quality-title">Review quality</h3>
        <p className="meta-text">
          Review effort below the bar on a vulnerability type that applies to a reviewed file is advice on every tier
          and never withholds the gate. A critical or high file that closes without an entry for an applicable type
          has that type recorded at effort 0, so it shows here as a gap. Files below the bar are grouped by risk and
          vulnerability type.
        </p>
      </header>
      {warnings.length === 0 && !effortGaps ? (
        <p className="cv-ok">No review-quality warnings.</p>
      ) : null}
      {warnings.length > 0 || effortGaps || depthAdvisories.length > 0 || untriggered || optionalFamilies ? (
        <ul className="cv-groups">
          {depthAdvisories.length > 0 && (
            <li>
              <details className="cv-group">
                <summary>
                  <span className="cv-group-title">Files with signal not yet read deep</span>
                  <span className="cv-group-count">
                    {depthAdvisories.length} {depthAdvisories.length === 1 ? "file" : "files"} · advice, not counted as a warning
                  </span>
                </summary>
                <table className="cv-table">
                  <caption className="meta-text">
                    Critical and high files whose reviews returned signal (a finding or suspicious result, or a current
                    finding located in the file) but were all wide passes. Each is where a deep pass is still to go.
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">File</th>
                      <th scope="col">Risk</th>
                      <th scope="col" className="cv-num">Review passes</th>
                      <th scope="col" className="cv-num">With signal</th>
                      <th scope="col" className="cv-num">Dispatches</th>
                      <th scope="col" className="cv-num">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {depthAdvisories.map((advisory) => (
                      <tr key={advisory.file_id}>
                        <td className="cv-path-cell"><span className="cv-path" title={advisory.file_path}>{advisory.file_path}</span></td>
                        <td>{CLASSIFICATION_LABELS[advisory.classification] ?? advisory.classification}</td>
                        <td className="cv-num">{advisory.passes}</td>
                        <td className="cv-num">{advisory.signal_passes}</td>
                        <td className="cv-num">{advisory.dispatches}</td>
                        <td className="cv-num">{advisory.findings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </li>
          )}
          {untriggered && (
            <li>
              <details className="cv-group">
                <summary>
                  <span className="cv-group-title">Vulnerability types below their floor with no lead</span>
                  <span className="cv-group-count">
                    {untriggered.total.toLocaleString()} on {untriggered.file_count.toLocaleString()}{" "}
                    {untriggered.file_count === 1 ? "file" : "files"} · advice, not counted as a warning
                  </span>
                </summary>
                <GapTable
                  gaps={untriggered}
                  caption={
                    <>
                      {untriggered.detail ? <>{untriggered.detail} </> : null}
                      Every one, file by file: <code>{untriggered.full_list ?? FULL_LIST_COMMAND}</code>
                    </>
                  }
                />
              </details>
            </li>
          )}
          {optionalFamilies && (
            <li>
              <details className="cv-group">
                <summary>
                  <span className="cv-group-title">Vulnerability types optional on client-bundle files</span>
                  <span className="cv-group-count">
                    {optionalByFamily.length.toLocaleString()} on {optionalFamilies.files.toLocaleString()}{" "}
                    {optionalFamilies.files === 1 ? "file" : "files"} · advice, not counted as a warning
                  </span>
                </summary>
                <table className="cv-table">
                  <caption className="meta-text">
                    {optionalFamilies.detail}. Every file and its optional types: <code>{optionalFamilies.full_list}</code>{" "}
                    <a href={codeViewHref(engagementKey, { view: "files", tags: "client-bundle" })}>List the client-bundle files</a>
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Vulnerability type</th>
                      <th scope="col" className="cv-num">Files it is optional on</th>
                    </tr>
                  </thead>
                  <tbody>
                    {optionalByFamily.map(([family, count]) => (
                      <tr key={family}>
                        <td title={family}>{familyLabel(family)}</td>
                        <td className="cv-num">{count.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </li>
          )}
          {effortGaps && (
            <li>
              <details className="cv-group" open>
                <summary>
                  <span className="cv-group-title">{QUALITY_GROUP_LABELS.effort_group}</span>
                  <span className="cv-group-count">
                    {effortGaps.total} {effortGaps.total === 1 ? "gap" : "gaps"}
                  </span>
                </summary>
                <GapTable
                  gaps={effortGaps}
                  caption={
                    <>
                      {effortGaps.total} effort {effortGaps.total === 1 ? "gap" : "gaps"} across {effortGaps.file_count}{" "}
                      {effortGaps.file_count === 1 ? "file" : "files"}. Every per-file gap: <code>{FULL_LIST_COMMAND}</code>
                    </>
                  }
                />
              </details>
            </li>
          )}
          {families.map(([family, list]) => (
            <li key={family}>
              <details className="cv-group">
                <summary>
                  <span className="cv-group-title" title={family}>{familyLabel(family)}</span>
                  <span className="cv-group-count">
                    {list.length} {list.length === 1 ? "file" : "files"} under-reviewed
                  </span>
                </summary>
                <table className="cv-table">
                  <thead>
                    <tr>
                      <th scope="col">File</th>
                      <th scope="col">Risk</th>
                      <th scope="col">Effort</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((warning) => (
                      <tr key={warning.text}>
                        <td className="cv-path-cell"><span className="cv-path" title={warning.file}>{warning.file}</span></td>
                        <td>{CLASSIFICATION_LABELS[warning.risk] ?? warning.risk}</td>
                        <td title={underReviewedLabel(warning.family, warning.effort, warning.threshold)}>
                          {warning.effort} of {warning.threshold}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </li>
          ))}
          {[...other.entries()].map(([kind, list]) => (
            <li key={kind}>
              <details className="cv-group">
                <summary>
                  <span className="cv-group-title">{QUALITY_GROUP_LABELS[kind]}</span>
                  <span className="cv-group-count">{list.length}</span>
                </summary>
                {kind === "direct_read" && (
                  <p className="meta-text">
                    Listed file by file under <a href={codeViewHref(engagementKey, { view: "files" })}>Files</a>.
                  </p>
                )}
                <ul className="cv-plain-list">
                  {list.map((warning) => (
                    <li key={warning.text}>
                      {"file" in warning ? (
                        <>
                          <span className="cv-path" title={warning.file}>{warning.file}</span>{" "}
                          <span className="meta-text">({CLASSIFICATION_LABELS[warning.risk] ?? warning.risk})</span>
                        </>
                      ) : (
                        warning.text
                      )}
                    </li>
                  ))}
                </ul>
              </details>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

/**
 * Effort gaps grouped by risk tier and vulnerability type. Each group names a
 * sample of its files and says how many it left out; the caption names the
 * read that lists every one.
 */
function GapTable({ gaps, caption }: { gaps: CodeEffortGaps; caption: ReactNode }) {
  return (
    <table className="cv-table">
      <caption className="meta-text">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Risk</th>
          <th scope="col">Vulnerability type</th>
          <th scope="col">Threshold</th>
          <th scope="col">Files</th>
          <th scope="col">Examples</th>
        </tr>
      </thead>
      <tbody>
        {gaps.groups.map((group) => {
          const hidden = group.file_count - group.sample_file_paths.length;
          return (
            <tr key={`${group.classification}:${group.family}`}>
              <td>{CLASSIFICATION_LABELS[group.classification] ?? group.classification}</td>
              <td title={group.family}>{familyLabel(group.family)}</td>
              <td>{group.threshold}</td>
              <td>{group.file_count}</td>
              <td className="cv-path-cell">
                <ul className="cv-examples">
                  {group.sample_file_paths.map((path) => (
                    <li key={path}><span className="cv-path" title={path}>{path}</span></li>
                  ))}
                  {hidden > 0 && <li className="meta-text">+{hidden.toLocaleString()} more</li>}
                </ul>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
