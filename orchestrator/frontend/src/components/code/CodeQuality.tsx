import type { CodeCoverage, CodeReadiness } from "../../lib/api";
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

type EffortWarning = Extract<QualityWarning, { kind: "effort" }>;

type Props = { engagementKey: string; warnings: QualityWarning[] };

export function CodeQuality({ engagementKey, warnings }: Props) {
  const effortByFamily = new Map<string, EffortWarning[]>();
  const other = new Map<Exclude<QualityWarning["kind"], "effort">, QualityWarning[]>();
  for (const warning of warnings) {
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
          Every reviewed critical or high file must show enough review effort on each vulnerability type that applies to
          it. Files below that bar are grouped by vulnerability type.
        </p>
      </header>
      {warnings.length === 0 ? (
        <p className="cv-ok">No review-quality warnings.</p>
      ) : (
        <ul className="cv-groups">
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
      )}
    </section>
  );
}
