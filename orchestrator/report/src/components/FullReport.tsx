import { useMemo } from "react";
import type {
  ReportAttackChain,
  ReportAttackChainLink,
  ReportData,
  ReportFinding,
} from "../types";
import {
  flattenFindings,
  formatDateTime,
  formatLabel,
  SEVERITY_RANK,
} from "../lib/format";
import { asPocRequest, asPocResponse, pocCurl, pocResponseText } from "../lib/poc";
import { reproRunIds, stepsText } from "../lib/steps";
import { Markdown } from "./Markdown";
import { CopyMarkdownButton, ReferenceList, ReproRunProvenance } from "./FindingParts";

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
  // How many of those siblings the root-cause fix closes outright
  // (report_readiness counts siblings whose effect is `eliminates_attack_path`).
  eliminatedPathCount: number;
}

function sectionAnchor(finding: ReportFinding): string {
  return `finding-${finding.slug ?? finding.report_id ?? finding.title ?? "x"}`
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-");
}

// Where a chain step lands in the document: the finding section it refers to,
// keyed by the slug an `assessment_attack_chain_links` row stores in
// `entity_ref`.
interface StepTarget {
  anchor: string;
  reportId: string;
  title: string;
  severity: string;
}

function FindingBlock({
  finding,
  kind,
  draft,
}: {
  finding: ReportFinding;
  kind: "root" | "sibling" | "standalone";
  draft: boolean;
}) {
  const sev = finding.severity ?? "info";
  const steps = stepsText(finding.steps_to_reproduce);
  const curl = pocCurl(asPocRequest(finding.poc_request));
  const responseText = pocResponseText(asPocResponse(finding.poc_response));
  const hasMeta =
    finding.owasp_category ||
    finding.cvss_vector ||
    finding.entry_point ||
    finding.sink ||
    finding.auth_context ||
    finding.evidence_type ||
    finding.source_name;
  return (
    <article className="rpt-doc-finding" id={sectionAnchor(finding)}>
      <header className="rpt-doc-finding-head">
        <h3>
          <span className="rpt-mono">{finding.report_id ?? finding.slug}</span> {finding.title}
          {kind === "sibling" && (
            <span className="rpt-sibling-tag">
              {/* The effect names what fixing the root buys for THIS sibling; a
                  flat "shares root cause" threw that distinction away. */}
              {finding.root_cause_effect
                ? formatLabel(finding.root_cause_effect)
                : "shares root cause"}
            </span>
          )}
        </h3>
        <div className="rpt-doc-finding-tags">
          <span className={`rpt-sev-badge rpt-sev-${sev}`}>{formatLabel(sev)}</span>
          {finding.cvss_score != null && (
            <span className="rpt-chip">CVSS {Number(finding.cvss_score).toFixed(1)}</span>
          )}
          {finding.cwe_id && <span className="rpt-chip">{finding.cwe_id}</span>}
          {finding.verification_status && (
            <span className="rpt-chip">{formatLabel(finding.verification_status)}</span>
          )}
          {finding.workflow_status && (
            <span className="rpt-chip">{formatLabel(finding.workflow_status)}</span>
          )}
          <CopyMarkdownButton finding={finding} />
        </div>
      </header>
      {finding.canonical_location && (
        <p className="rpt-doc-location rpt-mono">{finding.canonical_location}</p>
      )}
      {hasMeta && (
        <dl className="rpt-finding-meta">
          {/* For a code finding the entry point and the sink ARE the location:
              where attacker input enters, and where it reaches something
              dangerous. Nothing rendered either before this. */}
          {finding.entry_point && (
            <div>
              <dt>Entry point</dt>
              <dd className="rpt-mono">{finding.entry_point}</dd>
            </div>
          )}
          {finding.sink && (
            <div>
              <dt>Sink</dt>
              <dd className="rpt-mono">{finding.sink}</dd>
            </div>
          )}
          {finding.auth_context && (
            <div>
              <dt>Access required</dt>
              <dd>{formatLabel(finding.auth_context)}</dd>
            </div>
          )}
          {finding.evidence_type && (
            <div>
              <dt>Evidence type</dt>
              <dd>{formatLabel(finding.evidence_type)}</dd>
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
          {finding.source_name && (
            <div>
              <dt>Discovered by</dt>
              <dd>{finding.source_name}</dd>
            </div>
          )}
        </dl>
      )}
      {kind === "sibling" && finding.root_cause_note && (
        <p className="rpt-doc-rootcause">{finding.root_cause_note}</p>
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
          {/* Verbatim. `evidence_detail` is a CAPTURE — a request/response pair,
              a log excerpt, a stack trace — not authored prose, and markdown
              silently rewrites exactly the characters that carry its meaning:
              `__init__.py` loses its underscores to bold, a `>` request marker
              becomes a blockquote, `#` becomes a heading, and consecutive lines
              of an HTTP transcript collapse into one paragraph. Vigil does not
              alter what the operator captured (AGENTS.md; ADR 0019), and
              lib/findingMarkdown.ts already fences this field for the same
              reason — rendering it through Markdown made the page lossier than
              its own copy button. */}
          <pre className="rpt-code">{finding.evidence_detail}</pre>
        </div>
      )}
      {steps && (
        <div className="rpt-doc-block">
          <h4>Steps to reproduce</h4>
          {/* Verbatim — the author's numbering is what other sections cite. */}
          <div className="rpt-steps">{steps}</div>
          <ReproRunProvenance runIds={reproRunIds(finding.repro_runs)} draft={draft} />
        </div>
      )}
      {curl && (
        <div className="rpt-doc-block">
          <h4>Reproduction request</h4>
          {/* Synthesized from the recorded request object so it pastes into a
              terminal and runs: see lib/poc.ts. rpt-code-command does not
              soft-wrap, so a copied line is the line that was shown. */}
          <pre className="rpt-code rpt-code-command">{curl}</pre>
        </div>
      )}
      {responseText && (
        <div className="rpt-doc-block">
          <h4>Observed response</h4>
          <pre className="rpt-code">{responseText}</pre>
        </div>
      )}
      {finding.poc_code && (
        <div className="rpt-doc-block">
          <h4>Proof of concept</h4>
          <pre className="rpt-code rpt-code-command">{finding.poc_code}</pre>
        </div>
      )}
      {finding.remediation && (
        <div className="rpt-doc-block">
          <h4>Remediation</h4>
          <Markdown text={finding.remediation} />
        </div>
      )}
      {Array.isArray(finding.references) && finding.references.length > 0 && (
        <div className="rpt-doc-block">
          <h4>References</h4>
          <ReferenceList references={finding.references} />
        </div>
      )}
    </article>
  );
}

/**
 * What one chain link points at.
 *
 * A `finding` link whose slug names a section in this report renders as a link
 * into it — that is the whole point of carrying the links, and it is guaranteed
 * to resolve in a `final` export: report_readiness blocks on any step link that
 * is not a finding (`chain_step_not_finding_linked`) or whose `entity_ref` is
 * not reportable (`chain_step_missing_finding`), and a final export is refused
 * while any blocker stands. A DRAFT is exported with blockers outstanding, so
 * the unresolved case is real there and names the reference verbatim rather
 * than dropping a step out of the path.
 *
 * `entity_kind` is free-form TEXT, so a non-finding entity gets its kind shown
 * beside the reference instead of being interpreted.
 */
function ChainEntityRef({
  link,
  targets,
}: {
  link: ReportAttackChainLink;
  targets: Map<string, StepTarget>;
}) {
  const ref = link.entity_ref ?? "";
  const target = link.entity_kind === "finding" ? targets.get(ref) : undefined;
  if (target) {
    return (
      <a className="rpt-chain-ref" href={`#${target.anchor}`}>
        <span className={`rpt-sev-dot rpt-sev-${target.severity}`} aria-hidden="true" />
        <span className="rpt-mono">{target.reportId}</span> {target.title}
      </a>
    );
  }
  return (
    <span className="rpt-chain-ref">
      {link.entity_kind && <span className="rpt-chip">{formatLabel(link.entity_kind)}</span>}
      <span className="rpt-mono">{ref || "—"}</span>
    </span>
  );
}

function AttackChainBlock({
  chain,
  links,
  targets,
}: {
  chain: ReportAttackChain;
  links: ReportAttackChainLink[];
  targets: Map<string, StepTarget>;
}) {
  const sev = chain.severity ?? "info";
  // `relation` is free-form and only "step" means anything anywhere in Vigil,
  // so the split is step / not-step rather than a vocabulary. Everything else
  // attaches supporting context and keeps its own relation as its label.
  const steps = links.filter((link) => link.relation === "step");
  const context = links.filter((link) => link.relation !== "step");
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
      {steps.length > 0 && (
        <ol className="rpt-chain-steps">
          {steps.map((link, index) => (
            <li key={`step-${link.entity_ref ?? index}-${index}`}>
              <ChainEntityRef link={link} targets={targets} />
              {/* Link notes are authored beside target-derived evidence, so they
                  render as text and never through Markdown (ADR 0018). */}
              {link.notes && <p className="rpt-chain-note">{link.notes}</p>}
            </li>
          ))}
        </ol>
      )}
      {context.length > 0 && (
        <dl className="rpt-chain-context">
          {context.map((link, index) => (
            <div key={`ctx-${link.relation ?? "link"}-${link.entity_ref ?? index}-${index}`}>
              <dt>{formatLabel(link.relation)}</dt>
              <dd>
                <ChainEntityRef link={link} targets={targets} />
                {link.notes && <p className="rpt-chain-note">{link.notes}</p>}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {chain.narrative && (
        <div className="rpt-chain-narrative">
          {/* The list above is the recorded path; the narrative is the author's
              account of it, and the two deliberately overlap — one is citable
              and linked, the other explains why the sequence works. Heading it
              only once there are links to distinguish it from keeps a chain with
              no recorded links reading exactly as it did before. */}
          {links.length > 0 && <h4>Narrative</h4>}
          <Markdown text={chain.narrative} />
        </div>
      )}
    </article>
  );
}

export function FullReport({ data }: Props) {
  const { finding_groups, attack_chains, attack_chain_links, engagement } = data;
  const draft = data.mode === "draft";

  // Chain steps are anchored to the finding sections this document already
  // renders, so the appendix reads as a path through the report rather than a
  // second list of slugs.
  const stepTargets = useMemo(() => {
    const map = new Map<string, StepTarget>();
    for (const { finding } of flattenFindings(finding_groups)) {
      const slug = String(finding.slug ?? "");
      if (!slug) continue;
      map.set(slug, {
        anchor: sectionAnchor(finding),
        reportId: String(finding.report_id ?? slug),
        title: String(finding.title ?? slug),
        severity: finding.severity ?? "info",
      });
    }
    return map;
  }, [finding_groups]);

  // Payload order is the recorded step order (report_export sorts the links by
  // insertion); grouping preserves it.
  const linksByChain = useMemo(() => {
    const map = new Map<string, ReportAttackChainLink[]>();
    for (const link of attack_chain_links) {
      const key = String(link.chain_key ?? "");
      const existing = map.get(key);
      if (existing) existing.push(link);
      else map.set(key, [link]);
    }
    return map;
  }, [attack_chain_links]);

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
        eliminatedPathCount: group.residual_path_count ?? 0,
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
        eliminatedPathCount: 0,
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
        {engagement.scope_hosts.length > 0 && (
          <p className="rpt-doc-subtitle">
            {/* The printed document is the artifact that outlives the tab, so the
                authorized scope has to be legible from it alone. */}
            Scope: <span className="rpt-mono">{engagement.scope_hosts.join(", ")}</span>
          </p>
        )}
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
              {/* Siblings carry their own anchors now, so the contents can reach
                  them instead of stopping at the root of each group. */}
              {section.siblings.length > 0 && (
                <ol className="rpt-toc-siblings">
                  {section.siblings.map((sibling) => (
                    <li key={sectionAnchor(sibling)}>
                      <a href={`#${sectionAnchor(sibling)}`}>
                        <span
                          className={`rpt-sev-dot rpt-sev-${sibling.severity ?? "info"}`}
                          aria-hidden="true"
                        />
                        {sibling.title ?? sibling.slug ?? "Finding"}
                      </a>
                    </li>
                  ))}
                </ol>
              )}
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
          <FindingBlock
            finding={section.root}
            kind={section.siblings.length > 0 ? "root" : "standalone"}
            draft={draft}
          />
          {section.eliminatedPathCount > 0 && (
            <p className="rpt-doc-rootcause">
              Remediating this root cause closes {section.eliminatedPathCount} of the{" "}
              {section.siblings.length} attack path
              {section.siblings.length === 1 ? "" : "s"} below outright.
            </p>
          )}
          {section.siblings.map((sibling) => (
            <FindingBlock
              key={String(sibling.slug ?? sibling.report_id)}
              finding={sibling}
              kind="sibling"
              draft={draft}
            />
          ))}
        </section>
      ))}

      {attack_chains.length > 0 && (
        <section className="rpt-doc-section" id="appendix-attack-chains">
          <h2 className="rpt-appendix-title">Appendix A — Attack chains</h2>
          {attack_chains.map((chain) => (
            <AttackChainBlock
              key={String(chain.chain_key ?? chain.title)}
              chain={chain}
              links={linksByChain.get(String(chain.chain_key ?? "")) ?? []}
              targets={stepTargets}
            />
          ))}
        </section>
      )}
    </div>
  );
}

export default FullReport;
