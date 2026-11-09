// Finding fragments that render identically in the Findings table's detail pane
// and in the Full Report document. Only the surrounding chrome differs between
// those two views (a <section> vs a .rpt-doc-block), so the chrome stays with
// each caller and the parts that must not drift live here.

import { useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";

import type { ReportFinding } from "../types";
import { formatDateTime, referenceLink } from "../lib/format";
import { findingToMarkdown } from "../lib/findingMarkdown";
import { asPocRequest, asPocResponse, pocCurl, pocResponseText } from "../lib/poc";
import { reproRunIds, stepsText } from "../lib/steps";
import { Markdown } from "./Markdown";
import {
  asOperatorAuthority,
  operatorAuthorityLabel,
  operatorAuthoritySentence,
} from "../lib/operatorAuthority";

/**
 * Copy the whole finding as structured markdown.
 *
 * Section headings are `user-select: none` so that dragging across a
 * reproduction yields the command and nothing else — this button is where the
 * headings come back, for the reader who wants the finding as a document rather
 * than as something to paste into a shell.
 */
export function CopyMarkdownButton({ finding }: { finding: ReportFinding }) {
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

/**
 * The verdict chip's qualifier: this one was not reached by a proof receipt.
 *
 * Sits beside `verification_status` wherever that renders, because the status
 * word is identical either way — a reader seeing `Verified` has no other way
 * to tell an operator attestation from a dispatch-verified proof, and ADR 0043
 * makes rendering the two as equivalent the one presentation not available.
 * Returns null for the ordinary receipt-backed verdict.
 */
export function OperatorAuthorityTag({ finding }: { finding: ReportFinding }) {
  const stamp = asOperatorAuthority(finding.operator_authority);
  if (!stamp) return null;
  return (
    <span className="rpt-chip rpt-chip-attested" title={operatorAuthoritySentence(stamp)}>
      {operatorAuthorityLabel(stamp)}
    </span>
  );
}

/**
 * The attestation itself: what the operator relied on, and what they say it
 * settles.
 *
 * The chip states that a waiver stands; this states its content, so a reader
 * who distrusts the verdict can go and read the intel record the operator
 * relied on and reach their own conclusion — which is the whole reason ADR 0043
 * requires a resolvable intel id and not just a reason string.
 *
 * The reason is the operator's own words about target-influenced evidence, so it
 * renders verbatim and NOT through Markdown: markdown rewrites exactly the
 * characters that carry meaning in a quoted configuration line, and this
 * sentence is the only statement of what the out-of-snapshot evidence settles.
 * Presentation is clamped by CSS (it wraps and never overflows); the record is
 * not (ADR 0019, ADR 0018).
 */
export function OperatorAuthorityAttestation({ finding }: { finding: ReportFinding }) {
  const stamp = asOperatorAuthority(finding.operator_authority);
  if (!stamp) return null;
  return (
    <section className="rpt-attestation" aria-label="Operator-attested verdict">
      <h4 className="rpt-attestation-title">{operatorAuthorityLabel(stamp)}</h4>
      <p className="rpt-attestation-lede">
        {operatorAuthoritySentence(stamp)}
        {stamp.at && ` Recorded ${formatDateTime(stamp.at)}.`}
      </p>
      {stamp.reason && <p className="rpt-attestation-reason">{stamp.reason}</p>}
    </section>
  );
}

/**
 * Provenance for the reproduction steps: the command runs that produced them.
 *
 * Steps that were executed and steps that were reconstructed afterwards read
 * exactly the same as prose, and only `details.repro_runs` tells them apart —
 * which is why the backend raises `finding_repro_runs_missing` when steps arrive
 * with nothing behind them. Naming the absence is gated on draft mode, mirroring
 * `vigil assess export submission`, which prints its own "[NEEDS: ...]" marker
 * only while drafting: the operator reviewing a draft is the reader who can
 * still go and get the run ids, and a delivered report should not be carrying
 * the note at all — the finding should have been sent back instead.
 *
 * A `source` reproduction basis (the verdict rests only on source-observation
 * receipts) has no run to name: the cited source lines back its steps, as
 * `export submission` states, so that is what the report says instead.
 */
export function ReproRunProvenance({
  runIds,
  draft,
  basis,
}: {
  runIds: string[];
  draft: boolean;
  basis?: string;
}) {
  if (runIds.length > 0) {
    return (
      <p className="rpt-steps-runs">
        Command runs behind these steps:{" "}
        <span className="rpt-mono">{runIds.map((id) => `#${id}`).join(" · ")}</span>
      </p>
    );
  }
  if (basis === "source") {
    return (
      <p className="rpt-steps-runs">
        Derived from source review: the cited source lines back these steps, and no command run
        applies.
      </p>
    );
  }
  if (!draft) return null;
  return (
    <p className="rpt-steps-runs rpt-steps-runs-missing">
      No command run is recorded behind these steps.
    </p>
  );
}

export function ReferenceList({ references }: { references?: unknown[] }) {
  if (!Array.isArray(references)) return null;
  const links = references.map(referenceLink).filter((link) => link !== null);
  if (links.length === 0) return null;
  return (
    <ul className="rpt-ref-list">
      {links.map((link, index) => (
        <li key={`${link.url}-${link.label}-${index}`}>
          {link.url ? (
            <a href={link.url} target="_blank" rel="noopener noreferrer">
              {link.label}
            </a>
          ) : (
            link.label
          )}
        </li>
      ))}
    </ul>
  );
}

/** Which chrome wraps a section: the detail pane's bare `<section>`, or the document's block. */
type SectionBlock = "section" | "doc";

function Block({ block, children }: { block: SectionBlock; children: ReactNode }) {
  if (block === "doc") return <div className="rpt-doc-block">{children}</div>;
  return <section>{children}</section>;
}

/**
 * The finding's own claims — Summary, Impact, Evidence, Steps to reproduce,
 * Reproduction request, Observed response, Proof of concept, Remediation,
 * References — in the order both views read them.
 *
 * `block` is the only thing that differs between the Findings table's detail
 * pane and the Full Report document: a bare `<section>` there, a
 * `.rpt-doc-block` here. Everything inside is the same markup, so it lives here
 * where the two views cannot drift apart.
 */
export function FindingSections({
  finding,
  draft,
  block,
}: {
  finding: ReportFinding;
  draft: boolean;
  block: SectionBlock;
}) {
  const steps = stepsText(finding.steps_to_reproduce);
  const curl = pocCurl(asPocRequest(finding.poc_request));
  const responseText = pocResponseText(asPocResponse(finding.poc_response));
  return (
    <>
      {finding.summary && (
        <Block block={block}>
          <h4>Summary</h4>
          <Markdown text={finding.summary} />
        </Block>
      )}
      {finding.impact && (
        <Block block={block}>
          <h4>Impact</h4>
          <Markdown text={finding.impact} />
        </Block>
      )}
      {finding.evidence_detail && (
        <Block block={block}>
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
        </Block>
      )}
      {steps && (
        <Block block={block}>
          <h4>Steps to reproduce</h4>
          {/* Verbatim — the author's numbering is what other sections cite. */}
          <div className="rpt-steps">{steps}</div>
          <ReproRunProvenance
            runIds={reproRunIds(finding.repro_runs)}
            draft={draft}
            basis={finding.reproduction_basis}
          />
        </Block>
      )}
      {curl && (
        <Block block={block}>
          <h4>Reproduction request</h4>
          {/* Synthesized from the recorded request object so it pastes into a
              terminal and runs: see lib/poc.ts. rpt-code-command does not
              soft-wrap, so a copied line is the line that was shown. */}
          <pre className="rpt-code rpt-code-command">{curl}</pre>
        </Block>
      )}
      {responseText && (
        <Block block={block}>
          <h4>Observed response</h4>
          <pre className="rpt-code">{responseText}</pre>
        </Block>
      )}
      {finding.poc_code && (
        <Block block={block}>
          <h4>Proof of concept</h4>
          <pre className="rpt-code rpt-code-command">{finding.poc_code}</pre>
        </Block>
      )}
      {finding.remediation && (
        <Block block={block}>
          <h4>Remediation</h4>
          <Markdown text={finding.remediation} />
        </Block>
      )}
      {Array.isArray(finding.references) && finding.references.length > 0 && (
        <Block block={block}>
          <h4>References</h4>
          <ReferenceList references={finding.references} />
        </Block>
      )}
    </>
  );
}
