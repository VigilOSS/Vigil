// Package-local copy-as-markdown helper for the report's per-finding "Copy as
// Markdown" buttons.
//
// Adapted from orchestrator/frontend/src/lib/findingMarkdown.ts, but bound to
// the REPORT projection (report_readiness._report_record) rather than the live
// FindingsTab `Derived` shape. The field set differs: the report projection
// flattens details into `evidence_detail`, `cvss_score`, `steps_to_reproduce`,
// etc., and has no poc_request/poc_response objects. Empty sections are
// skipped so a sparse finding doesn't render a wall of empty headings.

import type { ReportFinding } from "../types";
import { formatLabel, referenceLink } from "./format";
import { asPocRequest, asPocResponse, pocCurl, pocResponseText } from "./poc";

export { stepsText } from "./steps";
import { reproRunIds, stepsText } from "./steps";

/**
 * A code fence `content` cannot close.
 *
 * CommonMark ends a fenced block at the first line whose fence is at least as
 * long as the opening one, so a fixed ``` fence ends wherever the content
 * happens to contain three backticks. The content here is target-derived:
 * `evidence_detail`, a recorded `body_excerpt`, `poc_code`. A hostile response
 * body that includes a ``` line therefore breaks OUT of the evidence block, and
 * every byte after it becomes live Markdown in a document the operator is about
 * to paste into a submission form — the target gets to write headings, links
 * and plausible report prose beside the operator's own words, and a reader
 * cannot tell which is which. That is the untrusted-target-text boundary
 * (ADR 0018) failing in the direction it exists to prevent.
 *
 * Nothing is escaped or removed to fix it — ADR 0019 rules that out, and the
 * evidence has to stay byte-exact anyway. Instead the delimiter outgrows the
 * content: one backtick longer than the longest run present, which by
 * construction no run in the content can match.
 */
function fenceFor(content: string): string {
  let longest = 0;
  for (const run of content.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  return "`".repeat(Math.max(3, longest + 1));
}

/**
 * The info string a fence may carry, or `""` when the hint cannot be one.
 *
 * A backtick fence's info string may not contain a backtick (CommonMark 4.5),
 * so ```` ```js`x` ```` is not a fence — it is a paragraph, and every byte the
 * projection meant to put inside the block becomes live Markdown instead. A
 * newline in the hint is worse still: it splits the opening line, and a hint
 * ending in ``` closes the block on the line after it opens.
 *
 * Only a *language hint* is dropped here, never a capture. The hint is
 * presentation — a syntax colour in whatever form the operator pastes into —
 * so losing it costs nothing that could be evidence, and ADR 0019 (do not
 * degrade the operator's own data) is not engaged. The capture the fence wraps
 * still goes in byte for byte.
 *
 * This twin only ever passes literals. Its sibling in orchestrator/frontend
 * passes `details.poc_language`, which is a free-form key no schema, prompt or
 * backend validates, so the guard lives in both and neither can drift.
 */
export function fenceInfo(hint: string): string {
  return /^[A-Za-z0-9_+#.-]*$/.test(hint) ? hint : "";
}

export function findingToMarkdown(d: ReportFinding): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);
  // Captures go in verbatim, inside a fence sized to hold them. The Full Report
  // renders the same values in a <pre> exactly as recorded, and a copy button
  // that hands back something else makes the page and its own clipboard
  // disagree about what the target did.
  const pushFenced = (content: string, info = "") => {
    const fence = fenceFor(content);
    push(`${fence}${fenceInfo(info)}`);
    push(content);
    push(fence);
  };

  const heading = [d.slug, d.title].filter(Boolean).join(" — ") || "Finding";
  push(`## ${heading}`);

  const statusParts: string[] = [];
  if (d.severity) statusParts.push(`**Severity:** ${d.severity}`);
  if (d.cvss_score != null) statusParts.push(`**CVSS:** ${Number(d.cvss_score).toFixed(1)}`);
  if (d.workflow_status) statusParts.push(`**Workflow:** ${d.workflow_status}`);
  if (d.verification_status && d.verification_status !== "unreviewed") {
    statusParts.push(`**Verification:** ${d.verification_status}`);
  }
  if (statusParts.length > 0) {
    push(statusParts.join(" · "));
    push();
  }

  const metaParts: string[] = [];
  if (d.canonical_location) metaParts.push(`**Location:** \`${d.canonical_location}\``);
  // For a code finding these two ARE the location: where attacker-controlled
  // input enters, and where it reaches something dangerous.
  if (d.entry_point) metaParts.push(`**Entry point:** \`${d.entry_point}\``);
  if (d.sink) metaParts.push(`**Sink:** \`${d.sink}\``);
  // Severity-defining context, and the Full Report shows both: what privilege
  // the attack needs, and whether the proof was observed on the wire or inferred
  // from source. Omitted from the copy, a high-severity claim reads as
  // unauthenticated and observed when it may be neither — the reader who copies
  // a finding gets a stronger report than the reader who reads one. Labelled
  // and formatted as the report labels them so the two cannot drift.
  if (d.auth_context) metaParts.push(`**Access required:** ${formatLabel(d.auth_context)}`);
  if (d.evidence_type) metaParts.push(`**Evidence type:** ${formatLabel(d.evidence_type)}`);
  if (d.cwe_id) metaParts.push(`**CWE:** ${d.cwe_id}`);
  if (d.owasp_category) metaParts.push(`**OWASP:** ${d.owasp_category}`);
  if (d.cvss_vector) metaParts.push(`**CVSS vector:** \`${d.cvss_vector}\``);
  if (metaParts.length > 0) {
    metaParts.forEach((part) => push(part));
    push();
  }

  if (d.summary && d.summary.trim()) {
    push("### Summary");
    push(d.summary.trim());
    push();
  }
  if (d.impact && d.impact.trim()) {
    push("### Impact");
    push(d.impact.trim());
    push();
  }
  // Presence is truthiness, not `.trim()`. A capture that is nothing but
  // whitespace is a RECORDED capture — it is the whole proof on a stripped,
  // padded or blank-response finding, which is why `lib/poc.ts` refuses to call
  // one absent — and `FullReport.tsx` renders it in a <pre> either way. Testing
  // the trimmed value dropped the section AND its heading from the copy while
  // the page still showed the bytes (AGENTS.md; ADR 0019).
  if (d.evidence_detail) {
    push("### Evidence");
    pushFenced(d.evidence_detail);
    push();
  }
  const steps = stepsText(d.steps_to_reproduce);
  if (steps) {
    push("### Steps to Reproduce");
    push(steps);
    push();
    const runs = reproRunIds(d.repro_runs);
    if (runs.length > 0) {
      push(`Command runs behind these steps: ${runs.map((id) => `\`#${id}\``).join(", ")}`);
      push();
    }
  }
  // Fenced as `sh` so a paste into a submission form keeps it a command block
  // rather than letting the platform's markdown reflow it into prose.
  const curl = pocCurl(asPocRequest(d.poc_request));
  if (curl) {
    push("### Reproduction Request");
    pushFenced(curl, "sh");
    push();
  }
  const responseText = pocResponseText(asPocResponse(d.poc_response));
  if (responseText) {
    push("### Observed Response");
    pushFenced(responseText, "http");
    push();
  }
  if (d.poc_code) {
    push("### Proof of Concept");
    pushFenced(d.poc_code);
    push();
  }
  if (d.remediation && d.remediation.trim()) {
    push("### Remediation");
    push(d.remediation.trim());
    push();
  }
  if (Array.isArray(d.references) && d.references.length > 0) {
    const links = d.references.map(referenceLink).filter((link) => link !== null);
    if (links.length > 0) {
      push("### References");
      links.forEach((link) => {
        push(link.url && link.url !== link.label ? `- ${link.label} — ${link.url}` : `- ${link.label}`);
      });
      push();
    }
  }

  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}
