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
import { referenceLink } from "./format";
import { asPocRequest, asPocResponse, pocCurl, pocResponseText } from "./poc";

export { stepsText } from "./steps";
import { reproRunIds, stepsText } from "./steps";

export function findingToMarkdown(d: ReportFinding): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);

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
  if (d.evidence_detail && d.evidence_detail.trim()) {
    push("### Evidence");
    push("```");
    push(d.evidence_detail.trim());
    push("```");
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
    push("```sh");
    push(curl);
    push("```");
    push();
  }
  const responseText = pocResponseText(asPocResponse(d.poc_response));
  if (responseText) {
    push("### Observed Response");
    push("```http");
    push(responseText);
    push("```");
    push();
  }
  if (d.poc_code && d.poc_code.trim()) {
    push("### Proof of Concept");
    push("```");
    push(d.poc_code.trim());
    push("```");
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
