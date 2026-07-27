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

export { stepsText } from "./steps";
import { stepsText } from "./steps";

function refLabel(ref: unknown): string {
  if (typeof ref === "string") return ref.trim();
  if (ref && typeof ref === "object") {
    const r = ref as { title?: string; id?: string; url?: string };
    const title = r.title || r.id || "";
    if (title && r.url) return `${title} — ${r.url}`;
    return r.url || title || "";
  }
  return String(ref);
}

export function findingToMarkdown(d: ReportFinding): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);

  const heading = [d.slug, d.title].filter(Boolean).join(" — ") || "Finding";
  push(`## ${heading}`);

  const statusParts: string[] = [];
  if (d.severity) statusParts.push(`**Severity:** ${d.severity}`);
  if (d.cvss_score != null) statusParts.push(`**CVSS:** ${Number(d.cvss_score).toFixed(1)}`);
  if (d.workflow_status) statusParts.push(`**Workflow:** ${d.workflow_status}`);
  if (d.verification_state && d.verification_state !== "unreviewed") {
    statusParts.push(`**Verification:** ${d.verification_state}`);
  }
  if (statusParts.length > 0) {
    push(statusParts.join(" · "));
    push();
  }

  const metaParts: string[] = [];
  if (d.canonical_location) metaParts.push(`**Location:** \`${d.canonical_location}\``);
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
    push("### References");
    d.references.forEach((r) => {
      const label = refLabel(r);
      if (label) push(`- ${label}`);
    });
    push();
  }

  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}
