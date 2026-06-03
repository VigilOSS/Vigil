// Copy-finding-as-markdown (UI/UX adoption wave, Tier 1c).
//
// Ported shape: reference-project static-reports ReportView.findingToMarkdown(), adapted
// to OUR finding fields. Produces a clean, portable markdown document an
// operator can paste into a ticket, report, or chat. Empty sections are
// skipped so a sparse finding doesn't render a wall of empty headings.
//
// This lives in lib/ (not the component) so it stays unit-testable and free of
// React. It accepts a structural subset of FindingsTab's `Derived` shape — the
// `Derived` type satisfies `MarkdownFinding` without an explicit cast.

import type { FindingPocRequest, FindingPocResponse, FindingReference } from "./api";

export type MarkdownFinding = {
  slug: string;
  title: string;
  severity: string;
  workflowLabel: string;
  verificationLabel: string;
  verificationKey: string;
  cvss_score?: number;
  cvss_vector?: string;
  canonical_location?: string;
  request_method?: string;
  parameter?: string;
  cwe_id?: string;
  owasp_category?: string;
  summary?: string;
  impact?: string;
  evidence?: string;
  steps_to_reproduce?: string[];
  poc_code?: string;
  poc_language?: string;
  poc_request?: FindingPocRequest | string;
  poc_response?: FindingPocResponse | string;
  remediation?: string;
  notes?: string;
  references?: FindingReference[];
};

// Local HTTP formatter — mirrors FindingsTab.formatHttp so request/response
// fences read the same in the markdown export as they do in the PoC pane.
function formatHttp(
  obj: FindingPocRequest | FindingPocResponse | string | undefined,
  kind: "req" | "resp",
): string {
  if (!obj) return "";
  if (typeof obj === "string") return obj;
  const lines: string[] = [];
  if (kind === "req") {
    const req = obj as FindingPocRequest;
    lines.push(`${(req.method || "GET").toUpperCase()} ${req.url || ""}`.trim());
  } else {
    const resp = obj as FindingPocResponse;
    if (resp.status != null) lines.push(`HTTP ${resp.status}`);
  }
  const headers = (obj as FindingPocRequest | FindingPocResponse).headers;
  if (headers && typeof headers === "object") {
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
  } else if (typeof headers === "string" && headers.trim()) {
    lines.push(headers.trim());
  }
  const body = (obj as FindingPocRequest | FindingPocResponse).body;
  if (body) {
    lines.push("");
    lines.push(body);
  }
  return lines.join("\n");
}

function refLabel(ref: FindingReference): string {
  if (typeof ref === "string") return ref.trim();
  if (ref && typeof ref === "object") {
    const title = ref.title || ref.id || "";
    if (title && ref.url) return `${title} — ${ref.url}`;
    return ref.url || title || "";
  }
  return String(ref);
}

export function findingToMarkdown(d: MarkdownFinding): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);

  push(`## ${d.slug} — ${d.title}`);

  // Severity / CVSS / workflow / verification on one line.
  const statusParts: string[] = [`**Severity:** ${d.severity}`];
  if (d.cvss_score != null) statusParts.push(`**CVSS:** ${d.cvss_score.toFixed(1)}`);
  statusParts.push(`**Workflow:** ${d.workflowLabel}`);
  if (d.verificationKey && d.verificationKey !== "unreviewed") {
    statusParts.push(`**Verification:** ${d.verificationLabel}`);
  }
  push(statusParts.join(" · "));
  push();

  if (d.canonical_location) {
    let loc = `**Location:** \`${d.canonical_location}\``;
    if (d.request_method) loc += ` (${d.request_method})`;
    if (d.parameter) loc += ` · param \`${d.parameter}\``;
    push(loc);
  }
  if (d.cwe_id) push(`**CWE:** ${d.cwe_id}`);
  if (d.owasp_category) push(`**OWASP:** ${d.owasp_category}`);
  if (d.cvss_vector) push(`**CVSS vector:** \`${d.cvss_vector}\``);
  if (d.canonical_location || d.cwe_id || d.owasp_category || d.cvss_vector) push();

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
  if (d.evidence && d.evidence.trim()) {
    push("### Evidence");
    push("```");
    push(d.evidence.trim());
    push("```");
    push();
  }
  if (d.steps_to_reproduce && d.steps_to_reproduce.length > 0) {
    push("### Steps to Reproduce");
    d.steps_to_reproduce.forEach((s, i) => push(`${i + 1}. ${s}`));
    push();
  }
  if (d.poc_code && d.poc_code.trim()) {
    push("### Proof of Concept");
    push("```" + (d.poc_language || ""));
    push(d.poc_code.trim());
    push("```");
    push();
  }
  const reqText = formatHttp(d.poc_request, "req");
  if (reqText.trim()) {
    push("### PoC Request");
    push("```http");
    push(reqText.trim());
    push("```");
    push();
  }
  const respText = formatHttp(d.poc_response, "resp");
  if (respText.trim()) {
    push("### PoC Response");
    push("```http");
    push(respText.trim());
    push("```");
    push();
  }
  if (d.remediation && d.remediation.trim()) {
    push("### Remediation");
    push(d.remediation.trim());
    push();
  }
  if (d.notes && d.notes.trim()) {
    push("### Notes");
    push(d.notes.trim());
    push();
  }
  if (d.references && d.references.length > 0) {
    push("### References");
    d.references.forEach((r) => {
      const label = refLabel(r);
      if (label) push(`- ${label}`);
    });
    push();
  }

  // Trim trailing blank lines.
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}
