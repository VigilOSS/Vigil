// Copy-finding-as-markdown (UI/UX adoption wave, Tier 1c).
//
// Ported shape: reference-project static-reports ReportView.findingToMarkdown(), adapted
// to OUR finding fields. Produces a portable markdown document an operator
// can paste into a ticket, report, or chat. Empty sections are skipped so a
// sparse finding doesn't render a wall of empty headings.
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
  // Severity-defining (shown in the drawer as "Auth context"): what privilege
  // the attack needs. Omitted here, a high-severity claim would read as
  // unauthenticated even when it needs an administrator — overstating the
  // finding to whoever reads the copy instead of the drawer.
  auth_context?: string;
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
    // Verbatim: a case-sensitive-routing probe records `get`/`GeT` on purpose.
    lines.push(`${req.method || "GET"} ${req.url || ""}`.trim());
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

// A capture is target-controlled text. A fixed ``` fence closes on the first
// such line inside it, letting a hostile body escape the block and become live
// Markdown in the operator's clipboard. Outgrow the content instead of escaping
// it, so the bytes stay exactly as recorded.
function fenceFor(content: string): string {
  let longest = 0;
  for (const run of content.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  return "`".repeat(Math.max(3, longest + 1));
}

/**
 * The info string a fence may carry, or `""` when the hint cannot be one.
 *
 * Twin of `fenceInfo` in orchestrator/report/src/lib/findingMarkdown.ts, and
 * the reason it exists lives on THIS side: the report twin only ever passes
 * literals, while this one passes `details.poc_language` — a free-form key a
 * specialist writes while reading target output, which no schema, prompt or
 * backend validates on the way here.
 *
 * A backtick fence's info string may not contain a backtick (CommonMark 4.5),
 * so ```` ```js`x` ```` is not a fence — it is a paragraph, and the capture
 * below it becomes live Markdown in a document the operator is about to file.
 * A newline in the hint is worse: it splits the opening line, and a hint ending
 * in ``` closes the block on the line after it opens.
 *
 * Only a *language hint* is ever dropped, never a capture. The hint is
 * presentation — a syntax colour in whatever form the operator pastes into —
 * so ADR 0019 (do not degrade the operator's own data) is not engaged; the
 * capture the fence wraps still goes in byte for byte.
 */
export function fenceInfo(hint: string): string {
  return /^[A-Za-z0-9_+#.-]*$/.test(hint) ? hint : "";
}

export function findingToMarkdown(d: MarkdownFinding): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);
  // Captures go in verbatim, inside a fence sized to hold them.
  const pushFenced = (content: string, info = "") => {
    const fence = fenceFor(content);
    push(`${fence}${fenceInfo(info)}`);
    push(content);
    push(fence);
  };

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
  // Raw, as the drawer's KV renders it: this twin's page does not title-case
  // the value, so neither does its clipboard.
  if (d.auth_context) push(`**Access required:** ${d.auth_context}`);
  if (d.cwe_id) push(`**CWE:** ${d.cwe_id}`);
  if (d.owasp_category) push(`**OWASP:** ${d.owasp_category}`);
  if (d.cvss_vector) push(`**CVSS vector:** \`${d.cvss_vector}\``);
  if (d.canonical_location || d.auth_context || d.cwe_id || d.owasp_category || d.cvss_vector) {
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
  // Presence is truthiness, not `.trim()`, and the drawer gates these the same
  // way. A capture that is nothing but whitespace is a RECORDED capture — the
  // whole proof on a stripped, padded or blank-response finding, which is why
  // report/src/lib/poc.ts refuses to call one absent. Testing the trimmed value
  // dropped the section AND its heading from the clipboard while the page still
  // showed the bytes (AGENTS.md; ADR 0019).
  if (d.evidence) {
    push("### Evidence");
    pushFenced(d.evidence);
    push();
  }
  // Verbatim: the author's own numbering is what other sections cite, so no
  // counter is imposed here.
  const stepsText = (d.steps_to_reproduce ?? []).join("\n").trim();
  if (stepsText) {
    push("### Steps to Reproduce");
    push(stepsText);
    push();
  }
  if (d.poc_code) {
    push("### Proof of Concept");
    pushFenced(d.poc_code, d.poc_language || "");
    push();
  }
  const reqText = formatHttp(d.poc_request, "req");
  if (reqText) {
    push("### PoC Request");
    pushFenced(reqText, "http");
    push();
  }
  const respText = formatHttp(d.poc_response, "resp");
  if (respText) {
    push("### PoC Response");
    pushFenced(respText, "http");
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

  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}
