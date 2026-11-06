// Copy-finding-as-markdown (UI/UX adoption wave, Tier 1c).
//
// Produces a portable markdown document from Vigil finding fields that an operator
// can paste into a ticket, report, or chat. Empty sections are skipped so a
// sparse finding doesn't render a wall of empty headings.
//
// This lives in lib/ (not the component) so it stays unit-testable and free of
// React. It accepts a structural subset of FindingsTab's `Derived` shape — the
// `Derived` type satisfies `MarkdownFinding` without an explicit cast.

import type { FindingOperatorAuthority, FindingPocRequest, FindingPocResponse } from "./api.ts";
import { operatorAuthorityLabel } from "./findingWorkflow.ts";

export type MarkdownFinding = {
  slug: string;
  title: string;
  severity: string;
  workflowLabel: string;
  verificationLabel: string;
  verificationKey: string;
  // Present only when the verdict rests on the operator's own out-of-snapshot
  // evidence instead of a decision receipt. The copy is what gets filed in a
  // ticket, where nobody can see the drawer that said so — so the status line
  // carries it rather than leaving the reader to assume a proof run.
  operatorAuthority?: FindingOperatorAuthority | null;
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
  evidence?: string;
  steps_to_reproduce?: string[];
  poc_code?: string;
  poc_language?: string;
  poc_request?: FindingPocRequest | string;
  poc_response?: FindingPocResponse | string;
  attack_scenario?: string;
  impact?: string;
  remediation?: string;
};

// Local HTTP formatter — mirrors FindingsTab.formatHttp so request/response
// fences read the same in the markdown export as they do in Submission.
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
 * literals, while this one passes `details.poc_language` — registered as FREE
 * TEXT, so the record door admits the key and checks nothing about the value.
 * A specialist writes whatever the target's own toolchain calls the language,
 * while reading target output (ADR 0018), and it reaches here untouched.
 *
 * A backtick fence's info string may not contain a backtick (CommonMark 4.5),
 * so ```` ```js`x` ```` is not a fence — it is a paragraph, and the capture
 * below it becomes live Markdown in a document the operator is about to file.
 * A newline in the hint is worse: it splits the opening line, and a hint ending
 * in ``` closes the block on the line after it opens.
 *
 * An inner SPACE is admitted, because it breaks nothing: a renderer reads the
 * first word of the info string as the language and ignores the rest, so
 * ```` ```python 3 ```` fences exactly as ```` ```python ```` does. Rejecting it
 * dropped the multi-word hints a specialist actually writes, and this guard
 * exists to stop an escape, not to decide which labels are tidy.
 *
 * Only a *language hint* is ever dropped, never a capture, and only when it
 * holds a character that would un-fence the block. The hint is presentation — a
 * syntax colour in whatever form the operator pastes into — so ADR 0019 (do not
 * degrade the operator's own data) is answered by the narrowness of the rule;
 * the capture the fence wraps still goes in byte for byte. The page's own chip
 * filters nothing at all, because a DOM text node holds no fence to break.
 */
export function fenceInfo(hint: string): string {
  return /^[A-Za-z0-9_+#.\- ]*$/.test(hint) ? hint : "";
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
  // On the same line as the verdict it qualifies, so a reader who skims one
  // line cannot take the verdict for a dispatch-verified one.
  if (d.operatorAuthority) {
    statusParts.push(`**${operatorAuthorityLabel(d.operatorAuthority, d.verificationKey)}** (no proof receipt)`);
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
  // Verbatim, as the operator wrote it, and in the same shape as the other
  // labelled metadata: this is the justification the whole waiver rests on, so
  // paraphrasing it would leave the ticket asserting a verdict whose stated
  // grounds nobody can check.
  if (d.operatorAuthority?.reason) push(`**Operator authority reason:** ${d.operatorAuthority.reason}`);
  if (d.cwe_id) push(`**CWE:** ${d.cwe_id}`);
  if (d.owasp_category) push(`**OWASP:** ${d.owasp_category}`);
  if (d.cvss_vector) push(`**CVSS vector:** \`${d.cvss_vector}\``);
  if (d.canonical_location || d.auth_context || d.operatorAuthority?.reason || d.cwe_id || d.owasp_category || d.cvss_vector) {
    push();
  }

  if (d.summary && d.summary.trim()) {
    push("### Summary");
    push(d.summary.trim());
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
  const reqText = formatHttp(d.poc_request, "req");
  const respText = formatHttp(d.poc_response, "resp");
  const hasEvidence = Boolean(d.evidence || d.poc_code || reqText || respText);
  // Presence is truthiness, not `.trim()`, and the drawer gates these the same
  // way. A capture that is nothing but whitespace is a RECORDED capture — the
  // whole proof on a stripped, padded or blank-response finding, which is why
  // report/src/lib/poc.ts refuses to call one absent. Supporting captures stay
  // nested under Evidence so the clipboard and Submission pane share one shape.
  if (hasEvidence) push("### Evidence");
  if (d.evidence) {
    const evidenceProbe = d.evidence.trim();
    const evidenceIsRaw = d.evidence !== evidenceProbe || evidenceProbe.length === 0 ||
      /^HTTP\/\d\.\d\b/i.test(evidenceProbe) ||
      /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d/i.test(evidenceProbe);
    if (evidenceIsRaw) pushFenced(d.evidence);
    else push(d.evidence);
    push();
  }
  if (d.poc_code) {
    push("#### Payload");
    pushFenced(d.poc_code, d.poc_language || "");
    push();
  }
  if (reqText) {
    push("#### Request");
    pushFenced(reqText, "http");
    push();
  }
  if (respText) {
    push("#### Response");
    pushFenced(respText, "http");
    push();
  }
  if (d.attack_scenario && d.attack_scenario.trim()) {
    push("### Attack Scenario");
    push(d.attack_scenario.trim());
    push();
  }
  if (d.impact && d.impact.trim()) {
    push("### Impact");
    push(d.impact.trim());
    push();
  }
  if (d.remediation && d.remediation.trim()) {
    push("### Remediation");
    push(d.remediation.trim());
    push();
  }

  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.join("\n");
}
