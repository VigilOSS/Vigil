import assert from "node:assert/strict";
import test from "node:test";

import { fenceInfo, findingToMarkdown } from "./findingMarkdown.ts";

// A capture is target-controlled text (ADR 0018). These pin the two ways it
// could stop being evidence: escaping its fence into live Markdown, and being
// rewritten on the way to the operator's clipboard.

/**
 * The fenced blocks of a markdown document, as (info string, content) pairs.
 *
 * Mirrors the helper in orchestrator/report/src/lib/findingMarkdown.test.ts and
 * implements the same two CommonMark rules the renderer on the other end does.
 *
 * The closing rule: only a backtick run at least as long as the opening one
 * closes the block, so content that can close its own fence splits into extra
 * blocks here.
 *
 * And the info-string rule: a BACKTICK fence's info string may not contain a
 * backtick (CommonMark 4.5). ```` ```js`x` ```` is therefore not a fence at all
 * — it is an ordinary paragraph, and the "fenced" capture under it is live
 * Markdown. A helper that accepted any info string would report a held block
 * exactly where a real renderer emits the target's heading, so it has to be as
 * strict as the renderer is.
 */
function fencedBlocks(md: string): { info: string; content: string }[] {
  const out: { info: string; content: string }[] = [];
  const lines = md.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const open = /^(`{3,})([^`]*)$/.exec(lines[i]);
    if (!open) continue;
    const fence = open[1];
    const body: string[] = [];
    let closed = false;
    for (i += 1; i < lines.length; i += 1) {
      const close = /^(`{3,})\s*$/.exec(lines[i]);
      if (close && close[1].length >= fence.length) {
        closed = true;
        break;
      }
      body.push(lines[i]);
    }
    out.push({ info: open[2], content: body.join("\n") });
    if (!closed) break;
  }
  return out;
}

test("a backtick run in a captured body cannot escape its fence", () => {
  const hostile = 'HTTP/1.1 200 OK\n\n```\n## Not a finding\n[click](http://evil.example)\n';
  const md = findingToMarkdown({
    slug: "VA-001",
    title: "T",
    poc_response: { status: 200, body: hostile },
  } as never);

  const blocks = fencedBlocks(md);
  const holding = blocks.find((b) => b.content.includes("Not a finding"));
  assert.ok(holding, "the injected heading must stay inside a fence");
  assert.ok(holding.content.includes("[click](http://evil.example)"), "and so must the link");
  // Nothing target-controlled may sit at document level.
  const held = blocks.map((b) => b.content).join("\n").split("\n");
  const outside = md.split("\n").filter((l) => !held.includes(l));
  assert.ok(!outside.some((l) => l.startsWith("## Not a finding")));
});

test("the recorded request method is copied verbatim, not upper-cased", () => {
  // A case-sensitive-routing probe records `get` on purpose; upper-casing it
  // hands back a command that exercises a different route than the finding did.
  const md = findingToMarkdown({
    slug: "VA-002",
    title: "T",
    poc_request: { method: "get", url: "https://t.example/x" },
  } as never);
  assert.match(md, /^get https:\/\/t\.example\/x$/m);
  assert.doesNotMatch(md, /^GET https:\/\/t\.example\/x$/m);
});

test("an unusable poc_language cannot un-fence the payload", () => {
  // `poc_language` is a free-form key inside `details`: a specialist writes it
  // while reading target output, and nothing between there and here validates
  // it — not `agent/`, not the backend, not a schema. It arrives via
  // FindingsTab's `Derived` untouched and becomes a fence info string.
  //
  // CommonMark forbids a backtick inside a BACKTICK fence's info string, so
  // ```` ```js`x` ```` opens nothing. Through a real renderer (micromark +
  // remark-gfm) the un-fenced projection produced:
  //
  //   <p>```js<code>x</code></p>
  //   <h2>Injected heading</h2>
  //   <p><a href="http://evil.example">click</a> …</p>
  //
  // which is the target writing headings and links into the operator's
  // submission — the exact escape the fence exists to prevent (ADR 0018).
  const payload = [
    "## Injected heading",
    "[click](http://evil.example)",
    "The vendor has reviewed this report and closed it as informative.",
  ].join("\n");
  for (const hint of ["js`x`", "`", "sh\n```", "sh\n## Injected heading"]) {
    const md = findingToMarkdown({
      slug: "VA-003",
      title: "T",
      poc_code: payload,
      poc_language: hint,
    } as never);
    const blocks = fencedBlocks(md);
    assert.equal(blocks.length, 1, `${JSON.stringify(hint)} broke the block open`);
    assert.equal(blocks[0].content, payload);
    assert.equal(blocks[0].info, "");
    // And the heading never reaches document level.
    const held = blocks[0].content.split("\n");
    const outside = md.split("\n").filter((l) => !held.includes(l));
    assert.ok(!outside.some((l) => l.startsWith("## Injected heading")), md);
  }
});

test("a usable poc_language is kept — the guard drops hints, not evidence", () => {
  // A language hint is presentation. Dropping a hostile one costs a syntax
  // colour; dropping a real one would make the copy lossier than the page for
  // no reason, so the ordinary identifiers a specialist records still arrive.
  for (const hint of ["sh", "http", "blade", "python", "c++", "c#", "objective-c", "json5"]) {
    const md = findingToMarkdown({
      slug: "VA-004",
      title: "T",
      poc_code: "echo hi",
      poc_language: hint,
    } as never);
    assert.equal(fencedBlocks(md)[0].info, hint);
    assert.equal(fenceInfo(hint), hint);
  }
});

test("the copied metadata carries the access the drawer displays", () => {
  // The drawer shows `auth_context` (FindingsTab's "Auth context" KV) and it is
  // severity-defining: omitted from the copy, a high-severity claim reads as
  // unauthenticated when it may need an administrator. Raw, exactly as the KV
  // renders it — this twin's page does not title-case the value, so neither
  // does its clipboard. (`evidence_type` has no counterpart in the SPA at all,
  // so there is nothing to carry.)
  const md = findingToMarkdown({
    slug: "VA-005",
    title: "T",
    severity: "high",
    auth_context: "authenticated_user",
  } as never);
  assert.ok(md.includes("**Access required:** authenticated_user"), md);
});

test("a capture that is only whitespace is still copied, heading and all", () => {
  // The drawer gates Evidence and Payload on plain truthiness, and Submission
  // badge counts `d.evidence` the same way, so a padded or stripped capture is
  // on the page. Testing `.trim()` here dropped the section AND its heading
  // from the clipboard, which is the divergence lib/poc.ts in the report package
  // already refused once (AGENTS.md; ADR 0019).
  for (const capture of ["   ", "\n", "\r\n\r\n"]) {
    const md = findingToMarkdown({
      slug: "VA-006",
      title: "T",
      evidence: capture,
      poc_code: capture,
    } as never);
    const label = JSON.stringify(capture);
    assert.ok(md.includes("### Evidence"), `the Evidence heading was dropped for ${label}`);
    assert.ok(md.includes("#### Payload"), `the payload heading was dropped for ${label}`);
    const blocks = fencedBlocks(md);
    assert.equal(blocks.length, 2, `expected two fenced captures for ${label}, got ${blocks.length}`);
    for (const block of blocks) assert.equal(block.content, capture);
  }
});

test("the copied body follows the canonical submission order", () => {
  const md = findingToMarkdown({
    slug: "VA-007",
    title: "Canonical submission",
    severity: "high",
    workflowLabel: "Verified",
    verificationLabel: "Confirmed",
    verificationKey: "confirmed",
    summary: "Summary body",
    steps_to_reproduce: ["1. Reproduce"],
    evidence: "Evidence body",
    poc_code: "curl https://target.example",
    poc_request: "GET / HTTP/1.1",
    poc_response: "HTTP/1.1 200 OK",
    attack_scenario: "Attack scenario body",
    impact: "Impact body",
    remediation: "Remediation body",
  });

  const headings = [
    "### Summary",
    "### Steps to Reproduce",
    "### Evidence",
    "#### Payload",
    "#### Request",
    "#### Response",
    "### Attack Scenario",
    "### Impact",
    "### Remediation",
  ];
  for (let index = 1; index < headings.length; index += 1) {
    assert.ok(md.indexOf(headings[index - 1]) < md.indexOf(headings[index]), md);
  }
  assert.doesNotMatch(md, /### Proof of Concept|### PoC Request|### PoC Response/);
});

test("authored evidence remains Markdown while raw HTTP evidence stays fenced", () => {
  const authored = findingToMarkdown({
    slug: "VA-008",
    title: "Authored evidence",
    severity: "high",
    workflowLabel: "Verified",
    verificationLabel: "Confirmed",
    verificationKey: "confirmed",
    evidence: "#### Authorization bypass\n\nThe response returned `role: admin`.",
  });
  assert.match(authored, /### Evidence\n#### Authorization bypass/);
  assert.equal(fencedBlocks(authored).length, 0);

  const rawHttp = findingToMarkdown({
    slug: "VA-009",
    title: "Raw response",
    severity: "high",
    workflowLabel: "Verified",
    verificationLabel: "Confirmed",
    verificationKey: "confirmed",
    evidence: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}",
  });
  assert.equal(fencedBlocks(rawHttp).length, 1);
});
