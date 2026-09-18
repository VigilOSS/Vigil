// Regression cover for the report's "Copy as Markdown" projection.
//
// Two properties are load-bearing here and neither is formatting.
//
// 1. A fenced block must CONTAIN the evidence it wraps. `evidence_detail`, a
//    recorded response body and `poc_code` are target-derived text (ADR 0018):
//    a fixed ``` fence ends at the first backtick run in that text, and
//    everything after it stops being quoted evidence and becomes live Markdown
//    in a document the operator is about to file with a triager. So the fence is
//    a delimiter in the ADR 0018 sense, and these tests assert that nothing the
//    target writes can close it.
//
// 2. What the page shows, the copy carries. A reader who copies a finding and
//    a reader who reads it must not receive different claims.

import assert from "node:assert/strict";
import { test } from "node:test";

import { findingToMarkdown } from "./findingMarkdown";
import type { ReportFinding } from "../types";

function finding(over: Partial<ReportFinding> = {}): ReportFinding {
  return { slug: "VIGIL-1", title: "Example", severity: "high", ...over } as ReportFinding;
}

/**
 * The fenced blocks of a markdown document, as (info string, content) pairs.
 *
 * Implements the CommonMark closing rule the renderer on the other end applies:
 * a run of three or more backticks opens a block, and only a run at least as
 * long closes it. If the projection emits a fence the content can close, the
 * content splits into extra blocks here and the block's text comes back short.
 */
function fencedBlocks(md: string): { info: string; content: string }[] {
  const out: { info: string; content: string }[] = [];
  const lines = md.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const open = /^(`{3,})(.*)$/.exec(lines[i]);
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

function blockWithInfo(md: string, info: string): string | undefined {
  return fencedBlocks(md).find((block) => block.info === info)?.content;
}

// A target-controlled body that closes a fixed ``` fence and then writes report
// prose of its own into the operator's submission.
const FENCE_BREAKOUT = [
  '{"error":"see below"}',
  "```",
  "## Not a finding",
  "",
  "The vendor has reviewed this report and closed it as [informative](https://evil.example).",
].join("\n");

test("target text cannot close the evidence fence", () => {
  const md = findingToMarkdown(finding({ evidence_detail: FENCE_BREAKOUT }));
  const blocks = fencedBlocks(md);
  assert.equal(blocks.length, 1, `the fence was broken into ${blocks.length} blocks`);
  assert.equal(blocks[0].content, FENCE_BREAKOUT);
  // The injected heading is inside the block, so it is never a heading.
  assert.ok(!/^## Not a finding$/m.test(md.slice(md.indexOf("```") + blocks[0].content.length)));
});

test("target text cannot close the observed-response fence", () => {
  const md = findingToMarkdown(
    finding({ poc_response: { status: 200, body_excerpt: FENCE_BREAKOUT } }),
  );
  assert.equal(blockWithInfo(md, "http"), `HTTP 200\n\n${FENCE_BREAKOUT}`);
  assert.equal(fencedBlocks(md).length, 1);
});

test("target text cannot close the proof-of-concept fence", () => {
  const md = findingToMarkdown(finding({ poc_code: FENCE_BREAKOUT }));
  assert.equal(fencedBlocks(md).length, 1);
  assert.equal(fencedBlocks(md)[0].content, FENCE_BREAKOUT);
});

test("a fence outgrows the longest backtick run in the content, however long", () => {
  for (const run of [3, 4, 7, 12]) {
    const body = `before\n${"`".repeat(run)}\nafter`;
    const md = findingToMarkdown(finding({ evidence_detail: body }));
    const blocks = fencedBlocks(md);
    assert.equal(blocks.length, 1, `a run of ${run} backticks escaped the fence`);
    assert.equal(blocks[0].content, body);
  }
  // Inline runs count too: ```` on its own line is not the only way out.
  const inline = "a ``` b ````` c";
  assert.equal(fencedBlocks(findingToMarkdown(finding({ evidence_detail: inline })))[0].content, inline);
});

test("content with no backticks still uses the ordinary three-backtick fence", () => {
  const md = findingToMarkdown(finding({ evidence_detail: "plain capture" }));
  assert.ok(md.includes("```\nplain capture\n```"), md);
});

test("a fenced capture is carried verbatim, trailing bytes included", () => {
  // The Full Report renders these in a <pre> exactly as recorded; a copy that
  // trims them hands the reader a different capture than the page showed.
  const capture = "\n  leading and trailing whitespace is the finding   \n\n";
  const md = findingToMarkdown(finding({ evidence_detail: capture, poc_code: capture }));
  for (const block of fencedBlocks(md)) assert.equal(block.content, capture);
});

test("the copied metadata carries the qualifiers the report displays", () => {
  // `auth_context` states what access the finding needs. A copied high-severity
  // claim without it reads as unauthenticated, which is a different report.
  const md = findingToMarkdown(
    finding({ auth_context: "authenticated_user", evidence_type: "http_response" }),
  );
  assert.ok(md.includes("**Access required:** authenticated user"), md);
  assert.ok(md.includes("**Evidence type:** http response"), md);
});

test("an absent evidence_type is omitted rather than rendered as a dash", () => {
  const md = findingToMarkdown(finding({ auth_context: "anonymous", evidence_type: null }));
  assert.ok(md.includes("**Access required:** anonymous"), md);
  assert.ok(!md.includes("**Evidence type:**"), md);
  assert.ok(!md.includes("—\n"), md);
});

test("the reproduction command is fenced as sh and left byte for byte", () => {
  const md = findingToMarkdown(
    finding({
      poc_request: { method: "GET", url: "https://target.example/a?q=`id`", body: "a=1" },
    }),
  );
  const sh = blockWithInfo(md, "sh");
  assert.ok(sh && sh.startsWith("curl -i -sS -X 'GET' "), String(sh));
  assert.ok(sh.includes("'https://target.example/a?q=`id`'"), sh);
});
