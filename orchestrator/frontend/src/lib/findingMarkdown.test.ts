import assert from "node:assert/strict";
import test from "node:test";

import { findingToMarkdown } from "./findingMarkdown.ts";

// A capture is target-controlled text (ADR 0018). These pin the two ways it
// could stop being evidence: escaping its fence into live Markdown, and being
// rewritten on the way to the operator's clipboard.

function fencedBlocks(md: string): string[] {
  const blocks: string[] = [];
  const lines = md.split("\n");
  let fence: string | null = null;
  let buf: string[] = [];
  for (const line of lines) {
    const m = line.match(/^(`{3,})/);
    if (fence === null && m) {
      fence = m[1];
      buf = [];
    } else if (fence !== null && m && m[1].length >= fence.length && line.trim() === m[1]) {
      blocks.push(buf.join("\n"));
      fence = null;
    } else if (fence !== null) {
      buf.push(line);
    }
  }
  return blocks;
}

test("a backtick run in a captured body cannot escape its fence", () => {
  const hostile = 'HTTP/1.1 200 OK\n\n```\n## Not a finding\n[click](http://evil.example)\n';
  const md = findingToMarkdown({
    slug: "VA-001",
    title: "T",
    poc_response: { status: 200, body: hostile },
  } as never);

  const blocks = fencedBlocks(md);
  const holding = blocks.find((b) => b.includes("Not a finding"));
  assert.ok(holding, "the injected heading must stay inside a fence");
  assert.ok(holding.includes("[click](http://evil.example)"), "and so must the link");
  // Nothing target-controlled may sit at document level.
  const outside = md
    .split("\n")
    .filter((l) => !blocks.join("\n").split("\n").includes(l));
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
