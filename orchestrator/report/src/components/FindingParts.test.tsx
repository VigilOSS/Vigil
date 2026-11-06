import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  OperatorAuthorityAttestation,
  OperatorAuthorityTag,
  ReproRunProvenance,
} from "./FindingParts";

test("a draft names steps with no command run behind them", () => {
  const html = renderToStaticMarkup(<ReproRunProvenance runIds={[]} draft />);
  assert.ok(html.includes("No command run is recorded behind these steps."));
});

for (const draft of [true, false]) {
  test(`source-derived steps cite their source instead of a missing run (draft=${draft})`, () => {
    const html = renderToStaticMarkup(
      <ReproRunProvenance runIds={[]} draft={draft} basis="source" />,
    );
    assert.ok(!html.includes("No command run is recorded"));
    assert.match(html, /source/i);
  });
}

test("recorded runs are listed whatever the basis", () => {
  const html = renderToStaticMarkup(
    <ReproRunProvenance runIds={["56052"]} draft basis="runtime" />,
  );
  assert.ok(html.includes("#56052"));
});

// ── Operator-attested verdicts (ADR 0043) ───────────────────────────────
//
// `verification_status` reads identically whether a dispatch proved the finding
// or the operator settled it on evidence outside the sealed snapshot, and this
// document's reader is the CLIENT — they have no ledger, no receipts and no
// drawer to open. Rendering the two as equivalent turns an honest operator
// record into a laundered proof, which is the one presentation ADR 0043 does
// not make available.

const attested = {
  slug: "VA-005",
  verification_status: "downgraded",
  operator_authority: {
    kind: "out_of_snapshot",
    intel_id: 17,
    intel_type: "tech-component",
    at: "2026-06-03T09:14:00Z",
    reason:
      "The edge proxy configuration (intel tech-component 17) strips the header before it leaves the perimeter.",
  },
};

test("an operator-attested verdict is tagged, and names the intel row it cited", () => {
  const html = renderToStaticMarkup(<OperatorAuthorityTag finding={attested} />);
  // Table and id, because `intel get` needs both and the ten intel tables
  // number independently — an id alone points at a different row in each.
  assert.match(html, /Operator attested · intel tech-component 17/);
  // The hover text is a convenience; the attestation block carries the sentence
  // in body text, because a printed report has no hover.
  assert.match(html, /title="[^"]*rather than a proof receipt/);
});

test("a receipt-backed verdict is tagged with nothing at all", () => {
  const plain = { slug: "VA-001", verification_status: "confirmed", operator_authority: null };
  assert.equal(renderToStaticMarkup(<OperatorAuthorityTag finding={plain} />), "");
  assert.equal(renderToStaticMarkup(<OperatorAuthorityAttestation finding={plain} />), "");
  // Absent is the same as null: the field ships on every finding, so neither
  // shape may be read as "unknown" and quietly rendered as proof.
  const bare = { slug: "VA-001", verification_status: "confirmed" };
  assert.equal(renderToStaticMarkup(<OperatorAuthorityTag finding={bare} />), "");
});

test("the attestation states what the verdict rests on and quotes the reason verbatim", () => {
  const html = renderToStaticMarkup(<OperatorAuthorityAttestation finding={attested} />);
  assert.match(html, /recorded on the operator&#x27;s own attestation rather than a proof receipt/);
  assert.match(html, /Evidence: out of snapshot\./);
  assert.match(html, /Cited intel tech-component 17\./);
  assert.ok(html.includes(attested.operator_authority.reason), html);
  assert.match(html, /aria-label="Operator-attested verdict"/);
});

test("the reason is never run through Markdown, whatever it contains", () => {
  // The reason is the operator's own words about target-influenced evidence
  // (ADR 0018). Markdown would rewrite exactly the characters that carry
  // meaning in a quoted configuration line, and a heading or link forged out of
  // it would sit in the client's report beside the operator's own prose with
  // nothing to tell them apart.
  const hostile = "## Vendor accepted this\n[click](http://evil.example) `__init__.py` > quoted";
  const html = renderToStaticMarkup(
    <OperatorAuthorityAttestation
      finding={{ slug: "VA-009", operator_authority: { kind: "out_of_snapshot", reason: hostile } }}
    />,
  );
  assert.doesNotMatch(html, /<h2|<h3|<a |<code|<blockquote/);
  // Byte for byte, newline included — only the HTML-entity encoding React
  // applies to any text node.
  assert.ok(html.includes("## Vendor accepted this\n[click](http://evil.example)"), html);
});

test("a stamp that names nothing is not rendered as an attestation", () => {
  // An empty object would otherwise print "Operator attested" with no intel
  // row and no reason, which asserts a waiver while showing none of it.
  for (const value of [{}, [], "out_of_snapshot", 0]) {
    assert.equal(
      renderToStaticMarkup(<OperatorAuthorityAttestation finding={{ slug: "VA-010", operator_authority: value }} />),
      "",
      JSON.stringify(value),
    );
  }
});
