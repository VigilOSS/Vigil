// Why the intel TABLE travels with the cited intel id.
//
// An operator-attested verdict carries no proof receipt, so the cited intel row
// is the one thing in it a distrustful reader can go and open. `intel get` takes
// the type as a required positional over ten entity types whose id sequences are
// allocated independently, which makes a bare id ambiguous rather than merely
// terse: a verdict citing `tech-component 1` resolves to an unrelated note on
// id 1 in whichever table the reader guessed. The citation then sends the one
// reader who distrusted the verdict to the wrong record.
//
// `asOperatorAuthority` narrows a free-form JSON column by copying the keys it
// recognises, so a key it does not copy is a key this document cannot render —
// silently, because the extra key throws nothing. That makes the narrowing, not
// the components, the place this is pinned.
//
// The degradation below is deliberate. A stamp carrying an id and no type must
// still render, naming the id alone: saying less is correct, and naming a table
// nobody resolved is the hazard itself.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  asOperatorAuthority,
  operatorAuthorityLabel,
  operatorAuthoritySentence,
} from "./operatorAuthority";

const stamp = {
  kind: "out_of_snapshot",
  intel_id: 17,
  intel_type: "tech-component",
  at: "2026-06-03T09:14:00Z",
  reason: "The edge proxy configuration strips the header before it leaves the perimeter.",
};

test("the narrowed stamp carries the intel table beside the id", () => {
  const narrowed = asOperatorAuthority(stamp);
  assert.ok(narrowed);
  assert.equal(narrowed.intel_id, 17);
  assert.equal(narrowed.intel_type, "tech-component");
});

test("both renderings name the table the cited id belongs to", () => {
  const narrowed = asOperatorAuthority(stamp);
  assert.ok(narrowed);
  // The same spelling the CLI prints and the operator would type
  // (`vigil assess intel get tech-component 17`), so a reader following the
  // citation out of this document lands on the row the verdict rested on.
  assert.equal(operatorAuthorityLabel(narrowed), "Operator attested · intel tech-component 17");
  assert.match(operatorAuthoritySentence(narrowed), /Cited intel tech-component 17\./);
});

test("a type the column did not deliver as a table name leaves the id standing alone", () => {
  // A stamp written before the field existed carries no type, and the column is
  // free-form, so a value that is not a table name can arrive. Both degrade to
  // the id by itself rather than to a guess.
  for (const intel_type of [undefined, "", 42, null, ["note"]]) {
    const narrowed = asOperatorAuthority({ ...stamp, intel_type });
    assert.ok(narrowed);
    assert.equal(operatorAuthorityLabel(narrowed), "Operator attested · intel 17");
    assert.match(operatorAuthoritySentence(narrowed), /Cited intel 17\./);
  }
});

test("a type with no id behind it cites nothing, and the verdict still says how it was reached", () => {
  // Half a citation is not a citation: the type alone opens no row, so the
  // waiver states itself and names no record.
  const narrowed = asOperatorAuthority({
    kind: "out_of_snapshot",
    intel_type: "note",
    reason: "Acme confirmed the fix shipped outside the snapshot.",
  });
  assert.ok(narrowed);
  assert.equal(operatorAuthorityLabel(narrowed), "Operator attested");
  assert.match(operatorAuthoritySentence(narrowed), /rather than a proof receipt\./);
});
