import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { ReproRunProvenance } from "./FindingParts";

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
