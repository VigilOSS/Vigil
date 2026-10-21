import assert from "node:assert/strict";
import test from "node:test";

import { renderToStaticMarkup } from "react-dom/server";

import { RunsTab } from "./RunsTab";

test("the Runs workspace states its purpose and renders a loading skeleton before data", () => {
  const html = renderToStaticMarkup(<RunsTab engagementKey="audit-test" />);

  assert.match(html, /<h1 class="ui-page-title">Runs<\/h1>/);
  assert.match(html, /Each run is one evidence-gathering session by an agent/);
  assert.match(html, /aria-busy="true"/);
});
