import assert from "node:assert/strict";
import test from "node:test";

import { renderToStaticMarkup } from "react-dom/server";

import { RunsTab } from "./RunsTab";

test("shared Runs tab renders a masked, read-only audit entry state", () => {
  const html = renderToStaticMarkup(<RunsTab engagementKey="audit-test" />);

  assert.match(html, /Shared audit/);
  assert.match(html, /Assessment runs/);
  assert.match(html, /Code, web, blue, and shared work/);
  assert.match(html, /Sensitive values masked · raw evidence unchanged/);
  assert.match(html, /Untrusted target-derived data/i);
  assert.match(html, /aria-pressed="false"/);
  assert.match(html, />Reveal values</);
});
