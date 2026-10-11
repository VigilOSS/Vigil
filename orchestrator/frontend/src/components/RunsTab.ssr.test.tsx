import assert from "node:assert/strict";
import test from "node:test";

import { renderToStaticMarkup } from "react-dom/server";

import { RunsTab } from "./RunsTab";

test("shared Runs tab renders a read-only audit entry state", () => {
  const html = renderToStaticMarkup(<RunsTab engagementKey="audit-test" />);

  assert.match(html, /Shared audit/);
  assert.match(html, /Assessment runs/);
  assert.match(html, /Code, web, blue, and shared work/);
});
