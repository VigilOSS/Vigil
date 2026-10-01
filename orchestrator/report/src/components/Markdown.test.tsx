import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { Markdown } from "./Markdown";

for (const source of [
  "https://user:password@target.example/pixel?token=secret&session=123",
  "http://127.0.0.1:8080/pixel",
  "//target.example/pixel",
  "./evidence.png",
]) {
  test(`image source stays visible without fetching: ${source}`, () => {
    const html = renderToStaticMarkup(<Markdown text={`![Captured proof](${source})`} />);
    assert.doesNotMatch(html, /<(?:img|link)\b/);
    assert.ok(html.includes("<strong>Captured proof</strong>"));
    assert.ok(html.includes(`<code>${source.replaceAll("&", "&amp;")}</code>`));
  });
}

test("reference images and empty alt text stay inert while ordinary links work", () => {
  const html = renderToStaticMarkup(
    <Markdown text={'![][proof]\n\n[proof]: https://target.example/proof\n\n[Open evidence](https://target.example/evidence)'} />,
  );
  assert.doesNotMatch(html, /<(?:img|link)\b/);
  assert.match(html, /<strong>[^<]+<\/strong>/);
  assert.ok(html.includes("<code>https://target.example/proof</code>"));
  assert.ok(html.includes('href="https://target.example/evidence"'));
  assert.ok(html.includes('target="_blank" rel="noopener noreferrer"'));
});

test("raw HTML stays escaped and blocked image URLs cannot become active", () => {
  const html = renderToStaticMarkup(
    <Markdown text={'<img src="https://target.example/pixel">\n\n![Payload](javascript:alert%281%29)'} />,
  );
  assert.doesNotMatch(html, /<(?:img|link|script)\b/);
  assert.ok(html.includes('&lt;img src=&quot;https://target.example/pixel&quot;&gt;'));
  assert.ok(html.includes("<strong>Payload</strong>"));
  assert.doesNotMatch(html, /(?:src|href)="javascript:/);
});
