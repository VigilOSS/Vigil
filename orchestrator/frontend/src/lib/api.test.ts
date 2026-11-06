import assert from "node:assert/strict";
import test from "node:test";

import { listAssessmentFindingLinks, listSurfaceRequestVariantLinks } from "./api.ts";

// Bounded BARE-LIST reads. These routes answer with a JSON array and no
// envelope — no `total`, no `has_more` — so a capped response is
// indistinguishable from a complete one and every view downstream renders a
// silently short list. Two of them are read whole by the SPA:
//
//   /finding-links                                     every finding's relationships,
//                                                      and the per-surface finding counts
//   /surface-request-variant-links/by-surface/{id}     rendered as the surface's own count
//
// so a cap does not merely hide rows there, it states a wrong number.

/** Stub `fetch` with a paginated bare list; returns the URLs it was asked for. */
function captureBareListFetch(total: number): string[] {
  const urls: string[] = [];
  (globalThis as { window?: unknown }).window = { location: { pathname: "/", origin: "http://acme.example" } };
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    urls.push(String(input));
    const limit = Number(url.searchParams.get("limit"));
    const offset = Number(url.searchParams.get("offset"));
    const page = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_unused, index) => ({
      id: offset + index + 1,
    }));
    return new Response(JSON.stringify(page), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return urls;
}

test("the finding-links read walks every page rather than trusting one", async () => {
  const urls = captureBareListFetch(1203);
  const links = await listAssessmentFindingLinks("acme-web");

  // Every row, not just the first page.
  assert.equal(links.length, 1203);
  assert.deepEqual(links.map((link) => (link as unknown as { id: number }).id).slice(0, 3), [1, 2, 3]);
  assert.equal((links[links.length - 1] as unknown as { id: number }).id, 1203);

  // Paged over the route's own window, and stopped by a short page.
  assert.equal(urls.length, 3);
  const first = new URL(urls[0]);
  assert.equal(first.pathname, "/engagements/acme-web/assessment/finding-links");
  assert.equal(first.searchParams.get("offset"), "0");
  assert.ok(Number(first.searchParams.get("limit")) >= 1);
  assert.deepEqual(
    urls.map((url) => new URL(url).searchParams.get("offset")),
    ["0", "500", "1000"],
  );
});

test("a surface's request-variant links are counted from every page", async () => {
  // The Surfaces record renders this array's own `.length` as the surface's
  // durable-variant total, so a capped page publishes a wrong count.
  const urls = captureBareListFetch(501);
  const links = await listSurfaceRequestVariantLinks("acme-web", 42);

  assert.equal(links.length, 501);
  assert.equal(urls.length, 2);
  assert.equal(
    new URL(urls[0]).pathname,
    "/engagements/acme-web/assessment/surface-request-variant-links/by-surface/42",
  );
});

test("an exactly-full final page is followed by the empty page that proves it is the end", async () => {
  // The stop condition is a SHORT page. A total that lands exactly on a page
  // boundary therefore costs one more request — and must not drop rows or
  // loop, which is the failure a `page.length === 0` guard alone would hide.
  const urls = captureBareListFetch(1000);
  const links = await listAssessmentFindingLinks("acme-web");

  assert.equal(links.length, 1000);
  assert.deepEqual(
    urls.map((url) => new URL(url).searchParams.get("offset")),
    ["0", "500", "1000"],
  );
});
