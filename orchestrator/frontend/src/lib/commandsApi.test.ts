import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_COMMAND_FILTERS,
  DEFAULT_COMMAND_SORT,
  activeCommandFilterCount,
  commandFiltersKey,
  commandSortFromModel,
  commandStatusReason,
  createCommandDatasource,
  fetchCommandFacets,
  fetchCommandPage,
  fetchCommandPosition,
  searchToken,
  type CommandLedgerPage,
} from "./commandsApi.ts";

// `request` resolves app-relative paths against the page location.
function captureFetch(body: unknown): string[] {
  const urls: string[] = [];
  (globalThis as { window?: unknown }).window = { location: { pathname: "/", origin: "http://acme.example" } };
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    urls.push(String(input));
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return urls;
}

test("page, facets and position reads send every filter, the sort and the paging window", async () => {
  const urls = captureFetch({ total: 0, offset: 0, count: 0, has_more: false, items: [] });
  const filters = { status: ["failed", "lost"], tool: ["curl"], agent: ["recon-specialist"], technique: ["SSRF", ""], probe_kind: ["payload"], scope: "attention" as const, q: " tool:curl 3f2a91c4 " };
  await fetchCommandPage("acme-web", filters, { sort: "tool", dir: "asc", limit: 100, offset: 200 });
  await fetchCommandFacets("acme-web", filters, 500);
  await fetchCommandPosition("acme-web", 42, filters, DEFAULT_COMMAND_SORT);

  const page = new URL(urls[0]);
  assert.equal(page.pathname, "/engagements/acme-web/assessment/command-runs/page");
  assert.deepEqual(page.searchParams.getAll("status"), ["failed", "lost"]);
  assert.deepEqual(page.searchParams.getAll("tool"), ["curl"]);
  assert.deepEqual(page.searchParams.getAll("agent"), ["recon-specialist"]);
  // Technique and probe kind go as stored; the blank value selects runs that declared none.
  assert.deepEqual(page.searchParams.getAll("technique"), ["SSRF", ""]);
  assert.deepEqual(page.searchParams.getAll("probe_kind"), ["payload"]);
  assert.equal(page.searchParams.get("scope"), "attention");
  // The search text goes to the server as typed (trimmed): the server owns the grammar.
  assert.equal(page.searchParams.get("q"), "tool:curl 3f2a91c4");
  assert.equal(page.searchParams.get("sort"), "tool");
  assert.equal(page.searchParams.get("dir"), "asc");
  assert.equal(page.searchParams.get("limit"), "100");
  assert.equal(page.searchParams.get("offset"), "200");

  const facets = new URL(urls[1]);
  assert.equal(facets.pathname, "/engagements/acme-web/assessment/command-runs/facets");
  assert.equal(facets.searchParams.get("facet_limit"), "500");
  assert.equal(facets.searchParams.get("sort"), null);

  const position = new URL(urls[2]);
  assert.equal(position.pathname, "/engagements/acme-web/assessment/command-runs/42/position");
  assert.equal(position.searchParams.get("sort"), "created_at");
  assert.equal(position.searchParams.get("dir"), "desc");
  assert.equal(position.searchParams.get("scope"), "attention");
});

test("an empty search sends no q and the all-runs scope is explicit", async () => {
  const urls = captureFetch({ total: 0, offset: 0, count: 0, has_more: false, items: [] });
  await fetchCommandPage("acme-web", { ...DEFAULT_COMMAND_FILTERS, scope: "all", q: "   " }, { ...DEFAULT_COMMAND_SORT, limit: 10, offset: 0 });
  const page = new URL(urls[0]);
  assert.equal(page.searchParams.get("q"), null);
  assert.equal(page.searchParams.get("scope"), "all");
});

test("grid sort columns map to server sort keys; unsortable or cleared columns fall back to newest first", () => {
  assert.deepEqual(commandSortFromModel([{ colId: "tool", sort: "asc" }]), { sort: "tool", dir: "asc" });
  assert.deepEqual(commandSortFromModel([{ colId: "rc", sort: "desc" }]), { sort: "return_code", dir: "desc" });
  assert.deepEqual(commandSortFromModel([{ colId: "duration", sort: "asc" }]), { sort: "duration_ms", dir: "asc" });
  assert.deepEqual(commandSortFromModel([{ colId: "command", sort: "asc" }]), DEFAULT_COMMAND_SORT);
  assert.deepEqual(commandSortFromModel([{ colId: "time", sort: null }]), DEFAULT_COMMAND_SORT);
});

test("the datasource reads the requested block with the grid sort and reports the server total as the last row", async () => {
  const page: CommandLedgerPage = { total: 1450, offset: 100, count: 0, has_more: true, items: [] };
  const calls: unknown[] = [];
  const seen: CommandLedgerPage[] = [];
  const datasource = createCommandDatasource(async (params) => { calls.push(params); return page; }, { onPage: (answer) => seen.push(answer) });
  const result = await new Promise<{ rows: unknown[]; lastRow?: number }>((resolve, reject) => {
    datasource.getRows({
      startRow: 100,
      endRow: 200,
      sortModel: [{ colId: "agent", sort: "desc" }],
      successCallback: (rows, lastRow) => resolve({ rows, lastRow }),
      failCallback: () => reject(new Error("failed")),
    });
  });
  assert.deepEqual(calls, [{ sort: "agent", dir: "desc", limit: 100, offset: 100 }]);
  assert.equal(result.lastRow, 1450);
  assert.equal(seen.length, 1);
});

test("a failed block read reports its message and fails the block", async () => {
  const errors: string[] = [];
  const datasource = createCommandDatasource(async () => { throw new Error("ledger unavailable"); }, { onError: (message) => errors.push(message) });
  await new Promise<void>((resolve) => {
    datasource.getRows({ startRow: 0, endRow: 100, sortModel: [], successCallback: () => undefined, failCallback: () => resolve() });
  });
  assert.deepEqual(errors, ["ledger unavailable"]);
});

test("the status reason puts the exit outcome after the status meaning and keeps every server reason", () => {
  assert.equal(
    commandStatusReason({ status: "failed", return_code: 7, timeout_seconds_requested: null, attention_reasons: ["finished unsuccessfully", "partial results"] }),
    "finished unsuccessfully · exit code 7 · partial results",
  );
  assert.equal(
    commandStatusReason({ status: "completed", return_code: 0, timeout_seconds_requested: null, attention_reasons: ["output cleanup deferred"] }),
    "exit code 0 · output cleanup deferred",
  );
  assert.equal(
    commandStatusReason({ status: "timed_out", return_code: null, timeout_seconds_requested: 180, attention_reasons: ["stopped at its time limit"] }),
    "stopped at its time limit · limit 180s",
  );
  assert.equal(commandStatusReason({ status: "completed", return_code: null, timeout_seconds_requested: null, attention_reasons: [] }), "no exit code recorded");
  assert.equal(commandStatusReason({ status: "running", return_code: null, timeout_seconds_requested: null, attention_reasons: ["still running"] }), "still running");
});

test("filter identity ignores chip order and surrounding spaces; the scope is not an operator filter", () => {
  const a = { status: ["lost", "failed"], tool: ["curl"], agent: [], technique: ["SSRF", "IDOR"], probe_kind: [], scope: "all" as const, q: "ssrf " };
  const b = { status: ["failed", "lost"], tool: ["curl"], agent: [], technique: ["IDOR", "SSRF"], probe_kind: [], scope: "all" as const, q: "ssrf" };
  assert.equal(commandFiltersKey(a), commandFiltersKey(b));
  assert.notEqual(commandFiltersKey(a), commandFiltersKey({ ...b, scope: "attention" }));
  assert.notEqual(commandFiltersKey(a), commandFiltersKey({ ...b, probe_kind: ["exploit"] }));
  assert.equal(activeCommandFilterCount(a), 6);
  assert.equal(activeCommandFilterCount(DEFAULT_COMMAND_FILTERS), 0);
});

test("search tokens quote values with spaces", () => {
  assert.equal(searchToken("technique", "SSRF"), "technique:SSRF");
  assert.equal(searchToken("intent", "verify token leak"), 'intent:"verify token leak"');
});
