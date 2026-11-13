import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_REQUEST_VARIANT_ORDER,
  REQUEST_VARIANT_COLUMN_SORT,
  fullBodyBytes,
  parseRequestVariantOrder,
  readLedgerHead,
  requestVariantColumnInitialSort,
} from "./httpApi.ts";

// A newest-first ledger of ids; each read records its window.
function ledger(ids: number[]) {
  const reads: [number, number][] = [];
  const fetchPage = async (offset: number, limit: number) => {
    reads.push([offset, limit]);
    return ids.slice(offset, offset + limit).map((id) => ({ id }));
  };
  return { reads, fetchPage };
}
const rows = (...ids: number[]) => ids.map((id) => ({ id }));
const keyOf = (row: { id: number }) => row.id;

test("readLedgerHead reads the whole page when nothing is held", async () => {
  const { reads, fetchPage } = ledger([3, 2, 1]);
  assert.deepEqual(await readLedgerHead(fetchPage, null, 10, keyOf, 2), rows(3, 2, 1));
  assert.deepEqual(reads, [[0, 10]]);
});

test("readLedgerHead adds only the rows newer than those held", async () => {
  const { reads, fetchPage } = ledger([6, 5, 4, 3, 2, 1]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5, 4, 3, 2, 1), 10, keyOf, 3), rows(6, 5, 4, 3, 2, 1));
  assert.deepEqual(reads, [[0, 3]]);
});

test("readLedgerHead returns at most a page", async () => {
  const { reads, fetchPage } = ledger([7, 6, 5, 4, 3]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5, 4, 3), 4, keyOf, 3), rows(7, 6, 5, 4));
  assert.deepEqual(reads, [[0, 3]]);
});

test("readLedgerHead reads four times more while no held row shows up", async () => {
  const { reads, fetchPage } = ledger([9, 8, 7, 6, 5]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5), 10, keyOf, 2), rows(9, 8, 7, 6, 5));
  assert.deepEqual(reads, [[0, 2], [0, 8]]);
});

test("readLedgerHead reads the whole page when more than a page of rows arrived", async () => {
  const { reads, fetchPage } = ledger([20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 5]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5), 10, keyOf, 2), rows(20, 19, 18, 17, 16, 15, 14, 13, 12, 11));
  assert.deepEqual(reads, [[0, 2], [0, 8], [0, 10]]);
});

test("readLedgerHead reads the page when the probe does not line up with what is held", async () => {
  const { reads, fetchPage } = ledger([6, 5, 3]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5, 4, 3), 10, keyOf, 3), rows(6, 5, 3));
  assert.deepEqual(reads, [[0, 3], [0, 10]]);
});

test("readLedgerHead takes a short probe without the held rows as the whole ledger", async () => {
  const { reads, fetchPage } = ledger([2]);
  assert.deepEqual(await readLedgerHead(fetchPage, rows(5, 4), 10, keyOf, 3), rows(2));
  assert.deepEqual(reads, [[0, 3]]);
});

test("a grid mounting on a kept order starts sorted on exactly that order's column", () => {
  const order = { sort: "path", dir: "asc" } as const;
  const sorted = Object.keys(REQUEST_VARIANT_COLUMN_SORT).filter((colId) => requestVariantColumnInitialSort(colId, order) !== undefined);
  assert.deepEqual(sorted, ["path"]);
  assert.equal(requestVariantColumnInitialSort("path", order), "asc");
  assert.equal(requestVariantColumnInitialSort("lastseen", DEFAULT_REQUEST_VARIANT_ORDER), "desc");
});

test("a kept order is restored only when a grid column can show it", () => {
  assert.deepEqual(parseRequestVariantOrder({ sort: "observations", dir: "desc" }), { sort: "observations", dir: "desc" });
  // No column sorts by id or first-seen time, so the grid could not show such an order.
  assert.deepEqual(parseRequestVariantOrder({ sort: "id", dir: "asc" }), DEFAULT_REQUEST_VARIANT_ORDER);
  assert.deepEqual(parseRequestVariantOrder({ sort: "path", dir: "sideways" }), DEFAULT_REQUEST_VARIANT_ORDER);
  assert.deepEqual(parseRequestVariantOrder("path"), DEFAULT_REQUEST_VARIANT_ORDER);
  assert.deepEqual(parseRequestVariantOrder(undefined), DEFAULT_REQUEST_VARIANT_ORDER);
});

test("a truncated body's full size is known only from an uncoded Content-Length", () => {
  assert.equal(fullBodyBytes({ "Content-Length": "1048576" }, 524_288), 1_048_576);
  assert.equal(fullBodyBytes({ "content-length": "1048576", "Content-Encoding": "identity" }, 524_288), 1_048_576);
  // A coded body's length counts wire bytes, not the decoded bytes the capture stores.
  assert.equal(fullBodyBytes({ "Content-Length": "189788", "Content-Encoding": "br" }, 524_288), null);
  assert.equal(fullBodyBytes({ "Transfer-Encoding": "chunked" }, 524_288), null);
  // A length that does not exceed what was stored says nothing about a cut.
  assert.equal(fullBodyBytes({ "Content-Length": "100" }, 524_288), null);
  assert.equal(fullBodyBytes({ "Content-Length": "many" }, 10), null);
  assert.equal(fullBodyBytes(null, 10), null);
});
