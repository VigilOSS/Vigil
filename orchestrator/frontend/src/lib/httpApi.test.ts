import assert from "node:assert/strict";
import test from "node:test";

import { readLedgerHead } from "./httpApi.ts";

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
