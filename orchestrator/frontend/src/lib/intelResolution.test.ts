import assert from "node:assert/strict";
import test from "node:test";

import { chunkIntelResolutionIds } from "./api.ts";

test("intel resolution batches preserve 101 ids without exceeding the API limit", () => {
  const ids = Array.from({ length: 101 }, (_, index) => index + 1);
  const batches = chunkIntelResolutionIds(ids);
  assert.deepEqual(batches.map((batch) => batch.length), [100, 1]);
  assert.deepEqual(batches.flat(), ids);
});
