import assert from "node:assert/strict";
import test from "node:test";

import { createCoalescedRunner } from "./coalesce.ts";

test("refresh bursts coalesce into one in-flight load plus one trailing load", async () => {
  let calls = 0;
  const releases: (() => void)[] = [];
  const run = createCoalescedRunner(() => {
    calls += 1;
    return new Promise<void>((resolve) => releases.push(resolve));
  });
  const first = run("join");
  run("join");
  assert.equal(calls, 1, "a join shares the in-flight load");
  run("refresh");
  run("refresh");
  run("refresh");
  assert.equal(calls, 1, "refreshes never start a second concurrent load");
  releases.shift()?.();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls, 2, "a burst ends with exactly one trailing load");
  releases.shift()?.();
  await first;
  assert.equal(calls, 2);
  const next = run("refresh");
  assert.equal(calls, 3, "an idle runner starts immediately");
  releases.shift()?.();
  await next;
});

test("a pass can tell whether a refresh arrived while it ran", async () => {
  const seen: boolean[] = [];
  const releases: (() => void)[] = [];
  const run = createCoalescedRunner(async ({ rerunQueued }) => {
    await new Promise<void>((resolve) => releases.push(resolve));
    seen.push(rerunQueued());
  });
  const done = run();
  run("refresh");
  releases.shift()?.();
  await new Promise((resolve) => setTimeout(resolve, 0));
  releases.shift()?.();
  await done;
  assert.deepEqual(seen, [true, false], "the first pass saw the queued refresh; the trailing pass saw none");
});

test("onSettled runs once, synchronously, when the last queued pass finishes", async () => {
  const events: string[] = [];
  const releases: (() => void)[] = [];
  const run = createCoalescedRunner(
    async () => {
      events.push("pass");
      await new Promise<void>((resolve) => releases.push(resolve));
    },
    () => events.push("settled"),
  );
  const done = run();
  run("refresh");
  run("refresh");
  releases.shift()?.();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(events, ["pass", "pass"]);
  releases.shift()?.();
  await done;
  assert.deepEqual(events, ["pass", "pass", "settled"]);
  // A pass that throws still settles the runner, so the next call starts fresh.
  const failing = createCoalescedRunner(async () => {
    throw new Error("boom");
  }, () => events.push("settled after failure"));
  await assert.rejects(failing(), /boom/);
  assert.equal(events.at(-1), "settled after failure");
});
