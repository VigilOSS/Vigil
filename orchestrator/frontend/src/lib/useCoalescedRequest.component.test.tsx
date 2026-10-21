// @vitest-environment jsdom

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCoalescedRequest, useCoalescedRunner } from "./useCoalescedRequest";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

afterEach(cleanup);

describe("useCoalescedRequest", () => {
  it("keeps one request in flight and re-runs once for a burst of reloads", async () => {
    const first = deferred<string>();
    const load = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValue("second");
    const { result, rerender } = renderHook(({ token }) => useCoalescedRequest("key", load, token), {
      initialProps: { token: 0 },
    });
    expect(load).toHaveBeenCalledTimes(1);
    rerender({ token: 1 });
    rerender({ token: 2 });
    rerender({ token: 3 });
    expect(load).toHaveBeenCalledTimes(1);
    await act(async () => first.resolve("first"));
    await waitFor(() => expect(result.current.data).toBe("second"));
    expect(load).toHaveBeenCalledTimes(2);
    expect(result.current.loading).toBe(false);
  });

  it("discards a response for a key that is no longer current and keeps showing prior data", async () => {
    const stale = deferred<string>();
    const loads: Record<string, () => Promise<string>> = {
      a: () => Promise.resolve("A"),
      b: () => stale.promise,
      c: () => Promise.resolve("C"),
    };
    const { result, rerender } = renderHook(({ key }) => useCoalescedRequest(key, loads[key]), {
      initialProps: { key: "a" },
    });
    await waitFor(() => expect(result.current.data).toBe("A"));
    rerender({ key: "b" });
    await waitFor(() => expect(result.current.loading).toBe(true));
    rerender({ key: "c" });
    expect(result.current.data).toBe("A");
    await act(async () => stale.resolve("B"));
    await waitFor(() => expect(result.current.data).toBe("C"));
    expect(result.current.dataKey).toBe("c");
  });

  it("does not load while disabled", () => {
    const load = vi.fn().mockResolvedValue("x");
    renderHook(() => useCoalescedRequest("key", load, 0, false));
    expect(load).not.toHaveBeenCalled();
  });
});

describe("useCoalescedRunner", () => {
  it("joins a repeated mount load, queues one rerun for a refresh burst, and always runs the latest task", async () => {
    const first = deferred<void>();
    const calls: string[] = [];
    const tasks = {
      a: vi.fn(() => {
        calls.push("a");
        return calls.length === 1 ? first.promise : Promise.resolve();
      }),
      b: vi.fn(() => {
        calls.push("b");
        return Promise.resolve();
      }),
    };
    const { result, rerender } = renderHook(({ name }: { name: "a" | "b" }) => useCoalescedRunner(tasks[name]), {
      initialProps: { name: "a" },
    });
    const run = result.current;
    void run("join");
    void run("join");
    expect(calls).toEqual(["a"]);
    rerender({ name: "b" });
    expect(result.current).toBe(run);
    void run("refresh");
    void run("refresh");
    await act(async () => first.resolve());
    await waitFor(() => expect(calls).toEqual(["a", "b"]));
  });
});
