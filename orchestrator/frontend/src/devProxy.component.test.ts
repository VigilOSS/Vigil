import { expect, it } from "vitest";
import config from "../vite.config";

it("routes the index summary to the same backend as engagement data", () => {
  const proxy = config.server?.proxy;
  expect(proxy?.["/dashboard"]).toBe(proxy?.["/engagements"]);
});
