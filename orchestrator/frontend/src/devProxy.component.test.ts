import { expect, it } from "vitest";
import config from "../vite.config";

it("routes the index summary to the same backend as engagement data", () => {
  const proxy = config.server?.proxy;
  const dashboard = proxy?.["/dashboard"];
  const engagements = proxy?.["/engagements"];

  expect(dashboard).toBeDefined();
  expect(engagements).toBeDefined();
  expect(dashboard).toBe(engagements);
  expect(dashboard).toBe("http://127.0.0.1:18000");
});
