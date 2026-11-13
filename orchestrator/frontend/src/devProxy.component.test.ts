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

type WsHandler = (
  proxyReq: { setHeader: (name: string, value: string) => void },
  req: { headers: Record<string, string | undefined> },
) => void;

function wsOriginRewrite(): WsHandler {
  const ws = config.server?.proxy?.["/ws"];
  if (!ws || typeof ws === "string" || !ws.configure) throw new Error("/ws proxy has no configure hook");
  const handlers: Record<string, WsHandler> = {};
  ws.configure({ on: (event: string, handler: WsHandler) => { handlers[event] = handler; } } as never, ws);
  const handler = handlers.proxyReqWs;
  if (!handler) throw new Error("/ws proxy does not handle proxyReqWs");
  return handler;
}

function forwardedOrigin(headers: Record<string, string | undefined>): string | undefined {
  let origin = headers.origin;
  wsOriginRewrite()({ setHeader: (name, value) => { if (name.toLowerCase() === "origin") origin = value; } }, { headers });
  return origin;
}

it("presents the dev page's own live-update socket with the backend's origin", () => {
  expect(forwardedOrigin({ origin: "http://localhost:5173", host: "localhost:5173" })).toBe("http://127.0.0.1:18000");
  expect(forwardedOrigin({ origin: "http://127.0.0.1:5174", host: "127.0.0.1:5174" })).toBe("http://127.0.0.1:18000");
});

it("forwards any other page's socket origin unchanged for the backend to refuse", () => {
  expect(forwardedOrigin({ origin: "https://attacker.example", host: "localhost:5173" })).toBe("https://attacker.example");
  expect(forwardedOrigin({ origin: "http://acme.example:5173", host: "acme.example:5173" })).toBe("http://acme.example:5173");
  expect(forwardedOrigin({ host: "localhost:5173" })).toBeUndefined();
});
