/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const BACKEND = "127.0.0.1:18000";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// The backend accepts live-update sockets only from its own UI origin. A socket
// opened by this dev server's own page carries the dev origin, so present the
// backend's; any other page's origin passes through for the backend to refuse.
function devPageOrigin(origin: string | undefined, host: string | undefined): boolean {
  if (!origin || !host) return false;
  try {
    const url = new URL(origin);
    return url.protocol === "http:" && url.host === host && LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

export default defineConfig({
  base: "./",
  plugins: [react()],
  test: {
    // Safety net for loaded machines (src/testSetup.ts raises the
    // testing-library wait to match); tests do not rely on it.
    testTimeout: 15_000,
    setupFiles: ["./src/testSetup.ts"],
  },
  server: {
    proxy: {
      "/dashboard": `http://${BACKEND}`,
      "/engagements": `http://${BACKEND}`,
      "/artifacts": `http://${BACKEND}`,
      "/ws": {
        target: `ws://${BACKEND}`,
        ws: true,
        configure: (proxy) => {
          proxy.on("proxyReqWs", (proxyReq, req) => {
            if (devPageOrigin(req.headers.origin, req.headers.host)) {
              proxyReq.setHeader("origin", `http://${BACKEND}`);
            }
          });
        },
      },
    },
  },
});
