/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

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
      "/dashboard": "http://127.0.0.1:18000",
      "/engagements": "http://127.0.0.1:18000",
      "/artifacts": "http://127.0.0.1:18000",
      "/ws": {
        target: "ws://127.0.0.1:18000",
        ws: true,
      },
    },
  },
});
