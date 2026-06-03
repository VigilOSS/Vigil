import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import { rename } from "fs/promises";
import { resolve } from "path";

// renameOutput renames the singlefile build product from dist/index.html to
// dist/template.html so the backend export endpoint has a stable filename to
// load and inject into. Ported from the reference-project static-reports vite config.
// The retry loop covers the small race where vite-plugin-singlefile is still
// flushing the inlined HTML when our post-bundle hook fires.
function renameOutput(from: string, to: string): Plugin {
  return {
    name: "rename-output",
    enforce: "post",
    closeBundle: async () => {
      for (let i = 0; i < 10; i++) {
        try {
          await rename(from, to);
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
      throw new Error(`Failed to rename ${from} -> ${to} after 10 attempts`);
    },
  };
}

// Single-file, fully offline report template. Unlike the reference-project reference we
// do NOT externalize react/recharts/ag-grid in rollupOptions — the output must
// be self-contained (every byte of JS + CSS inlined) so it opens with no
// network access on an air-gapped review machine.
export default defineConfig({
  plugins: [
    react(),
    viteSingleFile(),
    renameOutput(
      resolve(__dirname, "dist/index.html"),
      resolve(__dirname, "dist/template.html"),
    ),
  ],
  build: {
    target: "esnext",
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
    minify: true,
  },
});
