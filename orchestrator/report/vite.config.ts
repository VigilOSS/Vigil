import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { rename } from "fs/promises";
import { resolve } from "path";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// The report has one HTML entry and must remain usable from file:// on an
// offline review machine. Keep this deliberately project-specific: every JS
// and CSS output is inlined, and any asset Vite cannot inline fails the build.
function inlineReportBundle(): Plugin {
  return {
    name: "inline-report-bundle",
    enforce: "post",
    generateBundle(_options, bundle) {
      const htmlFiles = Object.values(bundle).filter(
        (item) => item.type === "asset" && item.fileName.endsWith(".html"),
      );
      if (htmlFiles.length !== 1) {
        this.error(`Expected one report HTML entry, found ${htmlFiles.length}`);
      }

      const htmlAsset = htmlFiles[0];
      let html = String(htmlAsset.source);

      for (const item of Object.values(bundle)) {
        if (item.type === "chunk") {
          const escapedName = escapeRegExp(item.fileName);
          const script = new RegExp(
            `<script([^>]*?) src="(?:[^"]*?/)?${escapedName}"([^>]*)></script>`,
          );
          const safeCode = item.code.replace(/<(\/script|!--)/gi, "\\x3C$1").trim();
          const inlined = html.replace(
            script,
            (_match, beforeSrc: string, afterSrc: string) =>
              `<script${beforeSrc}${afterSrc}>${safeCode}</script>`,
          );
          if (inlined === html) {
            this.error(`Report HTML does not reference emitted script ${item.fileName}`);
          }
          html = inlined;
          delete bundle[item.fileName];
          continue;
        }

        if (item !== htmlAsset && item.fileName.endsWith(".css")) {
          const escapedName = escapeRegExp(item.fileName);
          const stylesheet = new RegExp(
            `<link([^>]*?) href="(?:[^"]*?/)?${escapedName}"([^>]*)>`,
          );
          const css = String(item.source).replace('@charset "UTF-8";', "").trim();
          const inlined = html.replace(
            stylesheet,
            (_match, beforeHref: string, afterHref: string) =>
              `<style${beforeHref}${afterHref}>${css}</style>`,
          );
          if (inlined === html) {
            this.error(`Report HTML does not reference emitted stylesheet ${item.fileName}`);
          }
          html = inlined;
          delete bundle[item.fileName];
        }
      }

      const remaining = Object.values(bundle).filter((item) => item !== htmlAsset);
      if (remaining.length > 0) {
        this.error(
          `Report build emitted non-inline assets: ${remaining.map((item) => item.fileName).join(", ")}`,
        );
      }
      htmlAsset.source = html;
    },
  };
}

// renameOutput renames the single-file build product from dist/index.html to
// dist/template.html so the backend export endpoint has a stable filename to
// load and inject into.
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

// Single-file, fully offline report template. Do not externalize
// react/recharts/ag-grid in rollupOptions — the output must
// be self-contained (every byte of JS + CSS inlined) so it opens with no
// network access on an air-gapped review machine.
export default defineConfig({
  plugins: [
    react(),
    inlineReportBundle(),
    renameOutput(
      resolve(__dirname, "dist/index.html"),
      resolve(__dirname, "dist/template.html"),
    ),
  ],
  build: {
    target: "esnext",
    assetsInlineLimit: 100000000,
    assetsDir: "",
    cssCodeSplit: false,
    chunkSizeWarningLimit: 100000000,
    minify: true,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  base: "./",
});
