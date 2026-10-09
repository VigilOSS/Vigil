import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const dist = process.env.VIGIL_REPORT_DIST
  ? resolve(process.env.VIGIL_REPORT_DIST)
  : resolve(import.meta.dirname, "../dist");
const outputs = (await readdir(dist)).sort();
if (outputs.length !== 1 || outputs[0] !== "template.html") {
  throw new Error(`report build must emit only dist/template.html; found: ${outputs.join(", ")}`);
}

const html = await readFile(resolve(dist, "template.html"), "utf8");
const failures = [];
const injectionTarget = '"__VIGIL_REPORT_DATA__"</script>';
if (html.split(injectionTarget).length - 1 !== 1) {
  failures.push("report-data injection target does not occur exactly once");
}
if (!/<script\b[^>]*>[^<]+<\/script>/is.test(html)) {
  failures.push("missing inline JavaScript");
}
if (!/<style\b[^>]*>[^<]+<\/style>/is.test(html)) {
  failures.push("missing inline CSS");
}

const resourceTags = /<(script|link|img|source|iframe|object|embed|video|audio|track|input)\b([^>]*)>/gi;
const resourceAttrs = /\b(src|href|data|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
for (const tagMatch of html.matchAll(resourceTags)) {
  const tag = tagMatch[1].toLowerCase();
  for (const attrMatch of tagMatch[2].matchAll(resourceAttrs)) {
    const attribute = attrMatch[1].toLowerCase();
    const value = attrMatch[2] ?? attrMatch[3] ?? attrMatch[4] ?? "";
    const inlineImage = ["img", "source"].includes(tag) && attribute === "src" && value.startsWith("data:");
    if (!inlineImage) failures.push(`${tag} ${attribute} resource reference`);
  }
}
if (/<meta\b[^>]*\bhttp-equiv\s*=\s*["']?refresh\b/i.test(html)) {
  failures.push("meta refresh reference");
}
if (/@import\b/i.test(html)) failures.push("CSS import");
for (const styleMatch of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
  for (const match of styleMatch[1].matchAll(/url\(\s*["']?([^"')\s]+)["']?\s*\)/gi)) {
    const value = match[1];
    if (!value.startsWith("data:") && !value.startsWith("#")) {
      failures.push("CSS resource reference");
    }
  }
}
if (!/<div id="root"><\/div>/.test(html)) {
  failures.push("missing React mount point");
}

if (failures.length > 0) {
  throw new Error(`report is not a self-contained offline artifact: ${failures.join(", ")}`);
}
