import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const verifier = new URL("./verify-built-report.mjs", import.meta.url);
const shell = (body) => `<!doctype html><html><head><style>body{color:black}</style></head>
<body><div id="root"></div><script>const data="__VIGIL_REPORT_DATA__"</script>${body}</body></html>`;

async function verify(html) {
  const dist = await mkdtemp(join(tmpdir(), "vigil-report-verifier-"));
  await writeFile(join(dist, "template.html"), html, "utf8");
  const result = spawnSync(process.execPath, [verifier.pathname], {
    encoding: "utf8",
    env: { ...process.env, VIGIL_REPORT_DIST: dist },
  });
  await rm(dist, { recursive: true, force: true });
  return result;
}

for (const [name, resource] of [
  ["stylesheet with reversed attributes", '<link href="https://cdn.example/x.css" rel="stylesheet">'],
  ["protocol-relative CSS URL", "<style>.x{background:url(//cdn.example/x.png)}</style>"],
  ["iframe source", '<iframe src="https://cdn.example/frame"></iframe>'],
]) {
  test(`rejects ${name}`, async () => {
    const result = await verify(shell(resource));
    assert.notEqual(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stderr, /self-contained offline artifact/);
  });
}

test("accepts inline resources and inert links", async () => {
  const result = await verify(
    shell('<img src="data:image/png;base64,AA=="><a href="https://example.com">reference</a>'),
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test("does not treat JavaScript URL syntax as a CSS resource", async () => {
  const result = await verify(shell("<script>const value = 'url(https://target.example)'</script>"));
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
