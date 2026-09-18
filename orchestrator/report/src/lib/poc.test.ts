// Regression cover for the one string in this package that a reader is
// expected to execute.
//
// The report renders a `curl` invocation built from `details.poc_request`, and a
// finding's URL, headers and body are attacker-influenced by construction — they
// are what the target reflected back. If the quoting were wrong, a PoC URL
// carrying `$(...)` or a backtick would run on the machine of whoever pasted the
// block, which turns a delivered report into code execution against its own
// reader (the untrusted-target-text boundary, ADR 0018). So these assertions do
// not inspect the string: they hand it to a real `bash` and compare the argv the
// shell produces against the values that went in.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { asPocRequest, asPocResponse, pocCurl, pocResponseText, shellQuote } from "./poc";

/** Run `command` under bash with `curl` stubbed, and return the argv it saw. */
function argvFromShell(command: string): string[] {
  const script = `curl() { for a in "$@"; do printf '%s\\0' "$a"; done; }\n${command}`;
  const out = execFileSync("bash", ["-c", script], { encoding: "utf8" });
  return out.split("\0").slice(0, -1);
}

test("shellQuote survives a round trip through a real shell", () => {
  const hostile = [
    "plain",
    "with 'single' quotes",
    'with "double" quotes',
    "$(id) and `whoami`",
    "semi;colon && ampersand | pipe",
    "new\nline\ttab",
    "back\\slash",
    "*glob* ?and? [brackets]",
    "~tilde $HOME ${BRACE}",
    "",
  ];
  for (const value of hostile) {
    const out = execFileSync("bash", ["-c", `printf '%s' ${shellQuote(value)}`], {
      encoding: "utf8",
    });
    assert.equal(out, value, `shell mangled ${JSON.stringify(value)}`);
  }
});

test("a SQL-injection PoC pastes as the exact request that was recorded", () => {
  const url = "https://target.example/api?role=' OR 1=1-- -&x=$(id)&y=`whoami`;echo pwned";
  const curl = pocCurl(
    asPocRequest({
      method: "GET",
      url,
      headers: { Accept: "application/json", "X-Canary": 'a\'b"c$d`e' },
      body: "",
    }),
  );
  assert.deepEqual(argvFromShell(curl), [
    "-i",
    "-sS",
    "-X",
    // Never inferred from the body, and never re-cased.
    "GET",
    url,
    "-H",
    "Accept: application/json",
    "-H",
    'X-Canary: a\'b"c$d`e',
  ]);
});

test("a POST body reaches curl byte for byte", () => {
  const body = "payload='\"$(id)`whoami`&next=/admin;rm -rf /tmp/nothing";
  const curl = pocCurl(
    asPocRequest({
      method: "POST",
      url: "https://target.example/login",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    }),
  );
  const argv = argvFromShell(curl);
  assert.equal(argv[argv.indexOf("--data-raw") + 1], body);
  assert.equal(argv[argv.indexOf("-X") + 1], "POST");
});

test("the method is shell-quoted like every other recorded value", () => {
  // `method` is recorded from target-influenced traffic and IS the payload on a
  // verb-tampering or X-HTTP-Method-Override finding. Left unquoted, each of
  // these escaped the command: `;` and `&&` chained a second command, `$()` and
  // backticks substituted one, and `>` needed no command name at all.
  const hostile = [
    "GET; touch CANARY",
    "GET && touch CANARY",
    "GET | tee CANARY",
    "GET > CANARY",
    "GET $(touch CANARY)",
    "GET `touch CANARY`",
    "GET 'quoted'",
    "gEt",
  ];
  for (const method of hostile) {
    const curl = pocCurl(asPocRequest({ method, url: "https://target.example/k" }));
    assert.deepEqual(
      argvFromShell(curl),
      ["-i", "-sS", "-X", method, "https://target.example/k"],
      `method escaped the command: ${JSON.stringify(method)}`,
    );
  }
});

test("a hostile method creates no file and runs no command", () => {
  // The assertion above proves the argv; this proves the side effects, because
  // a shim that records argv cannot notice a command that ran BESIDE it.
  const dir = mkdtempSync(join(tmpdir(), "vigil-poc-canary-"));
  try {
    const canary = join(dir, "pwned");
    for (const method of [
      `GET; touch ${canary}`,
      `GET > ${canary}`,
      `GET $(touch ${canary})`,
      `GET \`touch ${canary}\``,
      `GET && touch ${canary}`,
    ]) {
      const curl = pocCurl(asPocRequest({ method, url: "https://target.example/k" }));
      argvFromShell(curl);
      assert.ok(!existsSync(canary), `command substitution fired for ${JSON.stringify(method)}`);
    }
    assert.deepEqual(readdirSync(dir), [], "the pasted command wrote to disk");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("whitespace decides presence but is never stripped from a value", () => {
  // `String.prototype.trim` removes U+00A0. A URL ending in a non-breaking space
  // is exactly what a parser-differential finding turns on, and trimming it made
  // the command reproduce a different request than the one recorded.
  for (const url of [
    "https://target.example/k\u00a0",
    "https://target.example/k ",
    " https://target.example/k",
    "https://target.example/a b",
    "https://target.example/k\t",
  ]) {
    const argv = argvFromShell(pocCurl(asPocRequest({ url })));
    assert.equal(argv[argv.length - 1], url, `url was rewritten: ${JSON.stringify(url)}`);
  }
  // Recorded case and spacing on the verb survive too.
  const argv = argvFromShell(pocCurl(asPocRequest({ method: " gEt ", url: "https://t.example/k" })));
  assert.equal(argv[argv.indexOf("-X") + 1], " gEt ");
  // Whitespace-only still reads as absent.
  assert.equal(asPocRequest({ url: "  \n " }), null);
  const defaulted = argvFromShell(pocCurl(asPocRequest({ method: "   ", url: "https://t.example/k" })));
  assert.equal(defaulted[defaulted.indexOf("-X") + 1], "GET");
});

test("a header value with no faithful string form is omitted, not corrupted", () => {
  const curl = pocCurl(
    asPocRequest({
      url: "https://target.example/k",
      headers: { "X-Str": "a", "X-Num": 1, "X-Bool": true, "X-Obj": {}, "X-Arr": [1], "X-Null": null },
    }),
  );
  const argv = argvFromShell(curl);
  const headers = argv.filter((_, i) => argv[i - 1] === "-H");
  // `String({})` is "[object Object]" — a value the target never saw, in a
  // command that would still run and reproduce the wrong request.
  assert.deepEqual(headers, ["X-Str: a", "X-Num: 1", "X-Bool: true"]);
});

test("a header name keeps the whitespace it was recorded with", () => {
  const curl = pocCurl(
    asPocRequest({ url: "https://target.example/k", headers: { " X-Smuggle": "1" } }),
  );
  const argv = argvFromShell(curl);
  assert.equal(argv[argv.indexOf("-H") + 1], " X-Smuggle: 1");
});

test("a recorded GET with a body stays a GET", () => {
  // curl's own rule is that a body implies POST. Letting that happen would send
  // a different request than the one that found the bug.
  const curl = pocCurl(
    asPocRequest({ method: "GET", url: "https://target.example/x", body: "a=1" }),
  );
  const argv = argvFromShell(curl);
  assert.equal(argv[argv.indexOf("-X") + 1], "GET");
  assert.equal(argv[argv.indexOf("--data-raw") + 1], "a=1");
});

test("the emitted command carries nothing a reader must strip by hand", () => {
  const curl = pocCurl(
    asPocRequest({
      method: "POST",
      url: "https://target.example/a?b=c",
      headers: { A: "1", B: "2" },
      body: "x=1",
    }),
  );
  for (const line of curl.split("\n")) {
    assert.ok(!/^\s*[$#>]\s/.test(line), `prompt character in ${JSON.stringify(line)}`);
    assert.ok(!/^\s*\d+[.)]\s/.test(line), `step number in ${JSON.stringify(line)}`);
  }
  assert.ok(
    !/[‘’“”–— ​]/.test(curl),
    "typographic substitution would break the paste",
  );
  // Continuations are explicit, so a copied line is a whole line.
  assert.ok(curl.includes(" \\\n  "));
});

test("an unusable poc_request yields no command rather than a broken one", () => {
  assert.equal(pocCurl(asPocRequest(undefined)), "");
  assert.equal(pocCurl(asPocRequest(null)), "");
  assert.equal(pocCurl(asPocRequest("GET /x")), "");
  assert.equal(pocCurl(asPocRequest([])), "");
  assert.equal(pocCurl(asPocRequest({ method: "GET" })), "");
  assert.equal(pocCurl(asPocRequest({ url: "   " })), "");
});

test("a request with only a url is still a complete command", () => {
  const curl = pocCurl(asPocRequest({ url: "https://target.example/x" }));
  assert.equal(curl, "curl -i -sS -X 'GET' 'https://target.example/x'");
  assert.deepEqual(argvFromShell(curl), ["-i", "-sS", "-X", "GET", "https://target.example/x"]);
});

test("the response block separates headers from body the way HTTP does", () => {
  const text = pocResponseText(
    asPocResponse({
      status: 200,
      headers: { "Content-Type": "application/json" },
      body_excerpt: '{"ok":true}\n\n',
    }),
  );
  assert.equal(text, 'HTTP 200\nContent-Type: application/json\n\n{"ok":true}');
});

test("an empty response projection renders nothing", () => {
  assert.equal(asPocResponse({}), null);
  assert.equal(asPocResponse({ headers: {}, body_excerpt: "  " }), null);
  assert.equal(pocResponseText(null), "");
});

test("a status-only response still renders", () => {
  assert.equal(pocResponseText(asPocResponse({ status: 500 })), "HTTP 500");
});
