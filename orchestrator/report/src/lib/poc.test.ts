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
//
// Argv is not the whole boundary, though. curl SYNTHESIZES request headers the
// caller never asked for, so an argv that carries exactly the recorded headers
// can still put `Content-Type`, `User-Agent` and `Accept` on the wire. The
// `wireFor` tests below therefore run a real `curl` against a real socket and
// assert the bytes the target would actually receive.

import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
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

/**
 * Run the synthesized command against a local socket and return the raw request.
 *
 * `build` receives the loopback URL to record in the PoC, so the command under
 * test is the real product of `pocCurl` and the bytes asserted on are the ones a
 * target would see. Nothing is stubbed: a header curl adds behind the tool's
 * back shows up here and nowhere else.
 */
async function wireFor(build: (url: string) => string): Promise<string> {
  const chunks: Buffer[] = [];
  const server = createServer((socket) => {
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      // Answer only once the whole request is in, body included: replying while
      // curl is still uploading makes curl exit with a write error instead of
      // completing the request under test.
      const buf = Buffer.concat(chunks);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep < 0) return;
      const head = buf.subarray(0, sep).toString("latin1");
      const declared = /\r\ncontent-length:[ \t]*(\d+)/i.exec(head);
      const need = declared ? Number(declared[1]) : 0;
      if (buf.length - (sep + 4) < need) return;
      socket.end("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const command = build(`http://127.0.0.1:${port}/probe`);
  try {
    await new Promise<void>((resolve, reject) => {
      execFile("bash", ["-c", command], { timeout: 20_000 }, (err) =>
        err ? reject(err) : resolve(),
      );
    });
  } finally {
    server.close();
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** The header lines of a captured request, in wire order, names untouched. */
function wireHeaders(raw: string): string[] {
  const head = raw.split("\r\n\r\n")[0] ?? "";
  return head.split("\r\n").slice(1);
}

/**
 * Header names curl derives rather than invents.
 *
 * `Host` comes from the URL and `Content-Length` from the body, so both
 * reproduce the recorded request. Every OTHER header curl puts on the wire
 * unbidden is a header the recorded request did not send.
 */
function inventedHeaders(raw: string, recorded: string[]): string[] {
  const derived = new Set(["host", "content-length"]);
  const asked = new Set(recorded.map((line) => line.toLowerCase()));
  return wireHeaders(raw).filter((line) => {
    const name = line.slice(0, line.indexOf(":")).trim().toLowerCase();
    return !derived.has(name) && !asked.has(line.toLowerCase());
  });
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
    // Accept was recorded, so only curl's other default is removed.
    "-H",
    "User-Agent:",
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
      ["-i", "-sS", "-X", method, "https://target.example/k", "-H", "User-Agent:", "-H", "Accept:"],
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
    // argv is [-i, -sS, -X, <method>, <url>, ...flags].
    assert.equal(argv[4], url, `url was rewritten: ${JSON.stringify(url)}`);
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
  assert.deepEqual(headers, ["X-Str: a", "X-Num: 1", "X-Bool: true", "User-Agent:", "Accept:"]);
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
  assert.equal(
    curl,
    "curl -i -sS -X 'GET' 'https://target.example/x' \\\n  -H 'User-Agent:' \\\n  -H 'Accept:'",
  );
  assert.deepEqual(argvFromShell(curl), [
    "-i",
    "-sS",
    "-X",
    "GET",
    "https://target.example/x",
    "-H",
    "User-Agent:",
    "-H",
    "Accept:",
  ]);
});

test("a recorded GET with a body reaches the wire without an invented Content-Type", async () => {
  // The finding: `--data-raw` makes curl synthesize
  // `Content-Type: application/x-www-form-urlencoded`, and curl adds `Accept`
  // and `User-Agent` besides. A GET-with-body parser differential turns on
  // exactly which of those the server sees, so the pasted command reached a
  // different parser than the request that produced the finding.
  const raw = await wireFor((url) =>
    pocCurl(asPocRequest({ method: "GET", url, body: "a=1" })),
  );
  assert.match(raw, /^GET \/probe HTTP\/1\.1\r\n/);
  assert.deepEqual(inventedHeaders(raw, []), []);
  assert.ok(raw.endsWith("\r\n\r\na=1"), `body was not sent verbatim: ${JSON.stringify(raw)}`);
});

test("a request with no recorded headers sends no headers curl made up", async () => {
  const raw = await wireFor((url) => pocCurl(asPocRequest({ url })));
  // Anchor the negative: `inventedHeaders` returning [] is also what a request
  // that never reached the socket looks like. `Host` is the one header curl
  // DERIVES rather than invents (see CURL_SYNTHESIZED_HEADERS), so its presence
  // proves a real request arrived and the emptiness above means something.
  assert.ok(
    wireHeaders(raw).some((line) => /^host:/i.test(line)),
    `no request reached the socket: ${JSON.stringify(raw)}`,
  );
  assert.deepEqual(inventedHeaders(raw, []), []);
});

test("recorded headers are sent, and only the unrecorded defaults are suppressed", async () => {
  const recorded = ["Accept: application/json", "X-Canary: 1"];
  const raw = await wireFor((url) =>
    pocCurl(
      asPocRequest({
        method: "POST",
        url,
        headers: { Accept: "application/json", "X-Canary": "1" },
        body: "q=1",
      }),
    ),
  );
  // Nothing beyond what was recorded (plus Host/Content-Length) — and the
  // recorded Accept is not suppressed along with curl's.
  assert.deepEqual(inventedHeaders(raw, recorded), []);
  const accepts = wireHeaders(raw).filter((line) => /^accept:/i.test(line));
  assert.deepEqual(accepts, ["Accept: application/json"]);
});

test("a recorded Content-Type survives, cased however it was recorded", async () => {
  const raw = await wireFor((url) =>
    pocCurl(
      asPocRequest({
        method: "POST",
        url,
        // A lowercase name replaces curl's default; suppressing it too would
        // delete the recorded header.
        headers: { "content-type": "application/json" },
        body: '{"a":1}',
      }),
    ),
  );
  assert.deepEqual(inventedHeaders(raw, ["content-type: application/json"]), []);
  const types = wireHeaders(raw).filter((line) => /^content-type:/i.test(line));
  assert.deepEqual(types, ["content-type: application/json"]);
});

test("a header name recorded with padding still displaces curl's own default", async () => {
  // ` User-Agent` with a leading space is a request-smuggling probe, and curl
  // does NOT treat it as a replacement for its own `User-Agent` — it sends
  // both. The recorded probe has to go out and the default has to not.
  const raw = await wireFor((url) =>
    pocCurl(asPocRequest({ url, headers: { " User-Agent": "probe" } })),
  );
  assert.deepEqual(inventedHeaders(raw, [" User-Agent: probe"]), []);
  assert.ok(
    wireHeaders(raw).includes(" User-Agent: probe"),
    `the smuggling probe was dropped: ${JSON.stringify(wireHeaders(raw))}`,
  );
  assert.ok(
    !wireHeaders(raw).some((line) => /^User-Agent:/.test(line)),
    "curl's own User-Agent went out beside the recorded one",
  );
});

test("suppression uses curl's remove syntax, not its empty-value syntax", () => {
  // `-H 'Name:'` removes a header curl would otherwise send. `-H 'Name;'` is a
  // different feature: it SENDS `Name:` with an empty value, which is still a
  // header the target never saw.
  const argv = argvFromShell(pocCurl(asPocRequest({ url: "https://target.example/k" })));
  const headers = argv.filter((_, i) => argv[i - 1] === "-H");
  assert.deepEqual(headers, ["User-Agent:", "Accept:"]);
  // Content-Type is only synthesized when there is a body, so nothing is
  // suppressed for it here.
  const withBody = argvFromShell(
    pocCurl(asPocRequest({ url: "https://target.example/k", body: "a=1" })),
  );
  assert.deepEqual(
    withBody.filter((_, i) => withBody[i - 1] === "-H"),
    ["User-Agent:", "Accept:", "Content-Type:"],
  );
});

test("the response block separates headers from body the way HTTP does", () => {
  const text = pocResponseText(
    asPocResponse({
      status: 200,
      headers: { "Content-Type": "application/json" },
      body_excerpt: '{"ok":true}',
    }),
  );
  assert.equal(text, 'HTTP 200\nContent-Type: application/json\n\n{"ok":true}');
});

test("the recorded response body keeps its trailing bytes", () => {
  // Trailing whitespace IS the evidence on a whitespace-sensitive parser
  // differential — a body that ends in CRLFs, a trailing space before a
  // boundary, a response that is nothing but whitespace. Stripping it left the
  // report claiming a finding whose proof it had deleted, and the block below
  // is the only place a reader ever sees those bytes.
  for (const body of [
    '{"ok":true}\n\n',
    "trailing space ",
    "tab\t",
    "\r\n\r\n",
    "   ",
    "\n",
  ]) {
    const text = pocResponseText(asPocResponse({ status: 200, body_excerpt: body }));
    assert.equal(text, `HTTP 200\n\n${body}`, `body was rewritten: ${JSON.stringify(body)}`);
  }
  // With nothing else recorded, the body stands alone and is still verbatim.
  assert.equal(pocResponseText(asPocResponse({ body_excerpt: "  \n" })), "  \n");
});

test("an empty response projection renders nothing", () => {
  assert.equal(asPocResponse({}), null);
  assert.equal(asPocResponse({ headers: {}, body_excerpt: "" }), null);
  assert.equal(pocResponseText(null), "");
  // A whitespace-only body is a RECORDED body, not an absent one.
  assert.notEqual(asPocResponse({ headers: {}, body_excerpt: "  " }), null);
});

test("a status-only response still renders", () => {
  assert.equal(pocResponseText(asPocResponse({ status: 500 })), "HTTP 500");
});
