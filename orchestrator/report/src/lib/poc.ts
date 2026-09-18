// Copy-and-run rendering for a finding's recorded HTTP proof of concept.
//
// `details.poc_request` / `details.poc_response` reach the report as structured
// objects (see agent/schemas/finding-record.schema.json), not as text. That is
// what lets this module SYNTHESIZE the reproduction rather than transcribe it,
// and synthesis is the only way to guarantee the one property that matters: a
// reader selects the block, pastes it into a terminal, and it runs. Nothing in
// the emitted string has to be stripped by hand — no `$ ` prompt, no step
// numbers, no line numbers, no typographic quotes. The prompt character belongs
// in CSS if it belongs anywhere; it never belongs in the text.
//
// Shell quoting is the load-bearing detail, not a nicety. A proof-of-concept URL
// routinely carries the very character that would end a shell string
// (`?q=test' AND 1=1-- -`), and payload bodies carry `$`, backticks, `&`, `;`
// and newlines. Every attacker-controlled value therefore goes through
// `shellQuote`, which is POSIX single-quoting: inside single quotes the shell
// expands nothing at all, so the only case to handle is the quote itself.

export interface PocRequest {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface PocResponse {
  status?: number;
  headers?: Record<string, string>;
  body_excerpt?: string;
}

/** POSIX single-quote a value so the shell reproduces it byte for byte. */
export function shellQuote(value: string): string {
  // Close the quote, emit an escaped literal quote, reopen. This is the only
  // escape POSIX single-quoting needs: nothing else is special inside them.
  return `'${value.split("'").join(`'\\''`)}'`;
}

function asRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  for (const [name, raw] of Object.entries(value as Record<string, unknown>)) {
    // The name is NOT trimmed: a header name with surrounding whitespace is a
    // parser-differential probe, and normalizing it here would reproduce a
    // different request than the one that found the bug.
    if (!name.trim()) continue;
    if (typeof raw === "string") {
      out[name] = raw;
    } else if (typeof raw === "number" || typeof raw === "boolean") {
      // Lossless: these stringify to exactly the bytes that went on the wire.
      out[name] = String(raw);
    }
    // Anything else (object, array, null) is schema-invalid and has no faithful
    // string form. `String({})` yields "[object Object]", which is a header
    // value the target never saw — the command would still run, and would
    // reproduce the wrong request without the reader being able to tell. An
    // absent header is at least visibly absent.
  }
  return out;
}

/** Narrow a loosely-typed payload value to a PocRequest, or null. */
export function asPocRequest(value: unknown): PocRequest | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  // Whitespace decides only whether the field is PRESENT; it is never stripped
  // from the value. `String.prototype.trim` removes U+00A0 among others, so a
  // URL ending in a non-breaking space — exactly what a parser-differential
  // finding turns on — was in the payload, absent from the DOM, and absent from
  // the clipboard. The synthesized command then reproduced a different request
  // than the one recorded.
  const url = typeof raw.url === "string" ? raw.url : "";
  if (!url.trim()) return null;
  return {
    method: typeof raw.method === "string" ? raw.method : "",
    url,
    headers: asRecord(raw.headers),
    body: typeof raw.body === "string" ? raw.body : "",
  };
}

/** Narrow a loosely-typed payload value to a PocResponse, or null. */
export function asPocResponse(value: unknown): PocResponse | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const status = typeof raw.status === "number" && Number.isFinite(raw.status) ? raw.status : undefined;
  const headers = asRecord(raw.headers);
  const body = typeof raw.body_excerpt === "string" ? raw.body_excerpt : "";
  if (status === undefined && Object.keys(headers).length === 0 && !body.trim()) return null;
  return { status, headers, body_excerpt: body };
}

/**
 * Render the recorded request as a runnable `curl` invocation.
 *
 * EVERY interpolated value is shell-quoted, the method included. `method` is
 * recorded from target-influenced traffic and is literally the payload on
 * verb-tampering, `X-HTTP-Method-Override` and WebDAV findings; the schema types
 * it as a bare string with no enum. Left bare here, `GET; touch /tmp/pwn` split
 * the command at the `;` and ran, and `>` needs no command name at all, so it
 * fired on every platform while silently eating curl's output into an
 * attacker-named file. Upper-casing is not a mitigation — `>`, `;`, `|`, `&&`,
 * `$()` and backticks are not letters, and on a case-insensitive filesystem
 * `TOUCH` still resolves to `/usr/bin/touch`. See: ADR 0018.
 *
 * The method is always explicit. Inferring it (curl's own "a body means POST"
 * rule) would silently rewrite a recorded `GET`-with-body into a `POST`, and a
 * reproduction that sends a different request than the one that found the bug is
 * worse than no reproduction. Headers are emitted verbatim and unfiltered for
 * the same reason — a deliberately hostile `Host:` or `X-Forwarded-For:` IS the
 * finding on a routing-trust bug, so this never second-guesses what the author
 * recorded.
 *
 * Long invocations break across lines with explicit `\` continuations rather
 * than relying on the browser to soft-wrap them: a soft wrap is invisible in the
 * copied string, so a reader who trusts their eyes cannot tell a wrapped flag
 * from two flags. A backslash continuation is in the text, survives the copy,
 * and pastes into any POSIX shell.
 */
export function pocCurl(request: PocRequest | null | undefined): string {
  const url = request?.url ?? "";
  if (!url.trim()) return "";
  // Recorded case is preserved, not normalized: a mixed-case verb is itself the
  // probe on a case-sensitive-routing finding.
  const recordedMethod = request?.method ?? "";
  const method = recordedMethod.trim() ? recordedMethod : "GET";
  const headers = request?.headers ?? {};
  const body = request?.body ?? "";

  // -i shows the response headers (the status line is usually the proof) and
  // -sS keeps curl quiet except for real errors.
  const head = `curl -i -sS -X ${shellQuote(method)} ${shellQuote(url)}`;
  const flags: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    flags.push(`-H ${shellQuote(`${name}: ${value}`)}`);
  }
  if (body) flags.push(`--data-raw ${shellQuote(body)}`);
  if (flags.length === 0) return head;
  return [head, ...flags].join(" \\\n  ");
}

/**
 * Render the recorded response as a wire-shaped evidence block.
 *
 * `HTTP <status>` rather than `HTTP/1.1 <status> OK`: the record stores a status
 * code and nothing else, so a full status line would be invented detail. Headers
 * and body stay separated by the blank line the HTTP grammar puts there, so a
 * reader never has to split them by hand.
 */
export function pocResponseText(response: PocResponse | null | undefined): string {
  if (!response) return "";
  const lines: string[] = [];
  if (response.status !== undefined) lines.push(`HTTP ${response.status}`);
  for (const [name, value] of Object.entries(response.headers ?? {})) {
    lines.push(`${name}: ${value}`);
  }
  const body = (response.body_excerpt ?? "").replace(/\s+$/, "");
  if (body) {
    if (lines.length > 0) lines.push("");
    lines.push(body);
  }
  return lines.join("\n");
}
