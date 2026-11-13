---
name: request-smuggling
description: Test for HTTP request smuggling via Content-Length and Transfer-Encoding desync
origin: Vigil
vuln_class: request-smuggling
---

# HTTP Request Smuggling Testing

## When to Activate

- Two or more HTTP parsers sit in the request path (CDN, load balancer, WAF, reverse proxy, app
  server), especially HTTP/2 at the edge downgraded to HTTP/1.1 upstream.

`--technique REQUEST-SMUGGLING`. curl normalises framing, so ambiguous CL/TE requests need
byte-exact control: a raw-socket (`ssl` + `socket`) or HTTP/2 client script run through
`vigil assess kali exec --technique REQUEST-SMUGGLING --intent "<purpose>" --probe-kind payload
--phase consume-test --timeout 60 -- python3 <script>` (`agent/skills/write-probe-script/SKILL.md`).
CL.TE and TE.CL detection shapes, TE.TE obfuscations, and HTTP/2 downgrade, H2.CL and H2.TE:
`agent/references/payloads/request-smuggling-payloads.md`.

## Safety

A desync on a shared front-end can attach your prefix to the next real user's request. Timing
probes leave no poisoned prefix and need no approval. Anything that sends a smuggled prefix —
prefix-based confirmation included, even on your own connection pair — and cache poisoning or
request capture can reach real users, so each needs operator approval first
(`agent/shared-constraints.md` §1); capturing other users' requests also exceeds proof
(`agent/shared-constraints.md` §4).

## Method

1. **Detect by timing.** A length/framing mismatch makes the back-end wait for bytes that never
   come: one variant hangs past the timeout (> 5 s against a measured baseline) while its control
   returns at once. Repeat it.
2. **Triage variants deterministically.** Record status, length and timing per variant into JSONL
   and rank with `vigil assess anomaly-score variant_responses.jsonl --top 5`; the outlier names
   the obfuscation that breaks the aligned baseline. A flat ranking means aligned for that
   technique; move to the next family.
3. **Families to cover:** CL.TE, TE.CL, TE.TE obfuscations (`Transfer-Encoding : chunked`,
   `xchunked`, tabs, duplicates, mixed case, line folding), H2.CL, H2.TE, CR/LF in HTTP/2 header values and pseudo-headers,
   H2 request tunnelling, CL.0 (back-end ignores `Content-Length` on some endpoints), pause-based
   desync, and client-side (browser-powered) desync where the server itself mis-frames.
4. **Confirm the prefix once approved** (Safety), on a connection pair you own: two connections
   from your client back to back, the second receiving the response to your smuggled prefix,
   against a cache-busted or unique path to keep the window for a real user's request small. A callback from "someone else's"
   request is not proof: crawlers, CDN prefetchers and scanners produce those too.
5. **Exploit only with approval:** reaching a front-end-blocked path (`/admin`, internal-only
   routes), front-end-injected header rewriting (`X-Forwarded-For`, auth headers), cache
   poisoning (`agent/skills/cache-poisoning/SKILL.md`), and reflected-XSS delivery via the
   smuggled response.

## What to Record

Front-end/back-end chain, the smuggling type and obfuscation, the exact request bytes, the timing
evidence, and the outcome (`agent/rules/hunting.md` §2). A timing-only desync is a real primitive;
record it with the approved exploitation step as the next test. Severity:
`agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- A single server with no proxy, or HTTP/2 end-to-end with no downgrade (H2-specific families
  only), rules out classic smuggling. Every family failing → aligned; record the negative with its
  run ids (`agent/rules/hunting.md` §13).
- One confirmed variant is a reason to check sibling hosts behind the same front-end
  (`agent/rules/hunting.md` §6).
- Escalate when CL and TE framing of the same body behave differently, an obfuscated TE header
  changes behaviour, or the edge terminates HTTP/2 and downgrades.
