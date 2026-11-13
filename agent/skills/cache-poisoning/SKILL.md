---
name: cache-poisoning
description: Test for web cache poisoning and web cache deception — unkeyed headers and cookies, fat GET, path normalisation, Vary abuse, CDN-specific behaviour, cache-poisoned denial of service, and redirect poisoning
origin: Vigil
vuln_class: cache-poisoning
---

# Cache Poisoning Testing

## When to Activate

- A CDN, reverse proxy or cache sits in front (Cloudflare, Akamai, Fastly, Varnish, Nginx):
  `X-Cache`, `Age`, `CF-Cache-Status`, `Via`, `Vary` or vendor headers in responses.

`--technique CACHE-POISONING` (`REQUEST-SMUGGLING` when the poison rides a smuggled request,
`agent/skills/request-smuggling/SKILL.md`). Probes run through `vigil assess kali exec` or, for a
header or cookie list, `vigil assess kali sweep` (one audited run per value, clustered by response
signature).

## Cache-buster discipline

Every probe carries a unique cache buster (`?cb=<random>`) so it hits the origin and poisons only a
key nobody else requests. Poisoning a real, shared cache entry (dropping the buster) serves your
content to real users: it needs operator approval (`agent/shared-constraints.md` §1) and is not
needed for proof.

## Method

1. **Map the key:** send the same busted request twice (`HIT` or `Age > 0` on the second), then
   vary path, query, Host and the headers named in `Vary`. Vendor key disclosure: Akamai
   `Pragma: akamai-x-get-cache-key` (and `X-Akamai-Staging`), `Fastly-Debug: 1`; Cloudflare
   `cf-cache-status` and cache-everything rules; Varnish `X-Varnish`; Nginx `proxy_cache_key` and
   `X-Accel-Redirect`.
2. **Find unkeyed inputs** with one busted request per candidate header, body intact:
   ```bash
   vigil assess kali sweep --technique CACHE-POISONING --intent "unkeyed header discovery" \
     --probe-kind payload --phase consume-test --timeout 30 --values-file headers.txt \
     -- bash -c 'curl -s -i -H "{}" "https://target.example/?cb=$(openssl rand -hex 4)"'
   ```
   (`headers.txt`: `X-Forwarded-Host: canary.example`, `X-Forwarded-Scheme: http`,
   `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-Port: 1`,
   `X-Host: canary.example`, …). The cluster that breaks from the baseline names the header;
   confirm the value is reflected in the body (links, redirects, meta tags, scripts). Cookies are
   keyed only under `Vary: Cookie`.
3. **Other primitives:** fat GET (a GET body the cache ignores and the origin reads); CR/LF in
   cached headers (`agent/skills/crlf-injection/SKILL.md`); `Vary` headers that leave other
   inputs unkeyed (`Vary: *` handling); redirect poisoning via `X-Forwarded-Scheme`/`-Host`.
4. **Web cache deception:** a static-looking suffix or delimiter the cache treats as static and
   the origin ignores (`/account.css`, `/account/x.js`, `/account;.css`, encoded `..%2f`
   normalisation differences) makes the cache store an authenticated page. Proof is the
   victim-shaped page served to your unauthenticated second client.
5. **Cache-poisoned DoS** (HTTP header oversize, meta-characters, method override) caches an
   error page: test only on a busted key, and only with approval for anything beyond it.

## Proof

Cross-user proof is a clean second request **without** the injected input, from a separate
client, against the same busted key, receiving the poisoned body or `Location`. A callback from a
poisoned redirect only shows that something followed it (your own clean fetch, a crawler or a
prefetcher); it adds attribution, not cross-user proof
(`agent/references/offensive-tactics/frp-tunneling.md` "What a callback proves").

## What to Record

Cache layer, the unkeyed input and the sweep cluster that isolated it, the poisoning request, the
clean second request and its poisoned response, and what a victim receives
(`agent/rules/hunting.md` §2: script execution, a redirect to an attacker origin, another user's
data served from cache). Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.
