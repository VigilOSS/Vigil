---
name: gf-patterns:ssrf
description: URL-fetch parameter patterns that signal server-side request forgery surfaces
origin: 1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc (+ local overlay)
bucket: ssrf
skill: ssrf-testing
weight: 40
---

# gf: ssrf

## What this bucket classifies

Parameters and path fragments that hint the server takes an attacker-controlled URL and
fetches it server-side. These are the raw surfaces for SSRF against cloud metadata,
internal services, and cross-protocol smuggling (gopher/file/dict/ldap).

## Load this reference when

- The corpus contains at least one `url=`, `uri=`, `feed=`, or `window=` query key, or one of
  the curated `*_url`/`*_uri` server-fetch compounds below
- Path fragments `/proxy/` or `/fetch/` appear in crawl or historical data
- Operator is choosing between `ssrf` and `redirect` buckets and needs tie-breaking context

## Parameter keys that match

`url, uri, host, port, feed, window`

### Curated server-fetch compound family

Both `snake_case` and concatenated (camelCase-lowercased) forms of names that mean "a URL the
**server** fetches" (as opposed to `redirect`'s "a URL the **browser** follows"):

`fetch_url, fetchurl, proxy_url, proxyurl, remote_url, remoteurl, webhook_url, webhookurl,
feed_url, feedurl, dest_uri, desturi, target_uri, targeturi, request_uri, requesturi`

### Image/avatar-fetch compound family

"SSRF via avatar/profile-picture URL" (the server downloads a user-supplied image URL
server-side to resize/re-host it) is one of the most frequently reported bug-bounty SSRF
variants. The bare `image`/`photo`/`avatar` keys exist only
in `img_traversal` (local path traversal) and `upload_fields` (multipart upload), neither of
which carries server-fetch-a-remote-URL semantics:

`image_url, imageurl, avatar_url, avatarurl, photo_url, photourl, picture_url, pictureurl,
logo_url, logourl, thumbnail_url, thumbnailurl, icon_url, iconurl`

### Navigation keys

`redirect, callback, continue, next, link, dest` belong to `redirect`, not this bucket's key set.
`ssrf` can match a `/proxy/` or `/fetch/` request carrying those parameters through the path
fragments below, but not through the bare parameter key. See `redirect.md` for key matching.

## Path patterns that match

`/proxy/`, `/fetch/`

## Weight and priority interpretation

- Baseline priority score: 40 (tied with `sqli`/`lfi`/`auth`/`deserialization`/`dotnet_handler`/
  `xxe`; below `rce`(50) and `graphql`/`secret_vault`(45))
- Terminal reasons that suppress this bucket: `inert_type` (image/video/font/archive are skipped at ingest)

## Example URLs that match

- `https://target.example/api/fetch?url=http://evil.example` — ssrf via url=
- `https://target.example/proxy/anything?uri=gopher://internal:6379/_info` — protocol smuggling via proxy path
- `https://target.example/feed/load?feed=http://localhost:8500/v1/catalog/services` — Consul metadata via feed=
- `https://target.example/profile/upload?avatar_url=http://169.254.169.254/latest/meta-data/` —
  avatar-fetch SSRF against cloud metadata (co-fires `cloud_metadata` too, via the IMDS-address
  regex, independent of the param name)
- `https://target.example/integrations/register?webhook_url=http://internal-service:8080/admin` —
  webhook-registration SSRF against an internal service

## What it does NOT classify

- Pure client-side redirect logic where the fetch happens in the browser (those land in `redirect`)
- OAuth `redirect_uri` alone without server-side fetching (that is the `redirect` bucket's signal)
- Image/video/font URLs — the ingest path marks them `inert_type` before classification runs

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Server%20Side%20Request%20Forgery)

## Related

- `agent/skills/ssrf-testing/SKILL.md` — the follow-up test skill
- `agent/references/gf-patterns/redirect.md` — adjacent bucket (client-side redirect vs server-side fetch)
- `agent/references/payloads/ssrf-payloads.md` — payload library once a surface is confirmed
