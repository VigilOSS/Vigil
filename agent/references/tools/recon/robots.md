---
description: Pre-crawl known-file fetch — robots.txt / sitemap.xml / .well-known/security.txt per host as a high-signal seed BEFORE the katana crawl. Scoped to the marginal pre-crawl fetch (katana -kf covers in-crawl known-files)
skill: surface-collection
---

# robots (pre-crawl known-file fetch)

`vigil assess kali robots` fetches each host's `/robots.txt`, `/sitemap.xml` and
`/.well-known/security.txt` before the katana crawl. `Disallow:` lines routinely name admin panels,
staging hosts and unlinked endpoints, and sitemaps list real URLs, so seeding them first lands the
crawl on real surface instead of finding it deep in the link graph (or missing it). Engine, inputs,
default `--paths`, and the `-mc` set that keeps a present-but-gated (401/403) file visible:
`vigil assess contract kali robots`. The engine is httpx, so the audit row's `tool_bin` is `httpx`
and the program attribution header rides every probe.

1. Run `kali robots -l <live_hosts>` right after `web-discovery` liveness. Add paths such as
   `/.well-known/openid-configuration` or `/sitemap_index.xml` with `--paths`.
2. Feed sitemap URLs and `Disallow` paths into the work buffer (`vigil assess ingest endpoints`)
   and/or use them as katana crawl roots.
3. Crawl with katana and keep `-kf all` on: it expands known files in the context of the full
   crawl and catches what the single fetch missed. The two fire at different times on different
   inputs, so neither replaces the other.
