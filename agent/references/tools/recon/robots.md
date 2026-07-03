---
description: Pre-crawl known-file fetch — robots.txt / sitemap.xml / .well-known/security.txt per host as a high-signal seed BEFORE the katana crawl. Scoped to the marginal pre-crawl fetch (katana -kf covers in-crawl known-files)
skill: surface-collection
---

# robots (pre-crawl known-file fetch)

**Purpose:** Before the katana crawl, fetch each in-scope host's `/robots.txt`, `/sitemap.xml`, and `/.well-known/security.txt`. These three are disproportionately high-signal: `robots.txt` `Disallow:` lines routinely name admin panels, staging hosts, and endpoints nobody links to; `sitemap.xml` enumerates real URLs directly; `security.txt` names a disclosure contact and sometimes a scope/policy URL. Seeding those paths into recon **before** the crawl makes the crawl land on real surfaces faster instead of discovering them (or missing them) deep in the link graph.

Run via `vigil assess kali robots` (typed verb, audit-flag-aware). Pass the required audit flags (`--technique RECON`, `--intent`, `--probe-kind fingerprint`, `--phase recon`, `--timeout`) per `shared-constraints.md §2`.

## Scope — pre-crawl ONLY (do not duplicate katana `-kf`)

This verb is the **marginal pre-crawl fetch** and nothing more. **katana's own `-kf` (known-files) flag already expands `robots.txt`/`sitemap.xml`/`.well-known` DURING the crawl** (see `agent/references/tools/recon/katana.md` and `kali_katana.py`). The two are complementary, not redundant:

- **`kali robots` first** — a fast, cheap single-fetch that surfaces the high-signal paths up front so you can seed them as work items / crawl roots before spending the deep-crawl budget.
- **katana `-kf all` during the crawl** — re-walks and expands known files in the context of the full crawl.

Do not re-implement in-crawl known-files expansion here, and do not skip `-kf` on the crawl because you ran `robots` (they fire at different times against different inputs).

## Engine + flag mapping

The engine is **httpx** probing the well-known paths (`-path`), so the audit row's `tool_bin` is `httpx`:

- **Input:** `<host>` / `-u <host>` (single) or `-l <file>` (a host/URL list — e.g. the `web-discovery` live set).
- **Paths:** `--paths` defaults to `/robots.txt,/sitemap.xml,/.well-known/security.txt`; override to add e.g. `/.well-known/openid-configuration` or `/sitemap_index.xml`.
- **Match codes:** `-mc` defaults to `200,301,302,401,403` — keeping `401/403` so a *present-but-gated* file (it exists, it is just protected) still surfaces instead of being silently dropped.
- **Output:** `-json` (structured), `-o <file>`.

Because the engine is httpx, the verb inherits httpx's required-header injection (a required-headers program marker rides every probe) and the shared scope posture — nothing extra to wire. Read-only GETs: leave `--destructive` off.

## Workflow

1. Run `kali robots -l <live_hosts>` right after `web-discovery`/liveness, before the deep crawl.
2. Feed the discovered sitemap URLs + `Disallow` paths into the work buffer (`ingest-endpoints`) and/or as katana crawl roots.
3. Crawl with katana (keep `-kf` on) — the pre-seeded paths make the crawl converge faster and the `-kf` pass catches anything the single-fetch missed.

Canonical annotated invocations: `vigil assess contract kali robots`.
