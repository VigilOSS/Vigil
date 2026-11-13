---
description: Historical URL discovery (Wayback, OTX, Common Crawl, URLScan); `vigil assess gau endpoints` is the recommended wrapper (cache-aware, ingests in one shot), with `gau secrets` and `gau js-endpoints` for body capture and JS-extracted route recovery; passive-collection scope rules and provider quotas
skill: gau-triage
---

# gau (Get All URLs)

Use `vigil assess gau endpoints` for collect-and-ingest (cache-aware; seats URLs into `work_items`
in one call), `vigil assess gau secrets` for body capture and secret extraction, and
`vigil assess gau js-endpoints` for routes in JS bundles (`agent/skills/gau-triage/SKILL.md` owns
the choice). Drop to the typed `vigil assess kali gau` only for a one-off archive sweep that does
not feed the work buffer; its `-o` becomes gau's `--o`, `--list` takes a domain file (the raw binary
under `kali exec` reads domains on stdin), and `--gau-timeout` is gau's own per-request timeout.

## Passive: no attribution header, no program rate cap, scope filtered downstream

gau sends nothing to the target; it queries third-party archives.

- **Program attribution headers and request-rate caps do not apply.** The header is withheld from
  gau so the researcher handle never reaches web.archive.org or Common Crawl, and a program's
  "max N req/s on automated tooling" governs target traffic, which gau does not generate. Only the
  providers' own quotas apply.
- **Scope is enforced when the corpus is consumed.** `--subs` on a wildcard root over-collects
  URLs for every subdomain, including carve-outs such as `appointments.acme-telco.example`. That is
  acceptable because ingestion and triage (`vigil assess scope filter`, work-buffer classification)
  filter the corpus before any active tool touches it. Passive breadth never widens the active
  crawl: `kali katana` fences each crawl to the scope.json hosts and excludes `out_of_scope` ones
  (`katana.md`).

## Provider quotas

URLScan (especially without a key) and OTX are quota-sensitive; Wayback and Common Crawl take the
most volume. For a large multi-root `--subs` sweep, prefer `--providers wayback,commoncrawl,otx`
and keep `--threads` at 3-5. gau continues past a provider that rate-limits it, but all four at high
threads burns a quota fastest. OTX and custom-provider keys go in `~/.gau.toml` inside the runtime.
Output repeats URLs; the wrapper verbs dedupe, a raw sweep needs `sort -u`.
