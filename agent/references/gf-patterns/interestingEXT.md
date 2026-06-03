---
name: gf-patterns:interestingEXT
description: File extensions that signal backup, config, source, and sensitive-file exposure
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: interestingext
weight: 10
---

# gf: interestingEXT

## What this bucket classifies

URL file extensions that indicate backup files, version-control artifacts, config dumps,
and source bundles left on the webserver. These are high-yield for quick wins: direct
source disclosure, credential leaks, and full-database downloads.

## Load this reference when

- gau or Wayback returned URLs ending in `.bak`, `.old`, `.swp`, `.sql`, `.tar.gz`, or `.pem`
- Nuclei's `exposures` templates flagged backup files — use this reference to widen the sweep
- Operator is ranking which historical URLs to live-probe first before spinning up full Phase 3

## Parameter keys that match

Not applicable — this bucket classifies URL paths by extension, not parameter names.
`classify_work.py` does not emit a direct `gf:interestingEXT` cluster. Instead, operators
see these surfaces via the `path:/<seg1>/<seg2>` path-fallback cluster and via trufflehog
filesystem scans once the bodies are downloaded.

## Path patterns that match

Classic extension list (from 1ndianl33t patterns):
`.bak, .backup, .old, .orig, .original, .save, .swp, .swo, .tmp, .temp, .log, .sql, .dump,
.cfg, .conf, .config, .ini, .json, .yaml, .yml, .xml, .env, .pem, .key, .pfx, .p12, .crt,
.tar, .tar.gz, .tgz, .zip, .rar, .7z, .gz, .iso, .sh, .bash, .py, .rb, .pl, .php~, .inc,
.git, .svn, .hg, .DS_Store, .htaccess, .htpasswd`

## Weight and priority interpretation

- No direct priority_score emitted by `classify_work.py` for this bucket. Use it as an
  operator-side filter applied to the raw corpus before dispatching downstream probes.
- Operator contract: when the gau corpus contains these extensions, record high-value
  hits as surfaces directly and cross-reference trufflehog findings against the body
  content for credential-type disclosures.

## Example URLs that match

- `https://target.example/backup/db_2024-01-01.sql.gz` — database dump
- `https://target.example/.env` — environment file with secrets
- `https://target.example/config.php.bak` — PHP source backup
- `https://target.example/deploy/id_rsa.pem` — private key disclosure
- `https://target.example/.git/config` — git repo exposed, reveals remote URL
- `https://target.example/server.log` — application log
- `https://target.example/archive/source.tar.gz` — source bundle

## What it does NOT classify

- Normal static assets (`.css`, `.js`, `.png`) — those ingest as inert types or scan via trufflehog for secret values, not as interestingEXT
- Public documentation bundles that use `.zip` for downloads — verify contents before escalating
- API responses with `.json` extensions that are intentional endpoints — those are normal `api` surfaces

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings Info Disclosure](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Source%20Code%20Management)

## Related

- `agent/references/payloads/info-disclosure-probes.md` — standard endpoints checklist for sensitive files
- `agent/references/tools/recon/trufflehog.md` — value-side secret detector that pairs with this extension filter
- `agent/references/gf-patterns/debug_logic.md` — adjacent bucket (`.git`, `.env` paths overlap)
