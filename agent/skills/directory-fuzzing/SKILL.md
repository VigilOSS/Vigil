---
name: directory-fuzzing
description: Discover hidden directories, files, and endpoints on web servers
origin: Vigil
---

# Directory Fuzzing

## When to Activate

- A web server is identified and hidden content (admin panels, backups, configs, API prefixes)
  may exist; after technology identification, for targeted lists.

Typed verb `vigil assess kali ffuf` (`-u -w -rate -t -H -mc -fc -fs -fw -fl -fr -ac -ic
-recursion -recursion-depth -o -of`; anything else, such as extensions, via
`--extra-args "-e .php,.bak"`); feroxbuster through `vigil assess kali exec`. Flags and filters:
`agent/references/tools/fuzzing/ffuf.md`, `feroxbuster.md`.

## Rate-of-Business (RoB) Calibration

A self-imposed "never enumerate" restriction is a **methodology choice, not a target fact.** Light,
targeted, low-rate discovery of known protected resources (login panels, admin paths, API prefixes)
is "identifying an indicator of vulnerability" under standard bug-bounty RoB definitions, not
exploitation. The honest constraint has three dimensions:

| Dimension | Compliant | Non-compliant |
|---|---|---|
| **Rate** | The dir-fuzz column of the `agent/references/recon/rate-calibration.md` row; back off on 429 | Unbounded `-t 200` against production |
| **Wordlist size** | Curated lists (dirb `common.txt`, raft-medium, tech-specific) | raft-large or custom brute against a production API |
| **Stop condition** | Stop on the first sensitive-data response; no bulk PII harvest | Running to exhaustion after a credential-bearing endpoint appears |

When a prior dispatch rejected or soft-capped discovery on RoB grounds without one of those
violations, re-dispatch with the restriction relaxed before accepting a coverage gap or downgraded
severity: a "maybe gated" verdict from a never-run pass is a coverage gap, not a disposition. Rates
per target: `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource
Policy"; doctrine: `agent/rules/hunting.md`.

## Wordlists in the runtime image

- dirb: `/usr/share/dirb/wordlists/common.txt` (~4,600), `big.txt`
- SecLists: `/usr/share/wordlists/SecLists/Discovery/Web-Content/` —
  `raft-medium-{directories,files}.txt`, `directory-list-2.3-{medium,big}.txt`, `common.txt`,
  `api/api-endpoints.txt`; DNS lists under `.../Discovery/DNS/`

Escalate common → raft-medium → directory-list-medium, within the RoB table.

## Method

```bash
vigil assess kali ffuf -u https://TARGET/FUZZ \
  -w /usr/share/dirb/wordlists/common.txt -rate 20 -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_common.json -of json \
  --technique FUZZ --intent "common path discovery" \
  --probe-kind payload --phase consume-test --timeout 600
```

- **Baseline** a nonexistent path first (status, size, words) so filters target the real soft-404.
- **Extensions:** `--extra-args "-e .php,.bak,.old,.conf,.env,.json,.yml,.log,.sql,.zip"`, plus
  tech-specific ones (PHP `.phps,.phtml,.inc`; ASP.NET `.aspx,.config`; Java `.jsp,.do,.action`).
- **Recursion:** feroxbuster with `--smart --auto-tune -d 3` and a thread count inside the RoB
  rate, then targeted ffuf under interesting directories.
- **Backups and sensitive files** (`.env`, `.git/HEAD`, `.git/config`, `.svn/entries`,
  `.DS_Store`, `web.config`, `wp-config.php` and backup suffixes `.bak .old .orig .save .swp ~`):
  read the body, not just the status — soft-200 error pages are the usual false positive
  (`agent/rules/hunting.md` §12). Exposure handling: `agent/skills/info-disclosure-testing/SKILL.md`.
- **API namespaces:** multi-product SaaS hosts nest APIs under per-product and versioned
  prefixes. Harvest the prefixes from JS bundles, source maps and docs
  (`agent/skills/source-analysis/SKILL.md`; a known multi-product prefix list is in
  `agent/references/tools/fuzzing/ffuf.md` "SaaS API Namespace Fuzzing"), probe each, and fuzz
  endpoints under every live one (`.../api/api-endpoints.txt`, with the app's suffix such as
  `.json`). On every non-404, read `Location`, `Server`, `Via`, `X-Served-By` and vendor routing
  headers
  (`x-envoy-decorator-operation`) for internal service names, Kubernetes hostnames or tenant data.
- **Virtual hosts:** fuzz `-H "Host: FUZZ.TARGET"` with a DNS list; wildcard parents from
  subdomain enumeration prove a vhost frontend exists.

## Triage

Filters cannot catch a soft-200 with a custom error body, or an admin page that differs only in
size class. Rank the survivors (ffuf JSON results carry `status`, `length`, `words`, `lines`,
`url`; rename `content-type`):

```bash
jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
  "$DIR/scans/ffuf_common.json" > "$DIR/scans/dir_pop.json"
vigil assess anomaly-score "$DIR/scans/dir_pop.json" --top 15
```

High scorers broke from the bulk shape (large body, distinct title, lone redirect, rare status,
rare `set-cookie`/`www-authenticate`/`location`); sizes are bucketed so boilerplate clusters. Verify
the top hits with `vigil assess kali exec … -- curl -s -i <url>`.

## What to Record

Discovered paths with status and size; sensitive files; admin and management interfaces; the
wordlists, rate and filters used; whether discovery was authenticated; new endpoints ingested with
`vigil assess ingest endpoints`.
