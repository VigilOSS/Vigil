---
description: Katana live crawling doctrine: audited wrapper flags, JS-aware defaults, bounded headless escalation, scope/rate controls, and ingestion handoff
skill: surface-collection
---

# Katana

**Purpose:** Live URL crawling and JavaScript-aware endpoint discovery for
in-scope web applications. Katana turns reachable pages into requestable routes
for Phase 2 work-buffer ingestion.

Run target-facing crawls through `vigil assess kali katana` so the command lands
in the audit pipeline. Use `vigil assess web-discovery` when you want the
composed host-liveness + Katana + optional ingest flow instead of a single crawl.

## Wrapper Contract

The typed wrapper currently exposes:

| Wrapper flag | Katana effect |
|---|---|
| `-u <url>` | crawl one URL |
| `-list <file>` | crawl newline-separated seed URLs |
| `-jc` | JavaScript endpoint crawling |
| `-jsl` | jsluice-based extraction |
| `-d <n>` | maximum crawl depth |
| `-c <n>` | concurrency |
| `-rl <n>` | request rate limit |
| `-headless` | browser-backed crawl path |
| `-jsonl` | JSONL output |
| `-o <file>` | output artifact path |
| `--extra-args "<flags>"` | append version-specific Katana flags after typed flags |

Check the live runtime before using long-tail flags:

```bash
vigil assess kali exec \
  --technique HEALTH --intent "katana flag inventory" \
  --probe-kind fingerprint --phase collect --timeout 60 -- katana -h
```

## Default Crawl

Use this as the normal Phase 2 crawl posture for a single app-like host:

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -jc -jsl -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt \
  --technique DISCOVERY --intent "live Katana crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

Depth `3` with `-jc -jsl` is the baseline. Depth `1` is a smoke test, not a
coverage pass. Raise depth only for a named reason such as nested documentation,
API explorer routes, or app sections discovered late in the crawl.

## SPA / JS-Heavy Escalation

Escalate to `-headless` when the baseline crawl or `httpx` evidence shows a
browser-semantic trigger. The browser-semantic skill owns the full trigger
matrix; Katana only supplies the broad headless crawl.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -jc -jsl -headless -c 5 -rl 10 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target_headless.txt \
  --technique DISCOVERY --intent "headless Katana crawl for JS-generated routes" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

Headless is the right next step when:

- the page is mostly shell HTML and routes appear after hydration;
- useful fetch/XHR/WebSocket/SSE calls are absent from raw HTML;
- client-side redirects or router guards construct URLs dynamically;
- non-headless output is near-empty for a known React/Vue/Angular/Next/Svelte app.

For precise DOM/request/console/screenshot evidence, load
`agent/skills/browser-semantic-analysis/SKILL.md`. Katana headless is a crawler;
it is not a structured browser evidence oracle.

## Scope, Rate, and Exclusions

Keep crawls scoped and bounded:

- Crawl one app host at a time unless the dispatch explicitly gives a seed list.
- Apply the per-target rate row from `agent/references/recon/rate-calibration.md`
  and edge-specific crawl posture from
  `agent/references/runtime-guides/cdn-edge-behavior.md`.
- Prefer browser-like headers on CDN/Bot-Manager targets when the edge blocks
  scanner user agents.
- Exclude static/binary extensions when the installed Katana supports an exclude
  flag. Pass it via `--extra-args` only after checking `katana -h`; common
  candidates are image/font/archive/media extensions.
- Use known-file discovery such as `-kf all` through `--extra-args` when the
  installed Katana version supports it and the dispatch needs robots/sitemap or
  well-known route expansion.

### Field-scope: `-fs fqdn` is the scope-safe default for mixed-scope seed lists

Katana is an **active** crawler — every link it follows is a live request to the
target. Its default field-scope is `-fs rdn` (root-domain): from a seed of
`blis.com` it will follow links to **any** `*.blis.com` subdomain it discovers.
That is exactly wrong when the program grants only *specific* subdomains of a
root (the common Bugcrowd/H1 shape: `media.acme.example` and
`media.acme.example` are in scope, but `*.media.acme.example` is not). With the
default `rdn`, Katana will actively probe out-of-scope sibling subdomains it
finds in links — a scope violation, not just noise.

Rule for a multi-host seed list that mixes wildcard-scoped roots and
specific-host entries: pass **`-fs fqdn`** so Katana only crawls the exact hosts
you seeded. Wildcard-subdomain breadth (`*.acme.example`) is then recovered
separately via a scoped subdomain-enum pass and passive `gau --subs` collection —
**not** by letting an active crawler wander the root domain. Use `-fs rdn` only
when every seed root is itself a wildcard-scoped in-scope entry.

The typed wrapper does not model `-fs`/`-cos`; pass them via `--extra-args`
(`--extra-args "-fs fqdn -cos self-service-"`), or use the raw `katana` binary
directly under `kali job start` for an all-day operator sweep.

### Exclude out-of-scope path patterns with `-cos`

When the program carves out specific path patterns (e.g. "any endpoint ending in
`/self-service-*` is out of scope"), exclude them at the crawler with
`-cos <regex>` (`-crawl-out-scope`) so Katana never issues the request — e.g.
`-cos self-service-`. scope.json matches at host granularity and cannot express a
path carve-out, so `-cos` is the enforcement point for path-level OOS rules.

### Mandatory program-attribution headers (Bugcrowd `X-Bug-Bounty`, etc.)

Many bounty programs require a researcher-attribution header on **every** request
to in-scope targets (e.g. Bugcrowd's `X-Bug-Bounty: BugCrowd-<username>`); a
missing/incorrect value commonly incurs a bounty penalty. Inject it on every
active probe via `-H`:

```bash
# raw binary (under kali job start) — exact program format, no space after colon:
katana -list seeds.txt -H X-Bug-Bounty:BugCrowd-<username> ...
# typed wrapper:
vigil assess kali katana -u https://target.example \
  --extra-args '-H "X-Bug-Bounty: BugCrowd-<username>"' ...
```

This applies to **all active tools** (katana, httpx, nuclei, ffuf, curl). It does
**not** apply to passive archive tools (`gau`, `subfinder`, CT-log enumeration)
that never touch the target — see `agent/references/tools/recon/gau.md`.

### JSONL output bloat — omit body/raw on long crawls (`-or -ob`)

Katana `-jsonl`/`-j` stores the full `response.body` **and** the entire `raw`
request/response per record by default. On a deep, long-running crawl of
content-heavy pages this explodes the artifact: an observed all-day-style run hit
**~1.9 GB in ~35 minutes** (≈210 KB/line) and was on track to fill the runtime
disk. The request rate was correctly throttled — the blowup is output volume per
record, decoupled from request count (jsluice also emits many endpoint lines per
JS file). For any deep/long crawl where you only need the discovered routes plus
metadata, add **`-or`** (omit-raw) and **`-ob`** (omit-body):

```bash
katana -list seeds.txt -d 5 -jc -jsl -kf all -fs fqdn -j -or -ob -o out.jsonl ...
```

This keeps `url`, `status_code`, `headers`, `content_length`, and tech detection
while dropping the page bodies (≈726 bytes/line in the same run). If you genuinely
need bodies for source-analysis, capture them in a separate, bounded pass rather
than the broad crawl.

Example with version-dependent extras:

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -jc -jsl -c 8 -rl 15 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt \
  --extra-args "-kf all -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,mp3,avi,zip,tar,gz,7z" \
  --technique DISCOVERY --intent "bounded JS-aware crawl with known-file expansion" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

If a target has invalid TLS and Katana cannot be told to skip verification in
the installed version, spot-validate with audited `curl -k` and continue with
other collection sources instead of assuming Katana can crawl it.

## Auth-Aware Crawl

When the engagement's credential store marks credentials as available
(`vigil auth status`) and the dispatch authorizes authenticated collection,
pass only the needed headers:

```bash
vigil assess kali katana \
  -u https://target.example/app \
  -d 3 -jc -jsl -c 8 -rl 15 \
  --extra-args '-H "Cookie: session=..." -H "Authorization: Bearer ..."' \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target_auth.txt \
  --technique DISCOVERY --intent "authenticated Katana crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

Keep auth material out of final prose. Cite the command-run id and artifact path;
the audit row carries the command detail for authorized reviewers.

## Deep-Enough Bound

Do not apologize for an incomplete crawl. Make a deterministic decision:

- **Complete enough:** depth `3`, JS extraction enabled, no near-empty SPA signal,
  no unexplored app section in visible links/forms, and output ingested.
- **Escalate:** SPA shell, browser-only API calls, client redirects, soft-error
  pages, or obvious hidden app sections remain.
- **Declare gap:** edge challenge, invalid TLS unsupported by Katana, auth expired,
  out-of-scope navigation, or headless runner missing.

When escalating, name the next action: deeper Katana, headless Katana,
browser-semantic analysis, source-analysis/LinkFinder, or a targeted fuzzer pass.

## Ingestion

Plain Katana output feeds `ingest-endpoints`:

```bash
cat /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt |
  vigil assess ingest-endpoints "$ENGAGEMENT_DIR/cases.db" katana
```

If the crawl produced JSONL with richer metadata and a triage step promoted
records into candidate JSONL, use `ingest-candidates` so priority and rationale
survive:

```bash
vigil assess ingest-candidates "$ENGAGEMENT_DIR/cases.db" \
  surface-collector-curated \
  /engagements/$ENGAGEMENT_KEY/scans/surface-collector/candidate_records.jsonl
```

## Adjacent Tools

- `LinkFinder` complements Katana by extracting routes from saved JavaScript
  bundles. Prefer `vigil assess gau-js-endpoints` for corpus-scale JS body
  extraction; use direct LinkFinder only for a narrow source-analysis dispatch.
- `curl_chrome116`, when present, is a browser-like HTTP baseline for edge/TLS/UA
  ambiguity. It does not execute JavaScript or prove browser-enforced behavior.
- `aem-hacker` is conditional AEM tooling. Use it only after fingerprints point
  to Adobe Experience Manager; it is not a general crawler.
- `jwt_tool` and SAML tooling belong to `jwt-testing` and `saml-sso-testing`.
  Browser or Katana output may discover the token/flow, but the protocol tests
  belong to those auth skills.

## Cross-References

- `agent/skills/surface-collection/SKILL.md` — Phase 2 crawl and ingestion flow.
- `agent/skills/browser-semantic-analysis/SKILL.md` — when headless/browser
  semantics are needed for evidence correctness.
- `agent/references/runtime-guides/browser-semantic-evidence.md` — browser-mode
  evidence contract and headed-browser escalation.
- `agent/references/runtime-guides/cdn-edge-behavior.md` — CDN/WAF rate and UA
  behavior that affects crawl posture.
