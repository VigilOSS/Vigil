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
| `-d <n>` | maximum crawl depth — **default 5** (deep by default) |
| `-fs <scope>` | field-scope — **default `fqdn`** (crawl only the exact seeded hosts); pass `rdn` only for wildcard-scoped roots |
| `-rl <n>` | request rate (req/s) — **default 10, hard-capped at 20** unless `--allow-fast-crawl`; clamped DOWN to the program ceiling |
| `--allow-fast-crawl` | permit `-rl` above the 20 req/s safety cap |
| `-c <n>` | concurrency (default 5) |
| `-kf <set>` | known-files expansion (e.g. `all` for robots/sitemap/well-known) |
| `-cos <regex>` | crawl-out-of-scope path carve-out (scope.json cannot express path-level OOS) |
| `-H <header>` | extra request header (repeatable); attribution headers auto-inject on top |
| `--keep-bodies` | keep body+raw in `-jsonl` (default omits them via `-or -ob` to bound disk) |
| `--include-static` | crawl static/binary assets too (default excludes them via `-ef`) |
| `--no-jc` / `--no-jsl` | disable JS-endpoint / jsluice crawl (both **on by default**) |
| `-headless` | browser-backed crawl path |
| `-jsonl` | JSONL output |
| `-o <file>` | output artifact path |
| `--extra-args "<flags>"` | append version-specific Katana flags after typed flags |

**The doctrine is now the DEFAULT.** A bare `vigil assess kali katana -u <host>` already enables
JavaScript endpoint crawling and jsluice extraction, then applies `-d 5`, `-fs fqdn`, `-or -ob`,
`-ef <static set>`, `-rl 10`, and `-c 5`. Override any of these with the typed flag above — you no
longer hand-assemble them in `--extra-args`. The result's `resolved_argv` shows the exact command
that ran after attribution-header / IP-pin injection.

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
  -u https://target.example -d 3 -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt \
  --technique DISCOVERY --intent "live Katana crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

Depth `3` with the default JavaScript endpoint and jsluice extraction is the
baseline. Depth `1` is a smoke test, not a coverage pass. Raise depth only for a
named reason such as nested documentation, API explorer routes, or app sections
discovered late in the crawl.

## SPA / JS-Heavy Escalation

Escalate to `-headless` when the baseline crawl or `httpx` evidence shows a
browser-semantic trigger. The browser-semantic skill owns the full trigger
matrix; Katana only supplies the broad headless crawl.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -headless -c 5 -rl 10 \
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
- Static/binary extensions are excluded by default (the wrapper injects an `-ef`
  set); pass `--include-static` to crawl them, or `-ef <list>` via `--extra-args`
  to override the set.
- Known-file discovery is a typed flag: `-kf all` (robots/sitemap/well-known
  expansion) — no `--extra-args` needed. `vigil assess kali tool-help katana`
  confirms the installed version's `-kf` values.

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

`-fs` and `-cos` are now **typed flags** — `-fs` defaults to `fqdn` (the scope-safe
choice), and `-cos <regex>` is passed directly (e.g. `-cos self-service-`). No
`--extra-args` assembly is needed for either.

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

Note: the program-attribution header is **auto-injected** by the wrapper from the
engagement's `required_headers`, so you usually do not pass it by hand. When you
do need an explicit header, `-H` is a **typed flag** (repeatable) — pass it
directly, not via `--extra-args` (a `--extra-args` value beginning with `-H` is
rejected by argparse):

```bash
# raw binary (under kali job start) — exact program format, no space after colon:
katana -list seeds.txt -H X-Bug-Bounty:BugCrowd-<username> ...
# typed wrapper — -H is a typed, repeatable flag:
vigil assess kali katana -u https://target.example \
  -H "X-Bug-Bounty: BugCrowd-<username>" ...
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
# Raw katana binary, not the typed wrapper: pass JS flags explicitly.
katana -list seeds.txt -d 5 -jc -jsl -kf all -fs fqdn -j -or -ob -o out.jsonl ...
```

This keeps `url`, `status_code`, `headers`, `content_length`, and tech detection
while dropping the page bodies (≈726 bytes/line in the same run). If you genuinely
need bodies for source-analysis, capture them in a separate, bounded pass rather
than the broad crawl.

**The `vigil assess kali katana` wrapper now injects `-or -ob` by default**, so a
deep crawl is disk-bounded without you remembering the flags. Pass `--keep-bodies`
only for that deliberate, bounded body-capture pass.

Example with version-dependent extras:

```bash
# -kf is a typed flag; static-asset exclusion (-ef) is already the wrapper default.
vigil assess kali katana \
  -u https://target.example -kf all \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt \
  --technique DISCOVERY --intent "JS-aware crawl with known-file expansion" \
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
# -H is a typed, repeatable flag — pass auth headers directly, not via --extra-args.
vigil assess kali katana \
  -u https://target.example/app \
  -H "Cookie: session=..." -H "Authorization: Bearer ..." \
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
  vigil assess ingest-endpoints katana
```

If the crawl produced JSONL with richer metadata and a triage step promoted
records into candidate JSONL, use `ingest-candidates` so priority and rationale
survive:

```bash
vigil assess ingest-candidates \
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
