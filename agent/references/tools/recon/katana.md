---
description: Katana live crawling doctrine: audited wrapper flags, JS-aware defaults, bounded headless escalation, traversal/rate controls, and ingestion handoff
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
| `-fs <scope>` | optional Katana field-scope (`fqdn`, `rdn`, or another installed-version value); omitted unless the operator supplies it |
| `-rl <n>` | request rate (req/s) — **default 10, hard-capped at 20** unless `--allow-fast-crawl`; clamped DOWN to the program ceiling |
| `--allow-fast-crawl` | permit `-rl` above the 20 req/s safety cap |
| `-c <n>` | concurrency (default 5) |
| `-kf <set>` | known-files expansion (e.g. `all` for robots/sitemap/well-known) |
| `-cos <regex>` | explicit crawl-exclusion regex supplied for this run |
| `-H <header>` | extra request header (repeatable); attribution headers auto-inject on top |
| `--keep-bodies` | keep body+raw in `-jsonl` (default omits them via `-or -ob` to bound disk) |
| `--include-static` | crawl static/binary assets too (default excludes them via `-ef`) |
| `--no-jc` / `--no-jsl` | disable JS-endpoint / jsluice crawl (both **on by default**) |
| `-headless` | browser-backed crawl path |
| `-jsonl` | JSONL output |
| `-o <file>` | output artifact path |
| `--extra-args "<flags>"` | append version-specific Katana flags after typed flags |

**The doctrine is now the DEFAULT.** A bare `vigil assess kali katana -u <host>` already enables
JavaScript endpoint crawling and jsluice extraction, then applies `-d 5`, `-or -ob`, `-ef <static
set>`, `-rl 10`, and `-c 5`. The wrapper leaves field-scope and crawl exclusions unset unless the
operator passes `-fs` or `-cos`; override the remaining defaults with the typed flags above rather
than hand-assembling them in `--extra-args`. The result's `resolved_argv` shows the exact command
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

### Choose field-scope explicitly for multi-host traversal

Katana is an **active** crawler — every link it follows is a live request to the
target. When a run needs exact-host traversal, pass `-fs fqdn`; when a wildcard
root intentionally needs root-domain traversal, pass `-fs rdn`. The wrapper
does not infer either value from `scope.json`, because an argv seed list and an
engagement inventory answer different questions.

For a multi-host seed list that mixes wildcard roots and specific-host entries,
`-fs fqdn` is normally the precise choice: wildcard-subdomain breadth is
recovered separately through the recon job and passive `gau --subs` collection.
Use `-fs rdn` when the run deliberately calls for following sibling subdomains.

`-fs` and `-cos` are typed flags passed directly to Katana. No
`--extra-args` assembly is needed for either.

### Explicit crawl exclusions with `-cos`

Use `-cos <regex>` (`-crawl-out-scope`) only when the operator deliberately wants
to prune a crawl branch for that run, for example `-cos self-service-`. The
wrapper passes this explicit value through; it does not derive exclusions from
`scope.json`, `out_of_scope`, or `off_limits_paths`.

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
browser-semantic analysis, the supported JS-source extraction pipeline, or a targeted fuzzer pass.

## Ingestion

Plain Katana output feeds `ingest endpoints`:

```bash
cat /engagements/$ENGAGEMENT_KEY/scans/katana_target.txt |
  vigil assess ingest endpoints katana
```

If the crawl produced JSONL with richer metadata and a triage step promoted
records into candidate JSONL, use `ingest candidates` so priority and rationale
survive:

```bash
vigil assess ingest candidates \
  surface-collector-curated \
  /engagements/$ENGAGEMENT_KEY/scans/surface-collector/candidate_records.jsonl
```

## Adjacent Tools

- `vigil assess gau js-endpoints` complements Katana by extracting routes from
  saved JavaScript bundles with the supported corpus-scale pipeline.
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
