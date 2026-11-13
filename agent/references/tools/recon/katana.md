---
description: Katana live crawling doctrine: wrapper defaults (pointer to the contract), depth judgement, bounded headless escalation, field-scope and -cos choices, JSONL bloat, crawl budget, the deep-enough bound, and ingestion handoff
skill: surface-collection
---

# Katana

Run as `vigil assess kali katana`; `vigil assess web-discovery` composes host liveness, Katana and
optional ingest. The wrapper defaults (`-d 5`, JS endpoint + jsluice crawling, `-or -ob`, static
`-ef` set, `-rl 10` capped at 20 and clamped to the program ceiling, `-c 5`) and the partial-output
behaviour on a `--timeout` cut are in `vigil assess contract kali katana`; `resolved_argv` shows the
command after attribution-header and IP-pin injection. Override a default with its typed flag
(`vigil assess kali katana --help`) rather than `--extra-args`. Crawl commands and ingestion are in
`agent/skills/surface-collection/SKILL.md` "Step 2: Live Crawl via Katana".

## Depth

Depth is decoupled from politeness: the rate cap carries the politeness, so the wrapper crawls
deep by default. Depth 3 with JS extraction is the least that counts as a coverage pass; depth 1 is
a smoke test. Go past the default only for a named reason such as nested documentation, API
explorer routes, or app sections discovered late.

`--crawl-budget <seconds>` sets katana's own `-crawl-duration` so the crawl stops itself; the
wrapper raises `--timeout` to fit a larger budget and refuses when that would pass the caller's
ceiling. Keep the budget inside one blocking call.

## SPA / JS-heavy escalation

Escalate to `-headless` when the baseline crawl or httpx shows a browser-semantic trigger:

- the page is mostly shell HTML and routes appear after hydration;
- useful fetch/XHR/WebSocket/SSE calls are absent from raw HTML;
- client-side redirects or router guards build URLs dynamically;
- non-headless output is near-empty for a known React/Vue/Angular/Next/Svelte app.

Katana headless is a crawler, not a structured browser evidence oracle; precise
DOM/request/console/screenshot evidence belongs to `agent/skills/browser-semantic-analysis/SKILL.md`.

## Scope, rate, and exclusions

- Crawl one app host at a time unless the dispatch gives a seed list. Rate comes from the
  `agent/references/recon/rate-calibration.md` row; edge-specific posture (browser-like headers when
  the edge blocks scanner user agents) from `agent/references/runtime-guides/cdn-edge-behavior.md`.
- **The crawl stays on scope.json hosts.** Every link Katana follows is a live request, so the
  wrapper fences it: a bare host keeps each seed on its own host, a `*.domain` entry lets it follow
  that domain's subdomains, and `out_of_scope` hosts are excluded. Pass `-fs` only to narrow or
  reshape the field scope (the scope.json crawl regex still applies); scope flags in
  `--extra-args` replace the whole fence and print a WARN. `vigil assess contract kali katana`
  has the exact argv.
- `-cos <regex>` prunes a branch for one run only when the operator wants it (e.g.
  `-cos self-service-`); the wrapper never derives exclusions from `out_of_scope` or
  `off_limits_paths`.
- Run `vigil assess kali robots` first for the high-signal seeds and keep `-kf all` on the crawl;
  they fire at different times on different inputs (`robots.md`). `vigil assess kali tool-help
  katana` confirms the installed `-kf` values.
- Program attribution headers are injected automatically; extra headers (auth cookies, bearer)
  use the typed, repeatable `-H`, because an `--extra-args` value that begins with `-H` is rejected
  by argparse. Cite the command-run id and artifact path, never the auth material, in prose.

## JSONL output bloat

Katana JSONL stores the full `response.body` and the raw request/response per record. One deep
crawl of content-heavy pages reached about 1.9 GB in 35 minutes (≈210 KB/line) at a correctly
throttled request rate, because jsluice also emits many endpoint lines per JS file. With `-or -ob`
the same run averaged about 726 bytes/line and kept `url`, `status_code`, `headers`,
`content_length` and tech detection. The wrapper injects `-or -ob`; pass `--keep-bodies` only for a
separate, bounded body-capture pass. A raw `katana` under `kali exec` needs `-jc -jsl -or -ob`
spelled out.

## Deep-enough bound

Make a deterministic decision rather than apologising for an incomplete crawl:

- **Complete enough:** depth ≥ 3, JS extraction on, no near-empty SPA signal, no unexplored app
  section in visible links/forms, output ingested.
- **Escalate:** SPA shell, browser-only API calls, client redirects, soft-error pages, or obvious
  hidden app sections remain. Name the next action: deeper Katana, headless Katana,
  browser-semantic analysis, `vigil assess gau js-endpoints`, or a targeted fuzzer pass.
- **Declare a gap:** edge challenge, invalid TLS Katana cannot skip (spot-validate with audited
  `curl -k` and move to other sources), expired auth, out-of-scope navigation, or a missing
  headless runner.
