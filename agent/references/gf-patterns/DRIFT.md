---
name: gf-patterns:DRIFT
description: Static upstream-only vs Python-only bucket review decisions
origin: 1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc (+ local overlay)
bucket: maintenance
---

# GF Pattern Drift Decisions

## Provenance and license

The upstream comparison is pinned to
`1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc`; the enrichment
comparison against `rix4uni/gf-patterns` is audited at
`aa4db64656ac1fe22c8b5ad3cb2bad21ce848050`. Both are MIT-licensed. Vigil's compiled keys are
adapted and then changed by local weighting, precision, and false-positive rules; they are not a
verbatim copy of either pattern set. Copyright notices, exact license text, and the limitation that
the originally consulted enrichment revision was not recorded are in `THIRD_PARTY_NOTICES.md`.

At the pinned 1ndianl33t revision, the matching upstream JSON files are `debug_logic`, `idor`,
`img-traversal`, `interestingEXT`, `interestingparams`, `interestingsubs`, `lfi`, `rce`, `redirect`,
`sqli`, `ssrf`, `ssti`, and `xss`. `cors`, `trust_surface`, and `upload_fields` have no corresponding
upstream pattern file at that revision and are labeled as local overlays rather than assigned
invented upstream provenance.

## Contract owners

`agent/scripts/assess/lib/classify_buckets.py` owns bucket declarations, weights, matching,
precision guards, and cluster selection. `agent/scripts/assess/lib/vuln_taxonomy.py` owns
bucket-to-class mappings. The adjacent bucket references describe current signals and exclusions.

Keep bucket declarations, taxonomy mappings, reference descriptions, and focused positive/negative
regressions synchronized. Upstream categories are not imported automatically: a category needs a
clear URL-triage purpose, while body secrets and source-code patterns belong to their own analysis
surfaces. Preserve upstream license notices when adapting vocabulary.

## Precision boundaries

- Type floors apply when no bucket matches; on matched rows they may raise the score without
  changing the cluster.
- Declaration order resolves equal-weight clusters. Preserve reason-chain order and pinned
  precision negatives when changing vocabulary.
- Full-URL matching supplements path matching only for declared full-URL buckets.
- Bare `query` needs GraphQL corroboration. Generic navigation keys do not imply server-side fetching.
- Upload-field overlap changes cluster selection without deleting the matched reason chain.
- Classifier input tables and matching logic participate in freshness/versioning. Use
  `vigil assess work-buffer reclassify --reclassify-stale` for stale classifications.

### Fix 4 — compound-key signal recovery

Compound-key classification uses three layers to keep generic inner tokens from overriding
more specific whole-key evidence:

1. **Curated whole-keys (precision).** The common `*_url`/`*_uri`/`*_to` open-redirect family is
   enumerated as whole keys on `redirect`, and the server-fetch family on `ssrf` (both `snake_case` and
   `concatenated` lowercased forms). So `?return_url=` clusters `gf:redirect` strongly and precisely —
   *not* `gf:ssrf`. This mirrors the established `idor` `*_id` whole-key idiom (the way
   to handle compound keys without tokenizing high-weight generics). `servicenow` similarly carries
   `sysparm_url`/`glide_sso_id` as whole keys.
2. **Tiered weak inner-token rescue (recall / never-miss).** `classify_row` splits keys on
   `_`/`-`/camelCase (`collect_weak_tokens`/`_weak_token_matches`) and matches the inner tokens at a
   capped weight (`WEAK_TOKEN_CAP`=20), used ONLY when no strong bucket and no type floor fired — so a
   novel compound (`?appRedirect=`, `?user_cmd=`) is rescued from the score-0 `path:*` fallback instead
   of being missed. `expand_compound_key` itself splits only `.`/`[`/`]` (those are structural
   delimiters whose inner token is full-strength, e.g. `username[$ne]`→`$ne` for `nosqli`), which keeps
   every pinned reason chain byte-identical.
3. **Secondary cross-routing (never-miss).** On a strongly-matched row, weak buckets are recorded as
   `secondary_buckets` and bridged to per-class coverage items by `ingest endpoints`, WITHOUT changing
   `cluster_key`/`priority_reason`/`priority_score`/`matched_buckets`. So a `?id=`+`?userCmd=` row keeps
   its `gf:sqli` cluster yet still reaches the command-injection specialist, and `sysparm_url` keeps
   `gf:servicenow` yet cross-routes its open-redirect/SSRF angle.

Regression coverage: `test_classify_compound_key_fix4.py`; the `gf:lfi+gf:upload_fields` chain and the
`priority_score==40` arithmetic are preserved (whole-key `file` has no `_`/`-`/camelCase split).

**Intentional presentation boundary:** `secondary_buckets` bridge to coverage but do not appear in the
human-facing `priority_reason` chain. `priority_reason` names score-driving primary evidence; secondary
buckets are weaker guesses, and `ingest endpoints` already records each as a coverage obligation with a
`weak inner-token signal at ingest` note. Copying them into the reason string would duplicate the signal,
overstate its confidence, and lengthen operator/LLM output without adding coverage.
