# ADR 0008 — URL-context scoring + generic surface buckets for work-buffer triage

- **Status:** Accepted — implemented. Code: `agent/scripts/assess/lib/classify_buckets.py` (the `_context_bonus` boost layer + the optional `url`/`source`/`live_status` kwargs on `classify_row`/`classify_from_fields`, the 9 net-new path/param buckets + the `cloud_metadata` regex bucket + the `_FULL_URL_REGEX_BUCKETS` pass, the `path_has_privileged_action` predicate, and the Part 6 param/extension additions) + `agent/scripts/assess/lib/vuln_taxonomy.py` (`GF_BUCKET_TO_CLASS` additions) + `agent/scripts/assess/lib/classify.py` and the ingest producers (typer + classification wiring). Shipped TDD.
- **Date:** 2026-06-29 (decided 2026-06-29; current-state cleanup 2026-07-20).
- **Decider:** Project owner.
- **Supersedes / relates to:** the second wave on top of **ADR 0004**
  (deterministic-first modern surface taxonomy). Per-bucket accept/override
  rationale lives in `agent/references/gf-patterns/DRIFT.md`. Extends ADR 0001
  ("no silent drops") to URL context.

---

## Context

ADR 0004 rescued dominant *modern surface shapes*
(graphql/api/auth/versioned-API/oauth/object-storage/deserialization) that the 7-year-old gf
taxonomy had no concept for. Follow-up review across a large, heterogeneous work buffer confirmed
three residual gaps that ADR 0004's path/param buckets cannot, by construction, close:

1. **The classifier threw away the row's URL context before scoring.** `classify_from_fields()`
   received only `case_type`, `url_path`, and the param JSON; the row's URL authority, ingest
   `source`, and `live_status` were in scope at the insert site but never threaded into scoring. The
   consequence: a `host_root` landing URL scored a **hard 0 even on
   `dev.`/`qa.`/`admin.`/`internal.` hosts**, and a **non-default management port** (e.g. a `:9443`
   Keycloak admin console) played no role whatsoever. Host *label* and port are among the strongest
   *generic* recon signals and were entirely ignored.

2. **A handful of high-recurrence enterprise surface shapes still fell through.** ASP.NET/WCF handlers (`.axd`/`.ashx`/`.asmx`/`.svc`) typed `unknown` and scored 0 (a genuine padding-oracle / ViewState-RCE surface). ServiceNow `.do` / `sysparm_*` action endpoints, WordPress/CMS/DB admin panels (the `/admin` boundary matcher misses `/wp-admin`, `/administrator`, `/phpmyadmin`, …), IdP admin/realm consoles, credential-vault APIs, ops/metrics dashboards, NoSQL operator injection, function-level-authz state verbs, and SSRF-to-IMDS proof payloads each had no bucket. None of these are engagement-specific — they are ubiquitous enterprise/cloud products.

3. **Our param/extension lists were narrower than upstream gf's**, so several low-risk recall adds to *existing* buckets were available (e.g. `debug_logic` was path-only and missed `?debug=1`).

These are surgical recall + context gaps, not a wholesale re-score: most of the priority-0 tail is genuinely inert historical-archive content and *should* be zero. The lever is host/source/live context plus a small set of generic buckets — applied without disturbing the mature, regression-pinned ADR-0004 classifier.

## Decision

**Add a boost-only URL-context scoring layer, 16 new generic classifications, and a Part 6 enrichment of existing buckets — all additive, all drift-gated, none engagement-specific.**

1. **Boost-only context-scoring layer (`_context_bonus`).** Thread optional `url=/source=/live_status=` kwargs (default `None`) into `classify_row()`/`classify_from_fields()` and pass them from the ingest producers. Compute a **strictly non-negative** bonus and apply it as `priority_score = max(base, base + bonus)` on the relevant branches, touching ONLY `priority_score` (never cluster/reason/terminal/matched-buckets). Signals stack independently: **+15** host-label (nonprod/admin/internal authority, boundary-anchored regex), **+5** well-known non-default port, **+5** `source-analysis`/`*-js-extract` source, **+5** `live`/`200` liveness. Computed after the inert/sourcemap early-returns and before `host_root`, so nonprod/admin `host_root` rows are rescued from 0 while keeping their stable `type:host_root` cluster. A default (no-kwargs) call is **byte-identical** to the pre-context output.

2. **Nine net-new path/param buckets**, each mapped to an existing canonical class (no new `VULN_CLASSES` minted): `secret_vault` (45 → `secrets-exposure`), `dotnet_handler` (40 → `deserialization`), `wordpress` (35 → `user-enumeration`), `cms_db_admin` (35 → `auth-bypass`), `idp_admin` (35 → `auth-bypass`), `nosqli` (35 → `nosqli`), `servicenow` (30 → `idor`), `privileged_action` (30 → `bfla`), `devops_console` (30 → `debug-exposure`). Each uses boundary-anchored fragments and is declaration-ordered so that on any co-fire with an existing weight-tied bucket the **existing** cluster is preserved (first-at-max-weight tie-break) with the new bucket recorded additively (e.g. `dotnet_handler` after `deserialization`, `wordpress` before `cms_db_admin`, `idp_admin` after `sso`/`trust_surface`, `devops_console` after `debug_logic`).

3. **One net-new regex bucket** — `cloud_metadata` (40 → `ssrf`): empty key set / empty literal fragments, signal carried entirely by `_REGEX_BUCKET_RULES` (link-local IMDS `169.254.169.254`, `metadata.google.internal`, IMDS paths, and the obfuscated decimal/hex forms). Because the marker most often sits in a query-value or host of a proof URL, `cloud_metadata` (and the new `object-storage` cloud host markers) are listed in `_FULL_URL_REGEX_BUCKETS`: `classify_row` re-tests their rules against the **full `url`** in a supplementary pass, deduped against any url_path hit, and **skipped entirely when `url` is absent** (so it is boost-only).

4. **`privileged_action` content-slug precision override.** A state-change verb alone does not fire the bucket; the `path_has_privileged_action` predicate requires a verb SEGMENT guarded by an `api`/`v<n>` sibling segment OR an embedded path object-ref. `/transfer-your-number` (content slug) and a bare `/transfer` page are rejected; `/api/users/grant`, `/v2/accounts/transfer`, `/users/1024/revoke` fire. Appended in `classify_row` (like the IDOR path-object-ref append) and deduped against the Part-6 param-key match.

5. **Four extensions to existing buckets + two typer/floor additions** (the remainder of the "16 generic classifications"): `oauth-oidc`/`sso` federation-metadata + DCR fragments, `interestingext`/`debug_logic` VCS/build-artifact fragments, `object-storage` bucket-listing params + cloud host markers; the typer learns `.axd/.ashx/.asmx/.svc`, extensioned auth pages (`wp-login.php`), and stronger api-spec recall; `_TYPE_FLOOR` gains `privileged_write → privileged_action/30`; and the `type=="unknown"` ingest guard is aligned across paths.

6. **Part 6 — param/extension enrichment of existing buckets, FP-screened.** Recall adds mined from upstream gf and diffed against our narrower lists (`rce`/`sqli`/`lfi`/`redirect`/`debug_logic`/`privileged_action`/`interestingext`). Two guards are load-bearing: **`code` is excluded from `rce`** (rce@50 outranks oauth-oidc@35, so a bare `?code=` OAuth callback would mis-cluster as `gf:rce`), and the **legitimate data extensions `.xml`/`.json`/`.csv`/`.yml`/`.pdf`/`.doc`/`.txt` are excluded from `interestingext`** (already typed `data`; would flood the bucket).

7. **The regression firewall (override #9) is non-negotiable.** Weight orders triage only, never skip/include. No change regresses an existing `_BUCKETS` entry or breaks a pinned `test_work_buffer.py` string (`gf:lfi+gf:upload_fields`; `/oauth/callback` ownership). This constraint shaped *how* Fix 4 (compound-key recall) landed, not *whether*: a naive `expand_compound_key` widening is behaviorally wrong (the inner tokens `id`/`uri`/`url` are high-weight generic keys, so splitting flips `gf:idor`→`gf:sqli` and routes every `?return_url=` to SSRF). Fix 4 therefore shipped as a **tiered mechanism** — curated whole-keys for the common `*_url`/`*_uri` families (precision), a capped-weight inner-token rescue used only when no strong bucket/floor fired (recall / never-miss), and `secondary_buckets` cross-routing on strong rows — all additive, with `expand_compound_key` itself still splitting only `.`/`[`/`]` so every pinned chain stays byte-identical.

8. **No dormant archive-demotion policy.** A consumer audit found that the former default-off `demote_dead_archive` parameter was never enabled by production; only its dedicated tests called it. It and its helper/tables were removed. Bucket-less archive rows now follow the same deterministic `path:*` fallback as every other bucket-less row, and source/liveness context remains strictly boost-only. This is the current supported boundary: the classifier does not make an unvalidated terminal skip decision from archive provenance.

9. **Drift-tested.** Every new bucket moved together with its `GF_BUCKET_TO_CLASS` entry so `test_vuln_taxonomy.py` stays green (CI fails if a bucket references an undeclared class); every new bucket has a `gf-patterns/*.md` reference doc, a `DRIFT.md` rationale entry, and focused tests with precision negatives.

### Owner constraints baked into the decision
- **Additive / boost-only:** context, buckets, and enrichment can only raise a score, add a reason-chain entry, or add a route — never lower a score or reorder a chain. A no-context call is byte-identical to the ADR-0004 output.
- **Generic, not engagement-specific:** the host-label regex, port set, and every bucket fragment/param key encode product/protocol shapes (Keycloak, ServiceNow, WordPress, Vault, IMDS, …), never a customer host, product, or path literal. Proactive buckets for Jenkins, phpMyAdmin, Vault, and cloud metadata preserve forward-looking coverage for future engagements.
- **Deterministic-first (ADR 0004) / no silent drops (ADR 0001):** the cheap, zero-FP context + boundary-anchored buckets land before any model spend, so a real surface never disappears into a priority-0 fallback for want of host/source/live signal.

## Consequences

**Positive**
- Nonprod/admin/internal `host_root` rows and non-default-port management interfaces leave priority 0 with zero new false-positive *routing* surface (the bonus touches only the score). The credential-vault / ASP.NET-handler / ServiceNow / CMS-DB-admin / IdP-admin / NoSQL / privileged-action / IMDS surface shapes get a `gf:*` home and route to their specialists.
- Skills route automatically: each bucket maps to an existing canonical class, so the `BUCKET_SKILLS` derivation and the coverage bridge pick the new buckets up with no hand-editing.
- The mature ADR-0004 classifier is untouched in behavior for any pre-existing input — the additive/boost-only contract and Fix 4's tiered design (weak inner-token matches never override a strong cluster; `expand_compound_key` still splits only `.`/`[`/`]`) keep every pinned arithmetic and reason-chain test byte-identical.

**Negative / risks**
- The +15 host-label / +5 port bonus will fire on benign nonprod marketing hosts and dev-servers serving static content. Tolerated: the bonus only orders triage (never gates), and a nonprod/admin authority is exactly the recon signal worth surfacing even on a dull-looking path.
- Several Part 6 recall adds are mildly generic params (`to`/`domain`/`site` on `redirect`; SQL-keyword params on `sqli`); they only affect ordering, and the high-FP candidates (`code` on `rce`; data extensions on `interestingext`) were explicitly excluded.
- Bucket count growth raises the per-row match cost marginally; the single declaration-ordered pass and cached compiled patterns keep it linear.

**Neutral / intentional boundaries**
- Fix 4 (compound-key recall) ships as curated whole-keys + capped inner-token rescue + `secondary_buckets` cross-routing. `secondary_buckets` deliberately stay out of the human-facing `priority_reason`: that string explains the score and primary cluster, while secondary buckets are weaker guesses that create separately annotated coverage obligations in `ingest endpoints`. Rendering them twice would imply equal confidence and add noise without adding routing coverage.
- Dead/archive provenance has no negative or terminal classifier path. A row with no bucket/floor/weak match receives the normal deterministic `path:*` fallback; the only context adjustment is a non-negative boost.
- The related web pipeline work is implemented, not pending: `web_discovery.py` always upserts an accepted httpx generation into the backend liveness ledger, and with `--db` it seats live results into the work buffer by default (explicit `--no-seat-liveness` opt-out). Katana output is converted to URL-sorted JSONL carrying `content_type`, response status, and technology metadata when present. The default disk-saving `-or -ob` crawl usually omits response metadata, so URL-only rows remain the expected fallback. `test_web_discovery_seat_katana.py` pins both paths.

## Alternatives considered

1. **More buckets / re-weighting instead of context scoring.** Rejected for the host-context gap: no path/param bucket can recover a `dev.`-host `host_root` row whose *path* is a bare `/` — the signal lives in the authority, which only the context layer reads. Buckets and context are complementary, so both shipped.
2. **A penalty or terminal demotion for dead/archive rows.** Rejected: a negative score risks lowering a legitimately bucketed row, while a terminal skip based on archive provenance was never corpus-validated or wired to a production caller. Both violate the simple boost-only boundary; no dormant flag remains.
3. **Naively widening `expand_compound_key` (the plan's literal Fix 4).** Rejected as behaviorally wrong, not merely risky: the inner tokens `id`/`uri`/`url` are high-weight generic keys, so a blanket split flips `workspace_id` to `gf:sqli`, `/oauth2/authorize?redirect_uri=` to `gf:ssrf`, and routes every `?return_url=` to SSRF instead of open-redirect. Fix 4 instead landed as the tiered curated-whole-key + capped-inner-token + secondary-cross-routing mechanism, which recovers the same surface with correct routing and zero pinned-chain perturbation.
4. **Adding `code` to `rce` and the generic data extensions to `interestingext` for maximal recall.** Rejected: `code` at weight 50 would mis-cluster every OAuth authorization-code callback as `gf:rce`, and `.xml`/`.json`/`.csv`/… would flood `interestingext` with content already typed `data`. Both are documented FP guards.

## References
- `agent/references/gf-patterns/DRIFT.md` — per-bucket accept/override rationale: the context layer, the 10 new buckets with canonical classes, the `privileged_action` precision override, the `cloud_metadata` full-URL match, the tiered Fix 4 mechanism, and the Part 6 FP guards.
- `agent/references/gf-patterns/*.md` — per-bucket reference docs (`dotnet_handler.md`, `wordpress.md`, `cms_db_admin.md`, `servicenow.md`, `idp_admin.md`, `secret_vault.md`, `devops_console.md`, `nosqli.md`, `privileged_action.md`, `cloud_metadata.md`).
- `agent/scripts/assess/lib/vuln_taxonomy.py` — `GF_BUCKET_TO_CLASS` (the drift-gated bucket→class map).
- Tests: `orchestrator/backend/tests/test_classify_context_scoring.py`, `test_classify_dotnet_handler.py`, `test_classify_high_value_buckets.py`, `test_classify_remaining_buckets.py`, `test_classify_part6_enrichment.py`; `agent/scripts/assess/tests/test_classify_type.py` and `test_web_discovery_seat_katana.py`.
- ADR 0004 — the modern surface taxonomy this extends (and whose override #9 / mechanisms it inherits). ADR 0001 — the "no silent drops" philosophy extended here to URL context.
