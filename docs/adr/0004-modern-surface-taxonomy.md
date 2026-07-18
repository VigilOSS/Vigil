# ADR 0004 — Deterministic-first modern surface taxonomy for URL triage

- **Status:** Accepted — implemented. Code: `agent/scripts/assess/lib/classify_buckets.py` (`_TYPE_FLOOR`, the 13 new/extended `_BUCKETS`, the regex-fragment mechanism, `normalize_path_for_cluster`, and the `_PATH_OBJECT_REF_SEGMENT` redesign) + `orchestrator/backend/lib/vuln_taxonomy.py` (`GF_BUCKET_TO_CLASS` additions). Shipped TDD in commit b3a9a6d7 (floor-key reconciliation follow-up in 12b143bb).
- **Date:** 2026-06-15 (decided 2026-06-15; shipped same day).
- **Deciders:** Project owner + Claude.
- **Supersedes / relates to:** the authoritative implementation contract is
  `docs/research/classify-surface-2026-06/IMPLEMENTATION-SPEC.md`; the empirical
  basis is the adjacent README and curated label artifacts. Relates to ADR 0001
  (the "no silent drops" philosophy this extends to the classifier).

---

## Context

Vigil ingests historical-URL (GAU) and crawl (Katana) corpora into a SQLite work-buffer, where `classify_buckets.classify_row()` assigns each row a `priority_score`, a `cluster_key`, and a `priority_reason` so the operator can rank surfaces and dispatch specialists. The classifier was a port of the 7-year-old `1ndianl33t/Gf-Patterns` taxonomy — a param-key + path-fragment bucket set written circa 2017 for monolithic web apps.

**The classifier buried the majority of two real corpora at priority 0.** Measured on the work-buffers of real engagements:

- **cms-gov** (`2026-05-16-194605-cms-gov`): 72,499 work items — only 12.4% gf-classified, 79.5% in the `path:*` fallback, **87.4% at priority 0**.
- **xfinity** (`2026-06-13-174755-xfinity`): identical shape — 6.7% classified, 79.8% fallback, **93.3% at priority 0**.

A multi-corpus label study (~8,000 templates across cms-gov + xfinity + zendesk, multiple deep sweeps with GPT-5.5 xhigh correction) quantified *what* was being buried. In the initial 535-template sample, 142 templates carried an actionable classification error (98 on cms-gov, 44 on xfinity); every `missed_high_value` and `misclassified` record sat at `priority_score = 0`, invisible to dispatch alongside genuinely inert content. The largest gaps were classes the gf taxonomy simply has no concept for:

- **`/graphql` at priority 0** — the single worst miss, present in both corpora, proposed priority 75, falling entirely to the `path:/` fallback.
- **`api` (40 missed in the sample; 82 actionable templates / 937 rows in the first cms-gov deep sweep)** — plain `/api/...` and `/rest/...` routes with no param signal, the largest gap by volume.
- **`auth`** entry points (`/login`, `/signin`, `/mfa`) at priority 0 — the gf taxonomy carried only a weight-15 `interestingparams` param-key signal.
- Whole modern classes absent from gf: **api-versioning** (`/v2/`, `/dhrp/rns/v3/`), **oauth-oidc** (`/.well-known/openid-configuration`), **websocket**, **sso/saml**, **jwt**, **object-storage** (cloud + Domino/Lotus `.nsf`/`$FILE`), **deserialization** (Siteforce `/sfsites/` loader-state, ASP.NET ViewState), **webhook**.

The cumulative cms-gov lower bound after three additional deep sweeps reached **1,711 actionable / 723 high-missed** templates — the original sample materially *undercounted* the gap. Two precision problems compounded the recall problem: the `_PATH_OBJECT_REF_SEGMENT` IDOR regex was diluted by `/2024/` year and `/page/2` pagination matches (and was blind to pre-normalized `{id}` templates), and the `ssrf` bucket's `next`/`redirect`/`callback` param keys mis-classified open-redirect surfaces as SSRF at weight 45.

A third corpus — **Zendesk** (a live modern SaaS, used qualitatively because its `cases.db` is malformed — `cases.db` has since been folded into the backend `assessment_work_items` ledger, see `docs/adr/0013-work-buffer-folded-into-backend-ledger.md`) — independently corroborated the two highest-value classes: of 1,540 proxy-captured rows, **1,023 are `api`-typed** and **392 are `graphql`-typed**, confirming that `api` and `graphql` are dominant surface shapes in production API-first architectures rather than niche classes (see §4b cross-corpus validation, now recorded in the research `README.md`).

## Decision

**Replace the gf-only triage with a deterministic-first modern surface taxonomy: a producer-`type` floor, 13 new/extended buckets, path-template cluster normalization, and precision tightenings — all running before any model pass.** The model classification pass (C-3) remains a *future second stage* scoped only to the residual fallback set; it is explicitly NOT the first stage.

1. **Type-floor (`_TYPE_FLOOR`) — rescue the producer's own signal first.** The producer assigns each row a `type` at ingest; the classifier previously discarded it for all non-inert rows. A 9-row `type → (floor_bucket, floor_weight)` table makes it a first-class input: `graphql→45`, `api_spec→40`, `auth_entry→40`, `portal_session→35`, `debug_config→35`, `form→30`, `workflow→idor 30`, `event_feed→ssrf 25`, `api_route→api 20`. The score becomes `max(match_weight, floor_weight)` — **a floor can never lower a bucket-driven score, and never changes cluster routing when a bucket matched**; when no bucket matches, the row clusters as `gf:<floor_bucket>` instead of the `path:*` fallback so specialist routing still fires. Zero new path/param heuristics, zero false-positive risk, zero model cost.

2. **13 modern buckets** addressing classes gf has no concept for: `graphql` (45), `auth` (40), `deserialization` (40), `oauth-oidc` (35), `sso` (35), `websocket` (30), `webhook` (30), `jwt` (30), `api-versioning` (25, a regex bucket), `object-storage` (25), `api` (20), plus extensions to `debug_logic` (compound-only actuator/health fragments) and the existing `upload_fields` (new REST `/attachments` fragments + content-type keys). Each uses boundary-anchored fragments (the pattern already proven to suppress `/admin` vs `/administration` false positives), with deliberate negative guards: no bare `/api/`, `/files/`, `/storage/`, `/health`, `/verify`, `/token`, `/callback` fragments (each flooded a content corpus or stole a regression-pinned cluster).

3. **Regex-fragment mechanism** — a 5th `_BUCKETS` tuple field carries raw regex fragments consulted on the same single declaration-ordered iteration, preserving the one-list tie-break and reason-chain ordering contract. The only regex bucket this round is `api-versioning` (`/v[0-9]+(?=[/?#]|$)`), matching `/v1/`, `/dhrp/rns/v3/actions` while rejecting `/version/1.0`, `/vue/app`, `/v1beta/x`.

4. **Path-template cluster normalization** (`normalize_path_for_cluster`) — collapses UUID / long-hex / year / numeric / opaque-token segments to placeholders *only* when building the `path:*` fallback cluster key, so `/explore-mvps/2024/M0004` and `/explore-mvps/2023/G0058` share one reviewable cluster. It is **never** consulted in bucket matching or in `_PATH_OBJECT_REF_SEGMENT` (which run on the raw URL).

5. **Precision tightenings** (applied *before* widening recall, per C-5): year + small-int + collection-noun gates on the IDOR path-object-ref rule (plus literal `{id}`/`{uuid}`/`{n}` placeholder matching for pre-normalized templates); and the `redirect`/`callback`/`continue`/`next`/`link`/`dest` keys moved out of `ssrf` (which now fires on those only via its `/proxy/`, `/fetch/` path fragments), with `ssrf` reduced 45→40.

6. **Soundness override #9 — the regression firewall is non-negotiable.** Weight affects triage *ordering only*, never skip/include. No change may regress an existing `_BUCKETS` entry or break an existing `test_work_buffer.py` test. Two tests pin exact strings (`gf:lfi+gf:upload_fields` reason chain; the `gf:trust_surface` ownership of `/oauth/callback`) and constrain the design — which is why `upload_fields` kept its name and weight 30, `api` carries no bare `/api/` fragment, and `oauth-oidc`/`webhook` omit `/oauth/`/`/callback`.

7. **Drift-tested.** Every new bucket has a `GF_BUCKET_TO_CLASS` entry in `vuln_taxonomy.py` (so the 2b coverage bridge mints a class-typed coverage item and the taxonomy drift test passes), a `gf-patterns/*.md` reference doc, a DRIFT.md rationale entry, and ≥1 positive row + ≥1 negative guard in the 93-row consolidated test matrix.

### Owner constraints baked into the decision
- Deterministic-first: free, zero-FP fixes (type-floor + boundary-anchored buckets + precision gates) land before any model spend; the model pass is scoped to the residual.
- No silent drops (ADR 0001): a buried surface is a missed bug; the floor + buckets exist so a real surface never disappears into a priority-0 `path:*` cluster.
- Robustness over speed; the contract (IMPLEMENTATION-SPEC) wins over the plan where they conflict, and override #9 (no regression) wins over the research roster where *they* conflict.

## Consequences

**Positive**
- The bulk of the buried high-value corpus (api / graphql / login / versioned-API / Domino object-storage / Siteforce deserialization families) is rescued from priority 0 with zero model cost and no new false-positive surface — boundary anchoring + negative guards keep recall gains from flooding content-rich `.gov`-style corpora.
- The `path:*` fallback collapses from ~11k+ distinct clusters into a reviewable, route-family-templated set, making operator defer/boost-by-cluster usable.
- One declaration-ordered bucket list keeps tie-break and reason-chain order deterministic and testable; the type-floor makes the producer's strongest cheap signal load-bearing.

**Negative / risks**
- Widening path regexes on a content-rich corpus risks queue noise; mitigated by mandatory route-context negative guards (the third targeted sweep over-called `workflow`/`admin`/`auth` on public-content page titles — `workflow` was a confirmed FP-trap and is deliberately a type-floor-only signal, deferred to the C-3 model pass for path-heuristic classification).
- The deterministic taxonomy is calibrated against cms-gov/xfinity/zendesk; it must be validated against the `.mil` archive/legacy-breadth corpus before it can be trusted as overfit-free (the research README names the two comparison corpora).
- The residual ambiguous single-row tail (~17.5k cms-gov templates) is not yet classified — by design; it is the input for the future C-3 model pass, not a gap in this decision.

**Neutral**
- The model classification pass (rd-plan C-3) and ingest observability (C-6) remain unshipped: C-3 is intentionally deferred as the second stage; C-6 is dropped.

## Alternatives considered

1. **Model-only classification as the first stage.** Rejected as the first stage: the strongest cheap signal (producer `type`) and the deterministic path/param structure of an API-first corpus are free and zero-FP — spending model tokens to re-derive `/graphql → high-value` or `/v2/ → versioned-API` is wasteful and non-reproducible. The deterministic taxonomy is first; the model pass (C-3) is a *future second stage* scoped only to the rows still at `path:*` priority 0 after these fixes, deduped by normalized url-template. This is the recorded "deterministic-first, model-second" decision.
2. **Tune down the existing gf weights / penalties instead of adding buckets.** Rejected: re-weighting cannot create a class the taxonomy lacks (`graphql`, `oauth-oidc`, `api-versioning` have no bucket to re-weight), so it leaves the dominant modern surfaces at priority 0 regardless.
3. **Rename `upload_fields → file-upload` and raise it to weight 35 (the research roster's proposal).** Rejected where it conflicts with override #9: the rename + reweight would break the pinned `gf:lfi+gf:upload_fields` reason string and the pinned `priority_score == 40` arithmetic. The recall intent (REST `/attachments` fragments + content-type keys) is delivered on the same `upload_fields` bucket at its existing name and weight instead.
4. **Add a bare `/api/` path fragment to the `api` bucket** (the research §4b proposal). Rejected: a bare `/api/` fragment fires on `/api/users/avatar` and corrupts the regression-pinned reason chain. The generic params-less `/api/...` rescue is delivered by the `api_route` type-floor (the semantically correct home); `/api/v<n>/` is covered by the `api-versioning` regex.

## References
- `docs/research/classify-surface-2026-06/IMPLEMENTATION-SPEC.md` — the authoritative implementation CONTRACT (bucket declaration order, the `_TYPE_FLOOR` table, the `_PATH_OBJECT_REF_SEGMENT` redesign, `normalize_path_for_cluster`, the 11 soundness overrides, and the 93-row test matrix). Where the spec conflicts with the research findings, the spec wins.
- `docs/research/classify-surface-2026-06/README.md` — the empirical basis: four labeling sweeps, the three+one corpora, the curated label artifacts, and the §4b cross-corpus validation detail (Zendesk graphql/api counts and endpoint shapes).
- `agent/references/gf-patterns/DRIFT.md` — the per-bucket accept/skip drift rationale (type-floor mechanism, all 13 buckets, precision tightenings, regex mechanism, corpus grounding).
- `agent/references/gf-patterns/*.md` — per-bucket reference docs (`graphql.md`, `api.md`, `auth.md`, `api-versioning.md`, `oauth-oidc.md`, `object-storage.md`, `deserialization.md`, `sso.md`, `webhook.md`, etc.), each carrying its corpus grounding and attack-class notes.
- ADR 0001 — the "no silent drops" / harness-not-gate philosophy this extends to URL triage.
