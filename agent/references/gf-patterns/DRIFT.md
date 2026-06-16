---
name: gf-patterns:DRIFT
description: Static upstream-only vs Python-only bucket review decisions
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: maintenance
---

# GF Pattern Drift Decisions

This file records the static bucket-review decisions behind `agent/scripts/assess/lib/classify_buckets.py`. Upstream GF pattern repositories are effectively stable; the Python classifier intentionally narrows URL triage to buckets that can route work-buffer items, so this rationale is maintained by review rather than a sync script.

## Current Intentional Python-Only Buckets

- `trust_surface` — path-only trust-boundary routes that upstream GF does not model directly. Keep this bucket because uploads, OAuth callbacks, reset flows, webhooks, imports, exports, downloads, previews, and render/convert flows are high-value even without parameter-key signal.

## Accepted Bucket-Expansion Decisions

- `idor` param-key + path expansion (2026-06): the original bucket was the thin upstream gf slice (`id,user,account,number,doc,email,group,profile,order,report`) keyed off parameter names only, with `Path patterns that match: None`. Expanded on two axes after a HackerOne/BugCrowd/CVE IDOR-tactics review:
  - **Param keys** broadened to the `*_id` family, tenant/org/workspace scoping keys (cross-tenant BOLA), generic object handles (`object_id`, `oid`, `uuid`, `gid`, `node`, …), domain objects (`invoice`, `payment`, `ticket`, …), and modern chat/agent refs (`conversation_id`, `thread_id`, `message_id`). These are object references an authenticated attacker can swap; the additions never *remove* a higher-weight bucket (idor weight 35 < rce/ssrf/sqli/lfi), they only add an idor route to the reason chain.
  - **Path-embedded ids** now matched via the `_PATH_OBJECT_REF_SEGMENT` regex in `classify_buckets.py` (numeric / UUID / long-hex segment), so `/users/1024/profile` and `/files/<uuid>` bucket as `idor` instead of dropping to the `path:` fallback. A regex (not a path-fragment substring list) was chosen so it generalizes to any collection name without enumerating routes. Accepted false-positive surface: numeric segments also match `/2024/...` year and `/page/2` pagination paths — tolerated because weight only affects ordering, never skip/include.
  - Regression tests: `test_classify_idor_path_embedded_numeric_id`, `test_classify_idor_path_embedded_uuid`, `test_classify_idor_expanded_param_key_workspace`, and `test_classify_non_object_path_is_not_idor` in `orchestrator/backend/tests/test_work_buffer.py`. Reference doc `gf-patterns/idor.md` updated to match.

## Upstream-Only Categories To Reassess Before Adding

- Secret or content-body categories (`aws_keys`, `base64`, `firebase`, `json_sec`, `strings`, `s3_buckets`) usually belong to body/artifact scanning skills such as `gau-triage`, not URL priority bucketing.
- Source-code categories (`go_functions`, `php_curl`, `php_errors`, `php_serialized`, `php_sinks`, `php_sources`) belong to source/code analysis rather than live URL dispatch.
- Infrastructure categories (`http_auth`, `interestingsubs`, `ip`, `servers`, `takeovers`, `urls`) may become separate recon or surface-collection signals, but should not be copied into `_BUCKETS` unless they produce a clear `work_items` dispatch cluster.
- `debug_pages`, `fw`, `meg_headers`, and `sec` need human review against existing `debug_logic`, `interestingparams`, and tool-output handling before becoming new buckets.

When adding a bucket, update `_BUCKETS`, add or update the matching `gf-patterns/*.md` reference, record the accept/skip rationale here when relevant, and add a focused classifier/dispatch regression test.

## Accepted Bucket-Expansion Decisions (2026-06 surface taxonomy)

**Research basis:** three-corpus label study (cms-gov/xfinity/zendesk, ~8,000 labeled templates
across multiple deep sweeps with GPT-5.5 xhigh correction) documented in
`docs/plans/classify-surface-rd-2026-06-15.md`. Tests in
`orchestrator/backend/tests/test_classify_buckets_api_auth.py` and
`orchestrator/backend/tests/test_classify_buckets_storage_deser_debug.py`.

### Type-floor mechanism (`_TYPE_FLOOR`)

A producer-`type` floor rescues rows that score 0 because no bucket fires on their path or
params. When a row matches no bucket AND its producer type is in `_TYPE_FLOOR`, the row
clusters as `gf:<floor_bucket>` (NOT the `path:*` fallback) so specialist routing still fires.
When a bucket DID match, the floor only raises the numeric score via `max(match, floor)` —
it never changes the cluster routing. Floors are additive and zero-FP: they cannot lower a
bucket-driven score and they add no new path/param heuristics.

| Producer type  | Floor bucket  | Floor weight | Rationale |
|----------------|---------------|:------------:|-----------|
| `graphql`      | `graphql`     | 45           | GraphQL producer type = definitive high-value surface |
| `api_route`    | `api`         | 20           | REST endpoint; param/path match can push higher |
| `api_spec`     | `api_spec`    | 40           | OpenAPI/Swagger/WSDL — enumerates full attack surface |
| `auth_entry`   | `auth`        | 40           | Login/MFA/SSO page; credential attacks possible |
| `form`         | `auth`        | 30           | Form POST — CSRF, injection, credential surfaces |
| `portal_session` | `auth`      | 35           | Session-bearing portal root |
| `debug_config` | `debug_logic` | 35           | Config/env/debug artifact |
| `workflow`     | `idor`        | 30           | Workflow/process step; object reference likely |
| `event_feed`   | `ssrf`        | 25           | Event/webhook feed; SSRF potential |

`api_spec` is a label-only floor bucket (no `_BUCKETS` entry, no path fragments or param keys
in the bucket table); the floor clusters it as `gf:api_spec` for specialist routing.

### 13 buckets in the 2026-06 expansion — rationale

All 13 new buckets address classes that the 7-year-old gf taxonomy (written for monolithic web
apps circa 2017) has no concept for. Delta vs upstream gf is noted for each.

1. **`graphql` (weight 45)** — GraphQL endpoints and canonical POST keys (`query`, `mutation`,
   `subscription`, `operationname`, `variables`). Path fragments: `/graphql`, `/graphiql`,
   `/graphql/v1`, `/graphql/v2`, `/api/graphql`, `/gql`. `/query` deliberately excluded as a
   path fragment (would mis-bucket REST search routes at weight 45; `query` PARAM key carries
   the signal). Delta: gf has NO graphql category. Single worst corpus miss: `/graphql` at
   priority 0 in both cms-gov and xfinity (proposed priority 75). Zendesk third corpus: 392/1,540
   proxy rows are graphql-typed. P1.

2. **`auth` (weight 40)** — Authentication-entry surfaces. COMPOUND path fragments only — bare
   `/verify` excluded (captcha/email-verify FP). `email`/`token` excluded from param key set
   (too generic; `email` floods profile-update surfaces, `token` is owned by `interestingparams`
   and `jwt`). Delta: gf's `interestingparams` (weight 15, param-key only) was the only
   credential signal. 11 `missed_high_value` in initial sample; 46 actionable templates (4,201
   rows) in first deep sweep; 173 in third targeted sweep. P1.

3. **`api` (weight 20)** — Generic REST/Apex API routes. Path-only bucket with narrow literal
   fragments (`/rest/`, `/rest/v`, `/services/apexrest/`, `/apexrest/`). Bare `/api/` and
   `/api/v` DELIBERATELY OMITTED as literal fragments — a bare `/api/` would break the pinned
   reason chain `gf:lfi+gf:upload_fields` (override #9). The generic `/api/...` rescue is
   delivered by the `api_route` TYPE FLOOR; `/api/v<n>/` is covered by `api-versioning` regex.
   Delta: gf has no generic API path concept; all `/api/...` routes scored 0. Zendesk: 1,023/1,540
   proxy rows are api-typed. P1.

4. **`api-versioning` (weight 25)** — Regex bucket (override #1): pattern
   `/v[0-9]+(?=[/?#]|$)` matches versioned API path segments at segment boundaries. No key set,
   no literal fragments — the empty `_BUCKETS` entry keeps it in the single iteration for
   tie-break/reason-chain order. Matches `/v1/`, `/v3/account`, `/dhrp/rns/v3/actions`;
   rejects `/version/1.0`, `/v/1`, `/vue/app`, `/v1beta/x`. Delta: gf has no versioned-API
   concept; 30 xfinity templates scored 0. P1.

5. **`oauth-oidc` (weight 35)** — OAuth2/OIDC discovery, JWKS, authorize/token/userinfo
   endpoints. Declared BEFORE `trust_surface` (also weight 35) so co-fires on shared fragments
   resolve to `gf:oauth-oidc` (first-at-max-weight tie-break, matrix O2/O3). The bare
   `/oauth/callback` does NOT contain `/oauth2/` (the `2` is required), so `trust_surface`
   retains ownership of the bare callback (regression pin §10.5). Delta: gf has no OIDC/OAuth
   concept; `/.well-known/openid-configuration` scored 0. P1.

6. **`object-storage` (weight 25)** — Cloud storage (`/s3/`, `/gcs/`, `/blob/`, `/bucket/`)
   and Domino/Lotus discriminators (`$file`, `.nsf`, `files.nsf`, `docscat`, `didc`). Bare
   `/files/` and `/storage/` DELIBERATELY OMITTED (cms-gov has thousands of `/files/*.pdf`
   static content pages — override #2). `key`/`object` dropped from param key set (too generic).
   Delta: gf has `s3_buckets` body-scanning but no URL-routing equivalent. Third targeted sweep:
   655 actionable templates (dominant Domino/Lotus pattern). P3 initially; corpus evidence
   raised priority.

7. **`deserialization` (weight 40)** — Java/Python/ASP.NET deserialization surfaces and
   Siteforce loader-state paths. `/sfsites/` fires even when the URL ends `.js` so Aura
   loader-state URLs are not classified as inert static assets. The xhigh-corrected second and
   third cms-gov sweeps found 56 and 199 actionable templates respectively, concentrated in
   Siteforce `/sfsites/l/{encoded-json}/...` paths. Delta: gf has no deserialization concept.
   P3 initially; confirmed P1-equivalent by corpus volume.

8. **`websocket` (weight 30)** — WebSocket upgrade paths. `/ws` is boundary-anchored (matches
   `/ws`, `/ws/feed` but NOT `/wsdl`, `/wsus` — the next character must be a segment boundary).
   Delta: gf has no WebSocket concept. P3.

9. **`webhook` (weight 30)** — Webhook registration and delivery endpoints. `url` excluded from
   param key set (ssrf at 40 already wins on `?url=`). `/callback` omitted (owned by
   `trust_surface`). `/event`/`/events` omitted (content-navigation-prone: `/events/2024/conf`
   is a conference page, not a webhook — the real webhook-with-target case is captured by the
   `endpoint`/`target` keys). Delta: gf has no webhook concept. P3.

10. **`jwt` (weight 30)** — JWT/bearer-token surfaces. `token` and `/token` EXCLUDED (owned
    by `interestingparams` and `trust_surface` respectively — override #8 for this bucket).
    Low-incremental secondary signal; mostly co-fires with `oauth-oidc` (35) or `auth` (40)
    where the higher-weight bucket wins. Delta: gf's `interestingparams` had `token` at weight
    15; this doubles the weight and adds path coverage for explicitly JWT-named endpoints. P3.

11. **`sso` (weight 35)** — SAML/SSO federation endpoints. Declared BEFORE `trust_surface`
    (weight 35) for the same tie-break reason as `oauth-oidc`. The `_suppress_auth_on_sso_route`
    function removes a generic `auth` match when an SSO PATH fragment fires AND no auth param
    key fires AND no `/saml/acs`|`/saml/sso` compound fires — preserving auth on real SAML
    assertion consumer routes (matrix X3, A7) and on SAMLResponse-bearing login pages (matrix
    W10). Delta: gf has no SSO/SAML concept. First deep sweep: 3 actionable templates (371 rows).
    P3.

### Precision tightenings (2026-06)

Applied before widening recall, per C-5 plan:

- **SSRF key set narrowed (override #7):** `redirect`, `callback`, `continue`, `next`, `link`,
  `dest` moved OUT of `ssrf` param keys to `redirect` only. `ssrf` weight reduced 45→40.
  Rationale: a `?next=` on a `/login` page is an open-redirect (not SSRF); `ssrf` still fires
  on those keys via `/proxy/` and `/fetch/` PATH fragments, not via the param keys. This
  prevents `?next=/home` on an ordinary login page from clustering as `gf:ssrf` at weight 45
  instead of `gf:auth` or `gf:redirect`.

- **IDOR path-object-ref precision (§4.1–4.2):** year-segment exclusion (4-digit 19xx/20xx),
  small-int exclusion (single-digit), collection-context gate (at least one prior context
  segment required). Placeholder tokens `{id}`, `{uuid}`, `{n}` added as explicit match
  candidates for pre-normalized templates (fixes the 16 misclassified IDOR records where
  template normalization had already substituted numeric/UUID segments before classification).

- **`debug_logic` extended with compound-only fragments (override #3):** bare `/health`,
  `/info`, `/status`, `/version`, `/metrics`, `/env` deliberately NOT added (flood content
  corpora); only compound/specific fragments added (`/healthz`, `/readyz`, `/server-status`,
  `/server-info`, `/actuator/health`, `/actuator/env`, `/actuator/mappings`, `/actuator/metrics`,
  `/actuator/beans`, `/prometheus`, `/package.json`).

- **`upload_fields` name and weight preserved (override #9):** the roster proposed renaming to
  `file-upload` and raising to weight 35. Override: keep name `upload_fields` (pinned cluster
  key and reason string) and weight 30 (pinned `priority_score == 40` arithmetic in regression
  test). Recall delivered via new REST path fragments and content-type keys instead.

### SSRF → redirect key migration

The keys `redirect`, `callback`, `continue`, `next`, `link`, `dest` were moved from the `ssrf`
param key set to `redirect` only. Under the previous scheme a `?next=` or `?continue=` on a
login page clustered as `gf:ssrf` (weight 45) — shadowing the `auth` or `redirect` buckets.
After migration these keys fire `redirect` (weight 25) or are subsumed by a co-firing bucket.
`ssrf` retains URL-fetch signal from its remaining keys (`url`, `uri`, `host`, `port`, `feed`,
`window`) and from its path fragments (`/proxy/`, `/fetch/`).

### Regex-fragment mechanism (override #1)

The `_REGEX_BUCKET_RULES` dict is keyed by bucket name and consulted on the same
declaration-ordered pass over `_BUCKETS`. A regex bucket still gets a real `_BUCKETS` entry
(empty key set + empty literal fragments) to remain visible to `GF_BUCKET_TO_CLASS` and the
bucket iteration; its only match signal is the regex rule. The single-list design preserves
tie-break order (first bucket at max weight) and reason-chain order (declaration order). Current
regex rule: `api-versioning` → `/v[0-9]+(?=[/?#]|$)`.

### Corpus grounding

Three corpora, ~8,000 labeled templates (worker labels, GPT-5.5 xhigh corrections):
- **cms-gov** (CMS.gov breadth): primary pain surface; 1,711 cumulative actionable templates
  across original sample + three deep sweeps
- **xfinity** (Xfinity named engagement): 44 actionable templates in initial 535-template sample
- **zendesk** (Zendesk modern SaaS, third validation corpus): 1,540 proxy-captured rows;
  used qualitatively to validate `graphql` (392 rows) and `api` (1,023 rows) as dominant
  surface shapes in production SaaS

Full research artifacts: `docs/plans/classify-surface-rd-2026-06-15.md` (in-repo) and
machine-local archive at `~/vigil-research/classify-surface-2026-06/` (not committed, ~156M).
Test files: `orchestrator/backend/tests/test_classify_buckets_api_auth.py`,
`orchestrator/backend/tests/test_classify_buckets_storage_deser_debug.py`,
`orchestrator/backend/tests/test_classify_type_floor.py`.
