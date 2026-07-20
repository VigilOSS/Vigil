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

**Decision of record:** `docs/adr/0004-modern-surface-taxonomy.md` (deterministic-first taxonomy:
type-floor + 13 buckets + normalization + precision). **Research basis:** three-corpus label study
(cms-gov/xfinity/zendesk, ~8,000 labeled templates across multiple deep sweeps with GPT-5.5 xhigh
correction) documented in `docs/research/classify-surface-2026-06/README.md` (see its §4b
cross-corpus validation); the implementation contract is
`docs/research/classify-surface-2026-06/IMPLEMENTATION-SPEC.md`. Tests in
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

Full research artifacts: `docs/research/classify-surface-2026-06/` (in-repo: README +
IMPLEMENTATION-SPEC + curated label batches) and machine-local archive at
`~/vigil-research/classify-surface-2026-06/` (not committed, ~156M).
Test files: `orchestrator/backend/tests/test_classify_buckets_api_auth.py`,
`orchestrator/backend/tests/test_classify_buckets_storage_deser_debug.py`,
`orchestrator/backend/tests/test_classify_type_floor.py`.

## Accepted Bucket-Expansion Decisions (2026-06 context + surface buckets)

**Decision of record:** `docs/adr/0008-classification-context-and-surface-buckets.md`
(host/source/live context-scoring + 16 generic classifications + Part 6 enrichment).
**Precedent:** this
is the second wave on top of the 2026-06 surface taxonomy (ADR 0004 / the section above) and
inherits its mechanisms (the single declaration-ordered `_BUCKETS` pass, boundary-anchored
`fragment_in_path`, the regex-bucket mechanism, the `_TYPE_FLOOR`, and soundness override #9 —
no regression). **Tests:** `orchestrator/backend/tests/test_classify_context_scoring.py`,
`test_classify_dotnet_handler.py`, `test_classify_high_value_buckets.py`,
`test_classify_remaining_buckets.py`, `test_classify_part6_enrichment.py`,
plus the typer-side `agent/scripts/assess/tests/test_classify_type.py`.

**The binding constraint, restated.** Every decision below is **additive / boost-only**: it can
only RAISE a `priority_score`, add a `+`-joined entry to a reason chain, or add a `gf:*` route —
never lower a score, reorder an existing chain, or change a pinned cluster key. The drift gate
(`test_vuln_taxonomy.py`) stays green because each new bucket moved together with its
`GF_BUCKET_TO_CLASS[bucket] = <existing canonical class>` entry (no new `VULN_CLASSES` were minted —
every class below already existed). Overrides #1–#9 from the section above remain binding.

### Context-scoring layer (Fix 1, boost-only) — host-label / port / source / live

The classifier historically discarded the row's URL authority, ingest `source`, and `live_status`
before scoring, so a `host_root` landing URL on a `dev.`/`admin.`/`internal.` host scored a hard 0,
and a non-default management port (e.g. a `:9443` Keycloak console) played no role. `_context_bonus`
(`classify_buckets.py`) reintroduces those signals as a **strictly non-negative** integer applied as
`priority_score = max(base, base + bonus)` on the relevant return branches, so an absent/zero context
can NEVER lower a score and a default (no-kwargs) call is **byte-identical** to the pre-context output.
The bonus touches ONLY `priority_score` — never `cluster_key`, `priority_reason`, `terminal_reason`, or
`matched_buckets`. The signals stack independently:

- **+15** when the URL authority's host matches the nonprod/admin/internal host-LABEL regex
  `(^|[.-])(dev|qa|test|stage|staging|uat|sit|preprod|nonprod|internal|intranet|admin|sandbox|dr|corp)([.-]|$)`.
  Boundary-anchored on `.`/`-` so `dev.example.com`, `api-qa.example.com`, `admin.corp.example.com`
  match while `development.example.com` (no boundary after `dev`) does NOT. This is the single highest-value
  generic recon signal and was entirely ignored before (the host *label*, not a product/host literal).
- **+5** for a well-known non-default management/dev port (`8080`/`8443`/`9443`/`8000`/`8888`/`7001`/`9000`/`5000`).
- **+5** when `source` is `source-analysis` or a `*-js-extract` producer (JS-extracted endpoints out-signal dead archive URLs).
- **+5** when `live_status` is `live`/`200`.

The bonus is computed AFTER the inert/sourcemap early-returns (those stay fixed) and BEFORE the
`host_root` branch, specifically so the nonprod/admin/internal `host_root` rows are rescued from priority
0 **without** changing their stable `type:host_root` cluster. Threaded into scoring via optional
`url=/source=/live_status=` kwargs on `classify_row()`/`classify_from_fields()` (default `None`, wired from
`db.py`'s insert site); the default preserves the legacy 5-arg test convention. It is GENERIC — no
product/host/path literal anywhere in the regex or port set.

> Accepted FP surface: a benign `qa`-labelled marketing host or a dev-server on `:8080` serving static
> content gets +15/+5. Tolerated because the bonus only orders triage (never gates), and a nonprod/admin
> host is exactly the recon signal we want surfaced even when the path looks dull.

Dead/archive provenance has **no demotion or terminal-skip path**. The prior default-off experiment had no
production caller and was removed with its helper and tables. A `gau-archive` row with no bucket, floor, or
weak-token match follows the same deterministic `path:*` fallback as any other row. Source/liveness context
is strictly non-negative: `live`/`200` can boost a row, while dead/unknown liveness is neutral.

### The 10 net-new buckets (9 path/param + 1 regex) and their canonical classes

Each new bucket maps to an **existing** canonical class so skills route automatically and the drift test
passes. Declaration order is chosen so that on any co-fire with an existing weight-tied bucket the
**existing** cluster is preserved by the first-at-max-weight tie-break, with the new bucket recorded
additively in the reason chain.

| Bucket | Wt | Canonical class | What it catches / why generic |
|--------|:--:|-----------------|-------------------------------|
| `dotnet_handler` | 40 | `deserialization` | ASP.NET/WCF handlers the typer otherwise dropped to `unknown` (Issue A): `.axd`/`.ashx`/`.asmx`/`.svc`, `/_vti_bin/`, `/trace.axd`, `/elmah.axd`; params `__viewstate`/`__eventvalidation`. WebResource padding oracle (CVE-2010-3332), ViewState/Telerik RCE (CVE-2019-18935), WCF/ASMX SOAP, ELMAH disclosure, SharePoint. Declared AFTER `deserialization` (both 40) so a shared `__viewstate` keeps cluster `gf:deserialization` (pinned) with `dotnet_handler` recorded alongside. |
| `wordpress` | 35 | `user-enumeration` | WP surfaces the `/admin` boundary matcher misses (Issue 3): `/wp-json`, `/wp-json/wp/v2/users`, `/wp-login.php`, `/wp-admin` (note `-admin`, NOT the `/admin` segment), `/xmlrpc.php`, `/wp-cron.php`, `/wp-content/debug.log`; params `author`/`rest_route`. Declared BEFORE `cms_db_admin` (both 35) so a shared `/wp-admin` clusters as `gf:wordpress`. |
| `cms_db_admin` | 35 | `auth-bypass` | CMS + DB admin panels the `/admin` boundary matcher misses (Issue 3): `/administrator` (Joomla), `/umbraco`, `/sitecore`, `/typo3`, `/ghost`, `/phpmyadmin`, `/adminer(.php)`, `/pma`, `/dbadmin`, `/manager/html` (Tomcat), `/admin-console`, `/wp-admin` (hyphenated → `/admin` never matches). Path-only. |
| `servicenow` | 30 | `idor` | ServiceNow guest Service Portal / GlideRecord / Struts `.do` (Issue B): paths `/api/now`, `/nav_to.do`, `auth_redirect.do`, `/sys_`, `/$`, `/sp?`, `/x_`; params `sysparm_url`/`sysparm_query`/`sysparm_table`/`glide_sso_id`. The `auth_redirect.do?sysparm_url=` open-redirect/SSO surface fires via the `sysparm_url` WHOLE key (see Fix 4 note — the compound split was NOT widened this round). Generic: ServiceNow is ubiquitous enterprise SaaS, not an engagement artifact. |
| `idp_admin` | 35 | `auth-bypass` | IdP **admin/realm** surfaces (complements `oauth-oidc`, which models the flow): Keycloak `/auth/realms`, `/realms/` (v17+ dropped `/auth`), `/auth/admin`, `/admin/master/console`; PingFederate `/as/authorization.oauth2`, `/as/token.oauth2`, `/as/clients.oauth2`; `/idp/`, `/nidp/`, `/adfs/ls`. Declared AFTER `sso`/`trust_surface` (all 35) so `/adfs/ls` stays `gf:sso` and `/as/token.oauth2` stays `gf:trust_surface`, with `idp_admin` recorded additively. Path-only. |
| `secret_vault` | 45 | `secrets-exposure` | Credential-store/vault APIs: HashiCorp Vault (`/v1/secret`, `/v1/secrets`, `/v1/auth/token`, `/vault/`), AWS Secrets Manager (`/secretsmanager`), Azure Key Vault (`/keyvault`), generic credential proxies (`/credential-stores`, `/credentials/retrieve`, `/values/retrieve`, `/api/secrets`). **Highest non-RCE weight** (45, tied with graphql, declared after it) because an exposed credential store is P1-class. Path-only. |
| `devops_console` | 30 | `debug-exposure` | Ops dashboards / metrics & registry planes routinely deployed unauthenticated: Grafana (`/grafana`, `/api/datasources`), Jenkins (`/jenkins`), Jolokia (`/jolokia`, JMX RCE), Hystrix, ELK (`/kibana`, `/_cat/`, `/solr/`, `/druid`), Go pprof (`/debug/pprof`), Docker registry (`/v2/_catalog`), GitLab (`/api/v4/projects`). Declared AFTER `debug_logic` (both 30) so `/debug/pprof` keeps cluster `gf:debug_logic`. Path-only. |
| `nosqli` | 35 | `nosqli` | Mongo/Elasticsearch operator injection (gf had no NoSQL concept): param keys are the operators `$ne`/`$gt`/`$gte`/`$lt`/`$regex`/`$where`/`$in`/`$or`/`$exists`; paths `/_search`, `/aggregate`, `/_msearch`. A compound key like `username[$ne]` is decomposed to the `$ne` token by the **existing** `[`/`]` split in `expand_compound_key`, so the operator survives into the matcher — this bucket gives it a home. `$where`/`$gt` overlap the widened `sqli` keys; both firing is fine (multi-bucket chain). |
| `privileged_action` | 30 | `bfla` | Function-level-authz / business-logic abuse. Two signals (see precision override below): a state-verb path predicate, and the Part-6 param-key form of the verbs. Declared after `servicenow` (30). Path fragments stay empty (the path signal is a predicate, not a literal fragment). |
| `cloud_metadata` | 40 | `ssrf` | REGEX bucket (see full-URL note below). SSRF-to-IMDS payloads (Capital-One-class). |

### `privileged_action` content-slug precision override (§A.9)

A bare state-change verb is **not** enough to fire `privileged_action` — that would mis-bucket ordinary
content. The `path_has_privileged_action` predicate (appended in `classify_row` exactly like the IDOR
path-object-ref append, deduped against any param-key match so the chain never lists the bucket twice)
fires only when a verb SEGMENT from `_PRIVILEGED_ACTION_VERBS` (`grant`/`revoke`/`approve`/`reject`/
`impersonate`/`transfer`/`sendotp`/`promote`/`setrole`/`disable`/`deactivate`/`sudo`/`assume-role`) is
**guarded** by either an `api`/`v<n>` sibling segment OR an embedded path object-ref:

- `/transfer-your-number` does NOT fire — its single hyphenated segment is not the bare verb `transfer`.
- a bare `/transfer` page does NOT fire — no API/version sibling, no object-ref.
- `/api/users/grant`, `/v2/accounts/transfer`, `/users/1024/revoke` DO fire.

This is the documented accept: we trade a little recall on bare-verb pages (deliberately suppressed as
content-slug FP traps) for precision on real function-level-authz endpoints. The matching weight is
resolved from `_BUCKETS` (`_PRIVILEGED_ACTION_WEIGHT`) so the predicate can never drift from the declared
weight. Param-key form (`?delete=`/`?grant=`) added in Part 6 reinforces the path signal.

### `cloud_metadata` regex bucket + the full-URL match mechanism (§B.10)

`cloud_metadata` is a regex bucket (mechanism per override #1): an empty key set and empty literal
fragments, with its only signal living in `_REGEX_BUCKET_RULES["cloud_metadata"]` — the AWS link-local
IMDS address `169.254.169.254`, GCP `metadata.google.internal`, the IMDS paths (`/latest/meta-data`,
`/computeMetadata`, `/metadata/instance`), and the obfuscated decimal/hex forms of the link-local address
(`2852039166`, `0xA9FEA9FE`). Weight 40 (tied with `ssrf`), declared AFTER `ssrf` so a co-fire on a shared
weight-40 SSRF surface keeps the existing cluster, with `cloud_metadata` recorded additively.

The IMDS marker most often sits in a **query-param value or host of a proof URL**, not the `url_path`.
So `cloud_metadata` (and the `object-storage` host markers `.s3.amazonaws.com`/`blob.core.windows.net`/
`storage.googleapis.com` added in §C.14) are listed in `_FULL_URL_REGEX_BUCKETS`: `classify_row` runs their
rules a second time against the **full `url`** (authority + query) in a supplementary pass, appending a
matched bucket deduped against any url_path-side hit. This pass is **boost-only** — it is skipped entirely
when `url` is absent (the default-kwarg test convention), so every pinned arithmetic / reason-chain test
stays byte-identical, and an appended bucket can only raise the score / add a chain entry, never reorder it.

### Fix 4 — compound-key signal recovery, landed as a TIERED mechanism

The plan's Fix 4 proposed widening `expand_compound_key` to split on `_`, `-`, and camelCase so
`sysparm_url`→{`sysparm`,`url`} etc. Applied **naively that is non-additive and behaviorally wrong**:
the inner tokens `id`/`uri`/`url` are HIGH-WEIGHT generic bucket keys (`sqli`@40, `ssrf`@40), and
because `cluster_key` = the highest-weight match, naive splitting promotes those generics over more
specific lower-weight clusters — empirically it flipped `workspace_id` (`gf:idor`→`gf:sqli`) and
`/oauth2/authorize?redirect_uri=` (`gf:oauth-oidc`→`gf:ssrf`), and routed every `?return_url=` to SSRF
instead of open-redirect. So the goal is delivered through THREE layers instead, all additive:

1. **Curated whole-keys (precision).** The common `*_url`/`*_uri`/`*_to` open-redirect family is
   enumerated as whole keys on `redirect`, and the server-fetch family on `ssrf` (both `snake_case` and
   `concatenated` lowercased forms). So `?return_url=` clusters `gf:redirect` strongly and precisely —
   *not* `gf:ssrf`. This mirrors the established `idor` `*_id` whole-key idiom (the codebase's chosen way
   to handle compound keys without tokenizing high-weight generics). `servicenow` similarly carries
   `sysparm_url`/`glide_sso_id` as whole keys.
2. **Tiered weak inner-token rescue (recall / never-miss).** `classify_row` splits keys on
   `_`/`-`/camelCase (`collect_weak_tokens`/`_weak_token_matches`) and matches the inner tokens at a
   capped weight (`WEAK_TOKEN_CAP`=20), used ONLY when no strong bucket and no type floor fired — so a
   novel compound (`?appRedirect=`, `?user_cmd=`) is rescued from the score-0 `path:*` fallback instead
   of being missed. `expand_compound_key` itself still splits only `.`/`[`/`]` (those are structural
   delimiters whose inner token is full-strength, e.g. `username[$ne]`→`$ne` for `nosqli`), which keeps
   every pinned reason chain byte-identical.
3. **Secondary cross-routing (never-miss).** On a strongly-matched row, weak buckets are recorded as
   `secondary_buckets` and bridged to per-class coverage items by `ingest endpoints`, WITHOUT changing
   `cluster_key`/`priority_reason`/`priority_score`/`matched_buckets`. So a `?id=`+`?userCmd=` row keeps
   its `gf:sqli` cluster yet still reaches the command-injection specialist, and `sysparm_url` keeps
   `gf:servicenow` yet cross-routes its open-redirect/SSRF angle.

Regression-pinned in `test_classify_compound_key_fix4.py`; the `gf:lfi+gf:upload_fields` chain and the
`priority_score==40` arithmetic are untouched (whole-key `file` has no `_`/`-`/camelCase split).

**Intentional presentation boundary:** `secondary_buckets` bridge to coverage but do not appear in the
human-facing `priority_reason` chain. `priority_reason` names score-driving primary evidence; secondary
buckets are weaker guesses, and `ingest endpoints` already records each as a coverage obligation with a
`weak inner-token signal at ingest` note. Copying them into the reason string would duplicate the signal,
overstate its confidence, and lengthen operator/LLM output without adding coverage.

### Part 6 — param/extension enrichment of EXISTING buckets, with FP guards

Mined from upstream gf repos (`tomnomnom/gf`, `1ndianl33t/Gf-Patterns`, `rix4uni/gf-patterns`) and diffed
against our narrower lists. **No new categories** — the upstream-only categories were already adjudicated in
the sections above. Weight only orders triage, so these marginal recall adds are safe; each is FP-screened:

- **`rce`** += `ping`,`exe`,`func`,`function`,`cli`,`daemon`. **`code` is DELIBERATELY EXCLUDED** — `rce`
  (weight 50) outranks `oauth-oidc` (35), so a bare `?code=` OAuth-callback param would mis-cluster the
  whole row as `gf:rce` (a high-frequency false positive on every authorization-code redirect). Also skipped:
  `query`/`load`/`read`/`download`/`upload`/`dir` (owned by other buckets).
- **`sqli`** += `where`,`select`,`table`,`column`,`field`,`from`,`row`,`sleep`,`fetch` (SQL-keyword-flavored
  params). `where`/`select` overlap `nosqli`'s `$`-operators; both firing is fine (multi-bucket chain).
- **`lfi`** += `folder`,`root`,`dir`,`inc` (include shorthand),`conf` (config inclusion).
- **`redirect`** += `goto`,`rt`,`to`,`domain`,`site` — the **single-token** open-redirect params. The
  `_url`/`_uri`/`_to` compound family is now handled by Fix 4's curated whole-keys + tiered rescue (see
  "Fix 4" above). `to`/`domain`/`site` are mildly generic but only affect ordering.
- **`debug_logic`** += param keys `debug`,`dbg`,`test` (it was path-only; `?debug=1`/`?test=1` toggles are a
  real signal it missed). `admin`/`grant`/`access` are kept OUT of debug params — those route to
  `privileged_action`.
- **`privileged_action`** += param-key form of the state verbs (`grant`,`delete`,`create`,`disable`,`enable`,
  `toggle`,`reset`,`rename`,`modify`,`alter`,`clone`) — `?delete=`/`?grant=` reinforce the path predicate.
- **`interestingext`** += `.backup`,`.bkp`,`.cfg`,`.cnf`,`.crt`,`.csr`,`.passwd`,`.pwd`,`.mdb`,`.rdp`,`.dat`,
  `.pac` (backup/cred/cert/db artifacts), plus the §C.13 VCS/IaC/IDE dotfiles `.svn`,`.hg`,`.gitlab-ci.yml`,
  `.ds_store`,`.terraform`,`.tfstate`. **DELIBERATELY EXCLUDED:** `.xml`/`.json`/`.csv`/`.yml`/`.pdf`/`.doc`/
  `.txt` — these are legitimate data files already typed `data`; adding them would flood the bucket.
  Boundary anchoring means the distinctive `.gitlab-ci.yml` does NOT reintroduce a generic `.yml` flood
  (`/config.yml` still does not match).

Explicitly NOT changed (respecting prior precision work): `ssrf` stays narrowed to `url`/`uri`/`host`/`port`/
`feed`/`window` (override #7 moved redirect/exec/debug params elsewhere; re-importing upstream's `ssrf.json`
mix would regress that). `ssti` gains nothing safe (upstream adds only generic `name`/`id`/`content`/`preview`
that belong to other buckets).

**Shipped deviations from the plan worth recording (rationale-preserving, not score-affecting):**
- §C.11/§C.12/§C.13 fragment routing: the SAML federation-metadata fragment that shipped on `sso` is
  `/federationmetadata` only — `/saml/metadata` and `/adfs/ls` were no-ops (already covered by the existing
  `/saml` and `/adfs/` fragments), and `/simplesaml`/`/shibboleth.sso` were **NOT** added because the canonical
  product endpoints under them carry an auth fragment that `_suppress_auth_on_sso_route` would then strip,
  DEMOTING those rows from `gf:auth` (40) to `gf:sso` (35) — a non-additive score decrease, which override #9
  forbids. The §C.13 build/dependency manifests (`composer.json`/`composer.lock`/`yarn.lock`/
  `package-lock.json`/`web-inf/web.xml`) shipped on `debug_logic` (mirroring its existing `/package.json`),
  while the VCS/IDE dotfiles shipped on `interestingext`.
