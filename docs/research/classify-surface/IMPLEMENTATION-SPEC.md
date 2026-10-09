# classify_buckets.py — Authoritative Implementation Spec (classify-surface 2026-06)

Research collection: `classify-surface-2026-06`.

> **Status authority:** this remains the classifier behavior contract, not an open-work queue.
> Future classifier changes require new measured evidence and an explicit implementation change.

**Status:** CONTRACT. This file is the single source of truth for the TDD effort on
`agent/scripts/assess/lib/classify_buckets.py`. RED tests encode this matrix verbatim;
GREEN code must satisfy every row. Where this spec conflicts with the research findings
(now consolidated in `README.md` §4b and the decision in `docs/adr/0004-modern-surface-taxonomy.md`),
**this spec wins** — it reconciles the research section-4 proposal against the adversarial soundness
overrides.

**Scope of edits (implementer):** `agent/scripts/assess/lib/classify_buckets.py` only.
Do not touch other modules in this phase except where this spec explicitly calls out a
required companion edit (DRIFT.md + gf-patterns/*.md docs, and `GF_BUCKET_TO_CLASS` in
`vuln_taxonomy.py` — see §11). No test file is edited in the RED phase except the new
classifier tests being added.

**Prime directive (soundness override #9):** weight only affects triage ORDERING, never
skip/include. No change may regress an existing `_BUCKETS` entry or break any existing test
in `orchestrator/backend/tests/test_work_buffer.py`. Two existing tests pin EXACT strings
and constrain the design — see §10 (Regression Firewall).

---

## 0. Locked mechanics carried forward unchanged

These behaviours in the current `classify_row` / `bucket_matches` are preserved exactly;
the spec only extends them.

1. `bucket_matches(url_path_lower, keys)` iterates `_BUCKETS` **in declaration order**;
   a param-key hit OR a path-fragment hit appends `(name, weight)`. (Regex buckets are
   appended by the same iteration — see §3.)
2. After literal matching, the path-object-ref rule appends `("idor", _IDOR_WEIGHT)` iff
   no `idor` already matched. (Extended in §4.)
3. `best_weight = max(weight for _, weight in matches)`.
   `top_buckets = [name for name, weight in matches if weight == best_weight]`.
   `best_name = select_cluster_bucket(case_type, matches, top_buckets[0])`.
   **Tie-break = first bucket in declaration order at the max weight.**
4. `priority_reason = "+".join(f"gf:{name}" for name, _ in matches)` — in match
   (declaration) order, every match listed, no dedupe of weight, but `matched_buckets`
   list is order-preserving deduped.
5. `cluster_key = f"gf:{best_name}"` when any bucket matched; else the path fallback.
6. `fragment_in_path()` matches the literal fragment via `re.escape()` + a segment
   boundary `(?=[/?#=&]|$)`; a trailing `/` on the fragment is dropped before anchoring.
   **A regex string therefore CANNOT be a literal `path_fragments` entry** (override #1).
7. Early returns are evaluated in this order and each fully wins (override #4):
   `INERT_TYPES` → `sourcemap` → `host_root` → (then bucket/floor logic).

---

## 1. Declaration order of `_BUCKETS` (authoritative)

Declaration order is load-bearing for tie-breaks (rule 0.3) and reason-chain order
(rule 0.4). The new/extended buckets are inserted at the positions below. **Existing
buckets keep their current relative order and weights; new buckets slot in by weight
band, and — critically — every new bucket is declared AFTER all existing buckets of equal
or higher weight so no existing tie-break or exact reason-chain flips** (see §10).

Final order (name → weight):

| # | bucket | weight | kind |
|---|--------|-------:|------|
| 1 | `rce` | 50 | existing |
| 2 | `graphql` | 45 | **NEW** |
| 3 | `ssrf` | 40 | existing (key set narrowed, §7) |
| 4 | `sqli` | 40 | existing |
| 5 | `lfi` | 40 | existing |
| 6 | `auth` | 40 | **NEW** |
| 7 | `deserialization` | 40 | **NEW** |
| 8 | `img_traversal` | 35 | existing |
| 9 | `idor` | 35 | existing |
| 10 | `oauth-oidc` | 35 | **NEW** |
| 11 | `sso` | 35 | **NEW** |
| 12 | `file-upload` | 35 | **NEW** (supersedes `upload_fields`; see §6.12) |
| 13 | `debug_logic` | 30 | existing (fragments EXTENDED, §6.13) |
| 14 | `websocket` | 30 | **NEW** |
| 15 | `webhook` | 30 | **NEW** |
| 16 | `jwt` | 30 | **NEW** |
| 17 | `redirect` | 25 | existing |
| 18 | `ssti` | 25 | existing |
| 19 | `cors` | 25 | existing |
| 20 | `api-versioning` | 25 | **NEW (regex bucket, §3)** |
| 21 | `object-storage` | 25 | **NEW** |
| 22 | `api` | 20 | **NEW (path-only, narrowed, §6.3)** |
| 23 | `xss` | 20 | existing |
| 24 | `interestingparams` | 15 | existing |
| 25 | `interestingext` | 10 | existing |

**Bucket count after this change: 25** (12 existing retained + 13 added/extended; note
`file-upload` REPLACES the name `upload_fields` — see §6.12 for the compatibility rule
that keeps the `gf:upload_fields` cluster-key behaviour intact for the existing test).

> **Tie-break note (deserialization vs ssrf/sqli/lfi/auth all at 40):** when two 40-weight
> buckets co-fire, the winner is the earliest in declaration order: `ssrf` < `sqli` < `lfi`
> < `auth` < `deserialization`. This is intentional — pre-existing 40-buckets keep priority,
> the new 40-buckets only win when no older 40-bucket fired.

---

## 2. Type → (bucket, floor weight) table  (override #4)

A `_TYPE_FLOOR` mapping is added: `dict[str, tuple[str, int]]` keyed by lowercased
producer `type`. The producer `type` is currently discarded for non-inert rows; the floor
makes it a first-class input.

### 2.1 The table (9 rows)

| producer `type` | floor bucket | floor weight |
|-----------------|--------------|-------------:|
| `graphql` | `graphql` | 45 |
| `api_route` | `api` | 20 |
| `api_spec` | `api_spec` | 40 |
| `auth_entry` | `auth` | 40 |
| `form` | `auth` | 30 |
| `portal_session` | `auth` | 35 |
| `debug_config` | `debug_logic` | 35 |
| `workflow` | `idor` | 30 |
| `event_feed` | `ssrf` | 25 |

> `api_spec` floor bucket is the literal token `api_spec` (there is no `_BUCKETS` entry of
> that name; it exists only as a floor/cluster label, mirroring how `interestingext` is
> used as a cluster label for the `sourcemap` early-return). `cluster_key` becomes
> `gf:api_spec` when the floor fires with no bucket match. This is intentional and the
> matrix tests it (row T3).

### 2.2 Floor application rule (EXACT)

In `classify_row`, AFTER the `INERT_TYPES` / `sourcemap` / `host_root` early returns
(those still win and short-circuit — override #4), compute `matches` (literal + regex +
path-object-ref) as today, then:

```
floor = _TYPE_FLOOR.get(case_type)            # (floor_bucket, floor_weight) or None
match_weight = max((w for _, w in matches), default=0)
floor_weight = floor[1] if floor else 0
score = max(match_weight, floor_weight)        # floor NEVER lowers an existing result

if matches:
    best_weight = max(w for _, w in matches)
    top_buckets = [n for n, w in matches if w == best_weight]
    best_name = select_cluster_bucket(case_type, matches, top_buckets[0])
    cluster_key = f"gf:{best_name}"
    reason = "+".join(f"gf:{n}" for n, _ in matches)
    matched_buckets = <order-preserving dedupe of match names>
    return {priority_score: score, priority_reason: reason,
            cluster_key: cluster_key, terminal_reason: None,
            matched_buckets: matched_buckets}

if floor:                                       # NO bucket matched but a floor fires
    fb = floor[0]
    return {priority_score: floor_weight,
            priority_reason: f"gf:{fb}",
            cluster_key: f"gf:{fb}",            # gf:<floor_bucket>, NOT path:* (override #4)
            terminal_reason: None,
            matched_buckets: [fb]}

# else: existing path:* fallback, but built from normalize_path_for_cluster (§5)
return {priority_score: 0, priority_reason: None,
        cluster_key: f"path:{normalize_path_for_cluster(url_path)}",
        terminal_reason: None, matched_buckets: []}
```

**Invariants this encodes:**
- `score = max(floor, match)` — a floor never reduces a bucket-driven score (matrix T7).
- When a bucket matched, the cluster key is still the bucket winner (the floor only raises
  the *number*); the floor's bucket name is NOT injected into the reason chain when a real
  match exists (matrix T7). Rationale: specialist routing follows `cluster_key`; the
  bucket match is the more specific signal.
- When NO bucket matched but a floor fires, `cluster_key = gf:<floor_bucket>` and
  `priority_reason = gf:<floor_bucket>` and `matched_buckets = [<floor_bucket>]` so
  `fetch-by-priority` / the 2b coverage bridge route it (matrix T1–T6).
- Inert/sourcemap/host_root early-returns are evaluated BEFORE the floor and are unaffected
  (matrix T8, T9, T10).

---

## 3. Regex-fragment mechanism  (override #1) — CHOSEN DESIGN

**Decision: extend the `_BUCKETS` tuple with a 5th field `regex_fragments`.**

Rationale over a separate `_REGEX_BUCKET_RULES` list: keeping regex buckets inside
`_BUCKETS` preserves a SINGLE declaration-ordered iteration in `bucket_matches`, so
tie-break order (rule 0.3) and reason-chain order (rule 0.4) stay defined by one list. A
side list would need a second merge step with its own ordering contract — more drift
surface. The 5th field defaults to `()` for every non-regex bucket, so existing tuples
gain one trailing element only.

### 3.1 Tuple shape (new)

```
_BUCKETS: tuple[tuple[str, int, frozenset[str], tuple[str, ...], tuple[str, ...]], ...]
#                  name  weight key_set         path_fragments    regex_fragments
```

Every existing tuple gains a trailing `()`. The two derived constants that unpack `_BUCKETS`
(`_IDOR_WEIGHT`, `_INTERESTINGEXT_WEIGHT`) currently use `for name, weight, _, _ in _BUCKETS`
— these MUST be updated to `for name, weight, _, _, _ in _BUCKETS` (5-tuple unpack) or the
module will raise `ValueError` at import. This is a required companion edit.

### 3.2 `regex_fragments` semantics

Each entry is a **raw regex string** compiled (cached) and `.search()`-ed against
`url_path_lower`. The pattern is NOT boundary-wrapped by the helper (unlike literal
fragments) — the pattern author supplies its own anchoring. A precompiled cache mirrors
`_fragment_pattern_cache`:

```
_regex_fragment_cache: dict[str, re.Pattern[str]] = {}

def regex_fragment_in_path(pattern: str, url_path_lower: str) -> bool:
    rx = _regex_fragment_cache.get(pattern)
    if rx is None:
        rx = re.compile(pattern)
        _regex_fragment_cache[pattern] = rx
    return rx.search(url_path_lower) is not None
```

### 3.3 `bucket_matches` consumes it (EXACT)

```
for name, weight, key_set, path_fragments, regex_fragments in _BUCKETS:
    key_hit  = bool(keys & key_set) if key_set else False
    path_hit = any(fragment_in_path(f, url_path_lower) for f in path_fragments)
    rx_hit   = any(regex_fragment_in_path(r, url_path_lower) for r in regex_fragments)
    if key_hit or path_hit or rx_hit:
        matches.append((name, weight))
```

### 3.4 `api-versioning` regex (the only regex bucket in this round)

```
regex_fragments = (r"/v[0-9]+(?=[/?#]|$)",)
```

- Matches a path segment that is `v` + one-or-more digits, bounded by `/`, `?`, `#`, or
  end-of-string.
- **MUST score (weight 25):** `/v1/`, `/v2/`, `/v3` (bare), `/dhrp/rns/v3/actions`,
  `/person/prefs/api/v1/`, `/api/v2/users`, `/v4/dcs/device`.
- **MUST NOT score:** `/version/1.0` (segment is `version`, not `v<digits>`),
  `/validate/endpoint` (no `v<digits>` segment), `/v/1` (segment is `v` with no digits),
  `/vue/app` (segment `vue` is not `v`+digits), `/v1beta/x` (segment `v1beta` ≠ `v1` at a
  boundary — the `(?=[/?#]|$)` lookahead rejects `beta` following the digits).

> Note on `/api/v2/...`: this fires BOTH `api-versioning` (regex, 25) and — if it also
> contains an `/apexrest/`-style fragment — `api` (20). Generic `/api/v2/...` without
> apexrest fires `api-versioning` only among these two (the `api` bucket no longer carries
> a bare `/api/` fragment — see §6.3). The `api_route` TYPE FLOOR is what guarantees a
> params-less, version-less `/api/...` still scores 20.

---

## 4. `_PATH_OBJECT_REF_SEGMENT` redesign  (overrides #5)

Runs on the **raw lowercased url path only** (never normalized — override #6). Appends
`("idor", _IDOR_WEIGHT)` iff no `idor` already in `matches` (unchanged dedupe rule 0.2).

### 4.1 What counts as an object-ref segment

A path segment is an object-ref candidate if it is one of:

1. **UUID** canonical: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
2. **Long hex** (Mongo ObjectId / SHA prefix): `[0-9a-f]{24,}`
3. **Numeric**, with precision predicates (§4.2): `[0-9]+`
4. **Literal placeholder tokens** (override #5 — pre-normalized templates):
   `{id}`, `{uuid}`, `{n}` (case-insensitive on the word; braces literal)

### 4.2 Precision predicates for the numeric arm

A numeric segment `N` is an object ref **only if ALL** hold:

- **Year exclusion:** `N` is NOT a 4-digit year in `1900..2099`
  (regex guard `^(?:19|20)[0-9]{2}$` → reject).
- **Small-int exclusion:** `N` is NOT a bare 1-digit integer `1..9` (pagination/`/1/`).
  (2-digit and up numerics pass this gate; 5+ digit numbers always pass — override #5
  "keep 5+ digit numbers".)
- **Collection-noun gate (ALLOWS short prefixes — override #5):** the object-ref segment
  must be preceded somewhere earlier in the path by at least one **collection-context
  segment**. A collection-context segment is any path segment that is itself NOT an
  object-ref candidate (i.e. a non-numeric, non-uuid, non-hex, non-placeholder word) and is
  **≥ 2 chars** — explicitly INCLUDING short prefixes like `efi`, `v2`, `wps`, `um`, `api`.
  The gate does NOT require a 4+ char "real word" collection noun. It only requires that the
  id is not the sole/leading meaningful segment of the path.

> The collection-noun gate's job is solely to reject a LONE id with no context
> (`/2024/`, `/{n}/`, `/12345`) while ACCEPTING real short-prefixed IDOR
> (`/efi/{id}`, `/v2/{id}`, `/wps/{id}`, `/api/users/1024/profile`). A segment counts as
> "context" even if it is a 2–3 char prefix; it must merely be a word, not itself an id.

### 4.3 Placeholder arm (`{id}`/`{uuid}`/`{n}`)

The placeholder tokens are object-ref candidates that **bypass the numeric precision
predicates** (they carry no year/small-int ambiguity) but STILL require the collection-noun
gate (override #5: "a lone `/{n}/` with no collection context must NOT match"). So:
- `/user/{id}` → matches (`user` is context).
- `/{id}/reports/{id}` → matches (the SECOND `{id}` is preceded by context `reports`; and
  the first `{id}` is preceded by … nothing, but the path as a whole contains a context
  segment `reports` before the second id, so the rule fires once). Matching is evaluated as
  "exists an object-ref segment that has at least one preceding context segment in the same
  path". `/{id}/reports/{id}` satisfies it via the trailing `{id}` after `reports`.
- `/{n}/` (lone) → does NOT match (no context segment anywhere).
- `/2024/` (lone year) → does NOT match (year excluded AND no context).

### 4.4 Accept / reject examples (these become matrix rows I1–I12)

| raw url_path | object-ref? | reason |
|--------------|:-----------:|--------|
| `/api/users/1024/profile` | ACCEPT | `1024` numeric, ≥2 digits, context `users`/`api` |
| `/files/550e8400-e29b-41d4-a716-446655440000` | ACCEPT | UUID arm; context `files` |
| `/orders/000000000000000000001000` | ACCEPT | long-hex arm (24+ hex); context `orders` |
| `/efi/{id}` | ACCEPT | placeholder; short prefix `efi` allowed as context |
| `/v2/{id}` | ACCEPT | placeholder; short prefix `v2` allowed as context |
| `/wps/{id}` | ACCEPT | placeholder; short prefix `wps` allowed as context |
| `/user/{id}` | ACCEPT | placeholder; context `user` |
| `/{id}/reports/{id}` | ACCEPT | trailing `{id}` after context `reports` |
| `/2024/` | REJECT | 4-digit year excluded AND no context |
| `/{n}/` | REJECT | lone placeholder, no context segment |
| `/page/2` | REJECT | `2` is bare 1-digit small-int (pagination) |
| `/about/company/history` | REJECT | no numeric/uuid/hex/placeholder segment |

> Override #5 closing clause: ALL of §4 matching runs on the RAW url only. Normalization
> (§5) is NEVER consulted here.

---

## 5. `normalize_path_for_cluster`  (override #6)

A new pure function used **only** to build the `path:*` fallback cluster key (it replaces
the call to `first_two_path_segments` in the final fallback branch). It is NEVER used in
bucket matching or in `_PATH_OBJECT_REF_SEGMENT` (override #6).

### 5.1 Substitution order (EXACT — apply per segment, then take first two segments)

Operate on `url_path` (original case for token detection, but emit lowercase-stable
placeholders). For each `/`-delimited segment, in this precedence (first match wins per
segment):

1. **UUID** `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` → `{uuid}`
2. **Long hex** `^[0-9a-f]{24,}$` → `{id}`
3. **Year** `^(?:19|20)[0-9]{2}$` → `{year}`
   (year is collapsed too, so `/explore-mvps/2024/M0004` and `/explore-mvps/2023/G0058`
   share a cluster — override #6 names this exact pair)
4. **Numeric** `^[0-9]+$` → `{n}`
5. **Opaque app token** `^[A-Za-z][0-9A-Za-z]*[0-9][0-9A-Za-z]*$` with length ≥ 5 AND
   containing at least one digit AND at least one letter (e.g. `M0004`, `G0058`) → `{token}`
6. otherwise: the segment is left as-is (lowercased for cluster stability)

After substitution, **collapse runs of identical adjacent placeholders** among
`{id}`/`{n}`/`{uuid}`/`{token}`/`{year}` to a single placeholder, THEN take the first two
segments (the existing `first_two_path_segments` two-segment rule) and join with `/`.

### 5.2 Worked examples (matrix rows N1–N4)

| url_path | normalized cluster_key |
|----------|------------------------|
| `/explore-mvps/2024/M0004` | `path:/explore-mvps/{year}` |
| `/explore-mvps/2023/G0058` | `path:/explore-mvps/{year}` (same cluster as above) |
| `/myportal/portalselfservice/abc123def/api/...` (opaque id seg) | `path:/myportal/portalselfservice` |
| `/about/company/history` | `path:/about/company` (no id-shaped segments) |

> The fallback only fires when NO bucket matched AND no floor fired. So normalization only
> affects rows that would otherwise be `path:*` at priority 0. Existing test
> `test_classify_non_object_path_is_not_idor` expects `path:/about/company` for
> `/about/company/history` — §5 preserves that (no id segments → unchanged). Existing
> `test_classify_work_path_fallback` (`/about/company/history` → `path:/about/company`) is
> likewise preserved.

---

## 6. Bucket definitions (every bucket: name, weight, key set, literal fragments, regex)

Existing buckets not listed here (`rce`, `sqli`, `lfi`, `img_traversal`, `idor`,
`redirect`, `ssti`, `cors`, `xss`, `interestingparams`, `interestingext`) are
**UNCHANGED** in weight, key set, and fragments — they only gain a trailing `()`
`regex_fragments` field. `ssrf` changes only its key set (§7).

### 6.1 `graphql` — weight 45
- key set: `{query, mutation, subscription, operationname, variables}`
  (lowercased; `collect_keys` lowercases keys so `operationName` → `operationname`)
- path_fragments: `("/graphql", "/graphiql", "/graphql/v1", "/graphql/v2",
  "/api/graphql", "/gql")`
  — **NOTE:** `/query` from plan 4b is DROPPED. `query` is already an `xss`/`sqli` PARAM
  key; a `/query` PATH fragment would mis-bucket REST `/query` search routes as graphql at
  weight 45. Use the param key `query` (already present here) instead. This is a soundness
  tightening of plan 4b.
- regex_fragments: `()`

### 6.2 `auth` — weight 40  (override #8: compound, no bare `/verify`)
- key set: `{username, password, mfa_code, otp, totp}`
  — **NOTE:** `email` is DROPPED from the auth key set (plan 4b listed it): `email` is
  already an `idor`/`interestingext`-adjacent generic key and a bare `email=` query param
  is not an auth-entry signal. `token` is DROPPED here too (it lives in `jwt` /
  `interestingparams`; keeping it in `auth` would double-fire on every `?token=`).
- path_fragments (compound only — override #8):
  `("/login", "/signin", "/sign-in", "/signon", "/sign-on", "/logout", "/sign-out",
    "/mfa", "/2fa", "/totp", "/otp", "/authenticate", "/auth/login", "/auth/signin",
    "/auth/verify", "/email/verify", "/saml/acs", "/saml/sso")`
  — **`/verify` (bare) is EXCLUDED** (captcha/verify FP, override #8). Only the compound
  `/auth/verify` and `/email/verify` are allowed.
  — `/saml` (bare) is owned by the `sso` bucket (§6.11); `auth` only carries the compound
  `/saml/acs` and `/saml/sso` (these co-fire `sso` too; both at 35/40 respectively —
  `auth` at 40 wins the cluster).
- regex_fragments: `()`

### 6.3 `api` — weight 20  (path-only, NARROWED — override #9 regression firewall)
- key set: `frozenset()` (path-only, per plan 4b)
- path_fragments: `("/rest/", "/rest/v", "/services/apexrest/", "/apexrest/")`
  — **Bare `/api/` and `/api/v` are DELIBERATELY OMITTED.** Reason: a bare `/api/`
  fragment fires on `/api/users/avatar` and appends `gf:api` to the reason chain, breaking
  the EXACT-string assertion in `test_upload_rows_prefer_upload_fields_over_generic_lfi`
  (`row[2] == "gf:lfi+gf:upload_fields"`). The generic params-less `/api/...` rescue is
  delivered by the **`api_route` TYPE FLOOR (§2, weight 20)** instead — which is the
  semantically correct home (plan 4b itself frames weight-20 api as a floor for
  params-less routes). `/api/v<n>/` is covered by the `api-versioning` regex bucket (§3.4).
- regex_fragments: `()`

> This is the single most important reconciliation: **plan 4b's `/api/` path fragment is
> replaced by the `api_route` type-floor** to honour override #9. See §10.

### 6.4 `api-versioning` — weight 25  (regex bucket — §3.4)
- key set: `frozenset()`
- path_fragments: `()`
- regex_fragments: `(r"/v[0-9]+(?=[/?#]|$)",)`

### 6.5 `oauth-oidc` — weight 35
- key set: `{client_id, redirect_uri, response_type, scope, state, nonce,
  code_challenge, grant_type}`
- path_fragments: `("/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server", "/oauth2/", "/oidc/",
  "/connect/authorize", "/connect/token", "/connect/userinfo",
  "/jwks.json", "/.well-known/jwks.json")`
  — boundary-anchored as usual; the trailing-`/` rule applies to `/oauth2/`, `/oidc/`.
- regex_fragments: `()`

### 6.6 `object-storage` — weight 25  (Domino + cloud only — override #2)
- key set: `{bucket, blob, prefix}`
  — **NOTE:** `key` and `object` from plan 4b are DROPPED (`key`/`object` are far too
  generic as param names and would flood). Keep only `bucket`/`blob`/`prefix`.
- path_fragments (Domino discriminators + cloud — override #2):
  `("$file", ".nsf", "files.nsf", "docscat", "didc", "/s3/", "/gcs/", "/blob/",
    "/bucket/")`
  — fragments are matched lowercased (the path is lowercased before matching), so `$FILE`,
  `.NSF`, `DocsCat`, `DIDC` all hit via their lowercased forms. `$file` and `.nsf` are
  matched as boundary-anchored literal fragments (the `$` and `.` are `re.escape`-d).
  — **NEVER a bare `/files/` or `/storage/` fragment** (override #2): `/files/document.pdf`
  and `/static/files/logo.png` MUST NOT match.
- regex_fragments: `()`
- MUST match: `/foo.nsf/view/$FILE/123/doc.pdf`, `/db.nsf/files`, `/s3/bucket/key`,
  `/app/docscat/list`, `/didc/render`.
- MUST NOT match: `/files/document.pdf`, `/static/files/logo.png`, `/storage/img.png`.

> `.nsf` boundary anchoring: `fragment_in_path(".nsf", "/foo.nsf/view")` → core `.nsf`,
> escaped to `\.nsf`, then `(?=[/?#=&]|$)`. `/foo.nsf/view` contains `.nsf` followed by `/`
> → matches. `/notes.nsfx` would NOT match (`x` is not a boundary). Good.

### 6.7 `deserialization` — weight 40  (Siteforce path-prefix + ViewState param)
- key set: `{data, payload, blob, object, serialized, viewstate, __viewstate}`
  (lowercased; `viewState`→`viewstate`, `__VIEWSTATE`→`__viewstate`)
- path_fragments: `("/deserialize", "/marshal", "/unmarshal", "/pickle",
  "/java-serial", "/sfsites/")`
  — `/sfsites/` is the Siteforce loader-state PATH PREFIX (override roster: "Siteforce
  /sfsites/ path-prefix"). So `/sfsites/l/<encoded-json>/bootstrap.js` matches
  deserialization at 40 even though it ends `.js`.
  — **Ordinary `.js` MUST stay low** (roster requirement): a plain `/static/app.js` has no
  `/sfsites/` prefix and no deserial param → does NOT match deserialization. (`.js` is not
  even an `interestingext`; it falls to the path fallback / its producer type.)
- regex_fragments: `()`
- MUST match: `/sfsites/l/eyJ.../bootstrap.js`; any path with `?__VIEWSTATE=...` or
  `viewState` body key.
- MUST NOT match: `/static/app.js`, `/assets/vendor.js`.

### 6.8 `websocket` — weight 30
- key set: `{channel, room, topic}`
- path_fragments: `("/ws", "/wss", "/websocket", "/socket.io", "/sockjs", "/stomp",
  "/mqtt")`
  — `/ws` is boundary-anchored, so `/ws`, `/ws/feed`, `/api/ws?x=1` match but `/wsdl` and
  `/wsus` do NOT (the `d`/`u` is not a boundary). This is the existing `fragment_in_path`
  guarantee — verified by analogy to the `/admin` vs `/administration` test.
- regex_fragments: `()`

### 6.9 `webhook` — weight 30
- key set: `{endpoint, target}`
  — **NOTE:** `url` from plan 4b is DROPPED from the webhook key set: `url` is the primary
  `ssrf`/`redirect` key; adding it to `webhook` (weight 30) creates a third firing on every
  `?url=` with no added routing value (ssrf at 40 already wins). Keep `endpoint`/`target`.
- path_fragments: `("/webhook", "/webhooks", "/hook", "/hooks", "/notify", "/event",
  "/events")`
  — **NOTE:** `/callback` is OMITTED from `webhook` (it already lives in `trust_surface`).
  `webhook` is additive to `trust_surface`, not a duplicate of its `/callback`.
- regex_fragments: `()`

### 6.10 `jwt` — weight 30
- key set: `{access_token, refresh_token, id_token, jwt, bearer}`
  — **NOTE:** bare `token` is DROPPED from the jwt key set (override #8: jwt overlaps
  trust_surface/`token`; keep it "low incremental" and avoid double-firing on every
  `?token=`). `interestingparams` already carries `token`.
- path_fragments: `("/jwt", "/bearer", "/refresh-token")`
  — **NOTE:** bare `/token` is OMITTED (already in `trust_surface`; override #8 keeps jwt a
  low-incremental secondary reason, not a re-fire of `/token`).
- regex_fragments: `()`

### 6.11 `sso` — weight 35
- key set: `{samlresponse, samlrequest, relaystate, wctx, wresult}`
  (lowercased; `SAMLResponse`→`samlresponse`, etc.)
- path_fragments: `("/sso/", "/sso", "/saml", "/saml2", "/cas/", "/adfs/", "/fed/",
  "/sts/")`
  — `/saml` boundary-anchored covers `/saml`, `/saml/acs`, `/saml/sso`, `/saml2`? No:
  `/saml2` — core `/saml` + boundary `(?=[/?#=&]|$)`; the char after `/saml` is `2`, not a
  boundary → `/saml2` does NOT match the `/saml` fragment. So `/saml2` is listed
  separately. `/saml/acs` matches `/saml` (next char `/`).
  — `/sso` and `/sso/` both listed so `/sso` (bare) and `/sso/login` both match.
- regex_fragments: `()`

### 6.12 `file-upload` — weight 35  (REPLACES `upload_fields`)

The bucket previously named `upload_fields` (weight 30) is **renamed to `file-upload` and
raised to weight 35** (roster: "raise existing upload_fields to 35 + add REST fragments").
Param keys are the union of the old set plus the additions; new REST path fragments are
added (the old bucket was param-only).

- key set: `{file, filename, upload, attachment, avatar, image, photo, document, media,
  content_type, mime_type, multipart}`
  (the original 9 keys + `content_type, mime_type, multipart` from plan 4b)
- path_fragments: `("/attachments", "/upload-file", "/file-upload", "/attach",
  "/media-upload")`
- regex_fragments: `()`

> **CRITICAL COMPATIBILITY RULE (regression firewall — §10):** the existing test
> `test_upload_rows_prefer_upload_fields_over_generic_lfi` asserts EXACTLY:
> `cluster_key == "gf:upload_fields"`, `priority_score == 40`, and
> `priority_reason == "gf:lfi+gf:upload_fields"`. Because the bucket is renamed to
> `file-upload` and reweighted to 35, a naive rename would change all three. The spec
> therefore **does NOT rename the bucket token** — it keeps the bucket NAME `upload_fields`
> in `_BUCKETS` (so `gf:upload_fields` and the reason string are preserved) and the
> `select_cluster_bucket` override keeps referencing `upload_fields`, BUT raises the weight
> path differently. See the resolution in §10.2 — the chosen, test-safe design keeps the
> bucket literally named `upload_fields` and KEEPS its weight at 30, delivering the
> "weight 35 file-upload" intent via the **`file-upload` REST fragments being added to the
> SAME `upload_fields` bucket** and via the type floors, NOT via a weight bump that breaks
> the pinned `priority_score == 40` / `== 35` arithmetic. The roster's "raise to 35" is
> explicitly overridden by override #9 (no regression) where they conflict.

#### 6.12.1 Resolution (authoritative, supersedes the roster's "weight 35")

- Bucket token stays `upload_fields` (NOT renamed). `gf:upload_fields` cluster key
  preserved. `GF_BUCKET_TO_CLASS["upload_fields"] = "file-upload"` already maps it to the
  correct class (no taxonomy edit needed for the rename).
- Weight stays **30** (NOT 35) — this preserves the pinned arithmetic in the existing test
  (`/api/users/avatar`: lfi 40 + upload_fields 30 → best 40, override → cluster
  `gf:upload_fields`, reason `gf:lfi+gf:upload_fields`, score 40).
- The REST path fragments `("/attachments", "/upload-file", "/file-upload", "/attach",
  "/media-upload")` and the three new keys `content_type, mime_type, multipart` ARE added
  to the `upload_fields` bucket (this is the real recall win — `/api/.../{id}/attachments`
  now scores 30 with no param).
- The `_UPLOAD_GENERIC_SHADOWS` override in `select_cluster_bucket` is unchanged; it still
  references `"upload_fields"`.

> Net: the 13th roster item ("file-upload weight 35 + REST fragments") is delivered as
> "upload_fields keeps name+weight 30, gains REST fragments + 3 keys" because override #9
> (no regression / pinned test arithmetic) WINS over the roster's weight number. The
> `auth_entry`/`form`/`portal_session` floors already give upload-adjacent auth surfaces
> their lift; file-upload's own recall comes from the new fragments, not the weight bump.

### 6.13 `debug_logic` — weight 30 (EXTENDED fragments — override #3)

Keep ALL existing fragments. ADD only compound/specific fragments (override #3):

- existing (unchanged): `("/admin", "/debug", "/dbg", "/dev", "/staging", "/stage",
  "/test", "/internal", "/mgmt", "/manage", "/console", "/dashboard", "/_profiler",
  "/phpinfo", "/actuator", "/.git", "/.env", "/config", "/backup")`
- ADD: `("/healthz", "/readyz", "/server-status", "/server-info", "/package.json",
  "/actuator/health", "/actuator/env", "/actuator/mappings", "/actuator/metrics",
  "/actuator/beans", "/prometheus")`
- **DO NOT ADD** (override #3 — these flood content corpora): bare `/health`, `/info`,
  `/status`, `/version`, `/metrics`, `/env`, `/spring`, `/_debug`, `/actuator/info`.
  (Plan 4b listed these; override #3 forbids them.)
- MUST score: `/healthz`, `/actuator/env`, `/package.json`, `/server-status`.
- MUST score 0 (path fallback): `/health-benefits/coverage` (`/health` is not even a
  fragment now, and `/healthz` ≠ `/health-benefits`), `/version/notes`, `/info/about`.
- regex_fragments: `()`

> `/actuator` (bare, existing) still matches `/actuator/health` etc. via boundary anchoring,
> so the explicit `/actuator/env` additions are belt-and-suspenders but harmless and make
> the reason chain explicit for sub-path-only deployments. They are listed because the
> roster/override #3 enumerates them explicitly.

---

## 7. ssrf → redirect key move  (override #7)

Move these SIX keys OUT of the `ssrf` key set (keep them in `redirect`, where they already
are): `redirect`, `callback`, `continue`, `next`, `link`, `dest`.

- **New `ssrf` key set:** `{url, uri, host, port, feed, window}`
  (was `{url, uri, host, port, redirect, feed, callback, continue, next, window, link, dest}`).
- `ssrf` still fires on those six keys ONLY via co-firing path fragments `/proxy/`,
  `/fetch/` (unchanged ssrf path fragments) — i.e. a `/proxy/?next=` is ssrf because the
  PATH matches, not the param.
- `redirect` key set is UNCHANGED (it already contains `redirect, return, returnto,
  return_to, next, redir, forward, continue, url, rurl, u, target, dest, destination,
  redirect_uri, go`). Note `redirect` already has `url` — that is intentional and unchanged.

Behavioural assertions (matrix S1–S3):
- `/login?next=/x` → `next` no longer in ssrf; `next` IS in redirect (25). No ssrf path
  fragment. **Also** `/login` fires `auth` (40). So matches = auth(40) + redirect(25).
  Cluster = `gf:auth` (40 > 25). **But override #7's headline example says
  `/login?next=/x → gf:redirect`.** Reconciliation: override #7 predates the `auth` bucket
  in the same batch; with `auth` present, `/login` is an auth-entry (the stronger signal)
  and `next` is the open-redirect param. The cluster is `gf:auth`; `gf:redirect` is in the
  reason chain. The NON-NEGOTIABLE part of override #7 is "`next` is NOT ssrf" — that holds
  (no `gf:ssrf` anywhere). The matrix encodes `cluster_key == "gf:auth"`,
  `priority_reason` contains `gf:redirect` and does NOT contain `gf:ssrf` (row S1).
- `/somepath?next=/x` (no auth, no proxy) → redirect(25) only → `gf:redirect`,
  no `gf:ssrf` (row S2). This is the pure form of override #7's intent.
- `/proxy/fetch?url=http://169.254.169.254/` → `url` in ssrf (40) + `/proxy/` path (ssrf) +
  `/fetch/` path (ssrf) + `url` in redirect (25). Cluster `gf:ssrf` (row S3).

---

## 8. `select_cluster_bucket` — unchanged

No change. It still upgrades `case_type == "upload"` + winner in
`_UPLOAD_GENERIC_SHADOWS` ({lfi, idor}) + an `upload_fields` match → `upload_fields`.
Because `upload_fields` keeps its name (§6.12.1), this override is untouched.

---

## 9. `matched_buckets` / 2b-bridge contract — unchanged shape

`matched_buckets` remains an order-preserving deduped list of matched bucket names. New
buckets must have a `GF_BUCKET_TO_CLASS` entry (§11) so the 2b coverage bridge can mint a
class-typed coverage-item. The floor-only branch (§2.2) returns
`matched_buckets = [<floor_bucket>]`.

---

## 10. Regression firewall (override #9 — NON-NEGOTIABLE)

These existing tests pin behaviour that new buckets could break. Each is preserved by an
explicit design choice above; restate here so the implementer can self-check.

### 10.1 `test_classify_work_assigns_ssrf_bucket`  (`/api?url=...`)
- Today: ssrf(40)+redirect(25) → `gf:ssrf`. After changes: `url` stays in ssrf; `api`
  bucket no longer has `/api/` fragment → no `gf:api`; no floor (type `api`, not
  `api_route`). Result unchanged: `gf:ssrf`, score ≥40, reason contains `gf:ssrf`. PASS.

### 10.2 `test_upload_rows_prefer_upload_fields_over_generic_lfi`  (`/api/users/avatar`, type `upload`, body `{file}`)
- EXACT pins: `cluster_key == "gf:upload_fields"`, `priority_score == 40`,
  `priority_reason == "gf:lfi+gf:upload_fields"`.
- Design choices that preserve all three:
  - `upload_fields` bucket KEEPS its name and weight 30 (§6.12.1) → reason token stays
    `gf:upload_fields`, override still upgrades cluster to `gf:upload_fields`.
  - `api` bucket has NO `/api/` fragment (§6.3) → no `gf:api` appended → reason chain stays
    exactly `gf:lfi+gf:upload_fields`.
  - `_PATH_OBJECT_REF_SEGMENT`: `/api/users/avatar` has no numeric/uuid/hex/placeholder
    segment → no idor appended.
  - type `upload` is NOT in `_TYPE_FLOOR` → no floor, score stays 40 (the lfi match).
  - `avatar` is NOT in `img_traversal` keys → no img_traversal fire.
  - **Verification of reason order:** declaration order has `lfi`(#5) before `upload_fields`
    (#12), so `gf:lfi+gf:upload_fields` is emitted in that exact order. PASS.

### 10.3 `test_classify_idor_*` (numeric / uuid / workspace) and `test_classify_non_object_path_is_not_idor`
- numeric `/api/users/1024/profile` → idor via path-object-ref (context `users`, `1024`
  ≥2 digits) → `gf:idor`, 35. PASS.
- uuid `/files/550e8400-...` → uuid arm + context `files` → `gf:idor`, 35. **Caution:**
  `object-storage` bucket fragment `.nsf`/`$file` does NOT fire on `/files/...` (override
  #2 forbids a `/files/` fragment) so no competing 25-bucket; idor(35) wins. PASS.
- workspace `/api/list?workspace_id=acme` → `workspace_id` in idor keys → `gf:idor`, 35.
  No `api` fragment match, no floor (type defaults to `api` in the helper, not `api_route`).
  PASS.
- `/about/company/history` → no bucket, no floor → `path:/about/company` (normalization
  leaves it unchanged, §5.2). PASS (`test_classify_non_object_path_is_not_idor` and
  `test_classify_work_path_fallback`).

### 10.4 `test_classify_matched_buckets_multiple` / 2b bridge (`/api/fetch?id=10&url=http://internal/`)
- `id` → idor+sqli; `url` → ssrf+redirect; `/api/fetch` → ssrf `/fetch/` path fragment.
  matched_buckets ⊇ {idor, ssrf} (and sqli, redirect). Tests use membership, not equality.
  `api` bucket no longer fires (`/api/` not a fragment; `/fetch/` is ssrf's). PASS.

### 10.5 `test_db_insert_inline_classifies_unknown_trust_surface` / proxy (`/oauth/callback`, type `unknown`)
- `/oauth` and `/callback` are `trust_surface` fragments (35). New buckets: `oauth-oidc`
  fragments are `/oauth2/`, `/oidc/`, etc. — `/oauth/callback` does NOT contain `/oauth2/`
  (next char after `/oauth` is `/`, and the fragment is `/oauth2/` which requires `2`) →
  oauth-oidc does NOT fire. `webhook`? `/callback` is NOT a webhook fragment (§6.9 omits
  it). So only `trust_surface`(35) fires. Pinned result `(unknown, pending, 35,
  gf:trust_surface, gf:trust_surface)` preserved. **This is why `/callback` was kept out of
  webhook and `/oauth` out of oauth-oidc.** PASS.

### 10.6 `test_fetch_by_priority_auto_routes_by_type` and other dispatch tests
- These insert pre-scored rows directly (no classification). Unaffected. PASS.

### 10.7 `test_s15_*`, `test_s20_*`, `test_classify_work_*`
- sourcemap early-return unchanged (§0.7). `/administration-guide` still falls through
  (`/admin` boundary-anchored; no new fragment matches it; type `unknown`/`page` not in
  floor). `/admin/users` → `gf:debug_logic`. host_root, inert, deterministic re-run all
  unchanged. PASS.

---

## 11. Required companion edit — `vuln_taxonomy.GF_BUCKET_TO_CLASS`

Add entries so new buckets route + survive the taxonomy drift test
(`code/skill/bucket classes ⊆ canonical classes`). All target classes below already exist
in `VULN_CLASSES`:

| bucket | GF_BUCKET_TO_CLASS value |
|--------|--------------------------|
| `graphql` | `graphql-injection` |
| `auth` | `auth-bypass` |
| `api` | `None` (family-level path signal, like `trust_surface`) |
| `api-versioning` | `None` (enumeration signal, no single class) |
| `oauth-oidc` | `oauth` |
| `object-storage` | `info-disclosure` |
| `deserialization` | `deserialization` |
| `websocket` | `websocket` |
| `webhook` | `ssrf` |
| `jwt` | `jwt` |
| `sso` | `saml` |

`upload_fields` keeps its existing `file-upload` mapping (unchanged). The `api_spec` floor
label has no `_BUCKETS` entry and needs no `GF_BUCKET_TO_CLASS` row (it is a cluster label
only); if the drift test enumerates floor labels, map `api_spec → None`.

> This edit is REQUIRED for GREEN (the module imports `vuln_taxonomy` and the drift test
> in `test_vuln_taxonomy.py` will fail otherwise). It is the only file outside
> `classify_buckets.py` the implementer touches in this round, plus the DRIFT.md /
> gf-patterns/*.md docs (convention from DRIFT.md line 30).

---

## 12. CONSOLIDATED TEST MATRIX (the contract)

Notation:
- `params` = query_params unless prefixed `body:` (body_params) — both flow through
  `collect_keys`; use whichever the row exercises.
- `type` = producer `type` passed to `classify_from_fields` / inserted row. Default in the
  test helper is `api`; rows that exercise the floor set it explicitly.
- `score` = `priority_score`. `cluster` = `cluster_key`.
- `reason ⊇ {…}` means `priority_reason` CONTAINS each `gf:x` (membership) — used where
  chain order is not the point. `reason ∌ gf:x` means it MUST NOT contain it.
- `reason ==` pins the EXACT string (chain order matters).
- Where two assertions are listed they are AND-ed.

### 12.1 Type-floor rows (T)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| T1 | `graphql` | `/graphql` | — | 45 | `gf:graphql` | also a `graphql` path fragment → bucket fires; floor==match==45. reason `gf:graphql` |
| T2 | `api_route` | `/api/testplans` | — | 20 | `gf:api` | NO bucket fires (no `/rest/` etc., no regex); floor-only → `gf:api`. reason `gf:api`. matched_buckets `["api"]` |
| T3 | `api_spec` | `/api/swagger.json` | — | 40 | `gf:api_spec` | floor-only label; no bucket; reason `gf:api_spec`; matched_buckets `["api_spec"]` |
| T4 | `auth_entry` | `/efi/account` | — | 40 | `gf:auth` | no auth fragment on `/efi/account`; floor-only → `gf:auth` |
| T5 | `form` | `/contact-us` | — | 30 | `gf:auth` | floor-only; reason `gf:auth` |
| T6 | `portal_session` | `/myportal/home` | — | 35 | `gf:auth` | floor-only; reason `gf:auth` |
| T7 | `event_feed` | `/proxy/fetch` | `url=http://x` | 40 | `gf:ssrf` | bucket ssrf(40) fires; floor(25) does NOT lower; score=max(40,25)=40; cluster `gf:ssrf`; reason ⊇ {gf:ssrf}; reason ∌ duplicate floor token |
| T8 | `image` | `/static/logo.png` | — | 0 | `type:image` | inert early-return wins over any floor; terminal_reason `inert_type` |
| T9 | `sourcemap` | `/static/app.js.map` | — | `_INTERESTINGEXT_WEIGHT` (10) | `gf:interestingext` | sourcemap early-return wins; reason `gf:interestingext` |
| T10 | `host_root` | `/` | — | 0 | `type:host_root` | host_root early-return wins; terminal_reason None; (would-be floor irrelevant) |
| T11 | `debug_config` | `/some/opaque/path` | — | 35 | `gf:debug_logic` | floor-only; reason `gf:debug_logic` |
| T12 | `workflow` | `/wizard/step/two` | — | 30 | `gf:idor` | floor-only; reason `gf:idor` |
| T13 | `unknown` | `/some/plain/route` | — | 0 | `path:/some/plain` | no bucket, NO floor (unknown∉floor) → path fallback |

### 12.2 graphql (G)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| G1 | `api` | `/api/graphql` | — | 45 | `gf:graphql` | path fragment |
| G2 | `api` | `/graphiql` | — | 45 | `gf:graphql` | path fragment |
| G3 | `api` | `/v1/data` | `query=...&variables=...` | 45 | `gf:graphql` | param keys `query`,`variables` fire graphql(45); also api-versioning regex `/v1/`(25). best=45 → `gf:graphql`; reason ⊇ {gf:graphql, gf:api-versioning} |
| G4 | `api` | `/search/query` | — | 0 | `path:/search/query` | `/query` is NOT a graphql PATH fragment (dropped, §6.1); no param; falls through |

### 12.3 auth (A)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| A1 | `api` | `/login` | — | 40 | `gf:auth` | path fragment |
| A2 | `api` | `/efi/signin` | — | 40 | `gf:auth` | `/signin` fragment |
| A3 | `api` | `/auth/verify` | — | 40 | `gf:auth` | compound `/auth/verify` |
| A4 | `api` | `/email/verify` | — | 40 | `gf:auth` | compound `/email/verify` |
| A5 | `api` | `/captcha/verify` | — | 0 | `path:/captcha/verify` | bare `/verify` is NOT a fragment (override #8) → no auth; falls through |
| A6 | `api` | `/mfa` | — | 40 | `gf:auth` | `/mfa` fragment |
| A7 | `api` | `/saml/acs` | — | 40 | `gf:auth` | `/saml/acs` (auth 40) co-fires `sso` (`/saml` 35); best=40 → `gf:auth`; reason ⊇ {gf:auth, gf:sso} |

### 12.4 api / api-versioning (V)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| V1 | `api` | `/v1/` | — | 25 | `gf:api-versioning` | regex `/v[0-9]+/` |
| V2 | `api` | `/dhrp/rns/v3/actions` | — | 25 | `gf:api-versioning` | regex matches nested `/v3/` |
| V3 | `api` | `/person/prefs/api/v1/` | — | 25 | `gf:api-versioning` | regex matches `/v1/` |
| V4 | `api` | `/version/1.0` | — | 0 | `path:/version/1.0` | segment `version` ≠ `v<digits>` → no regex; no floor (type api) |
| V5 | `api` | `/validate/endpoint` | — | 0 | `path:/validate/endpoint` | no `v<digits>` segment |
| V6 | `api` | `/services/apexrest/Foo` | — | 20 | `gf:api` | `/services/apexrest/` fragment fires the `api` bucket |
| V7 | `api` | `/rest/v2/items` | — | 25 | `gf:api-versioning` | both api(`/rest/`,20) and api-versioning(`/v2/`,25) fire; best=25; reason ⊇ {gf:api, gf:api-versioning} |
| V8 | `api` | `/v2/{id}` | — | 35 | `gf:idor` | api-versioning(25) + path-object-ref placeholder `{id}` with context `v2` → idor(35). best=35 → `gf:idor`; reason ⊇ {gf:api-versioning, gf:idor} |

### 12.5 oauth-oidc (O)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| O1 | `api` | `/.well-known/openid-configuration` | — | 35 | `gf:oauth-oidc` | path fragment |
| O2 | `api` | `/connect/token` | — | 35 | `gf:oauth-oidc` | path fragment |
| O3 | `api` | `/oauth2/authorize` | `client_id=x&redirect_uri=y` | 35 | `gf:oauth-oidc` | `/oauth2/` + keys; reason ⊇ {gf:oauth-oidc}; also redirect_uri in redirect(25) → reason ⊇ {gf:redirect} |
| O4 | `unknown` | `/oauth/callback` | — | 35 | `gf:trust_surface` | trust_surface(35) only — oauth-oidc does NOT fire (`/oauth2/`≠`/oauth/`); REGRESSION PIN (§10.5) |

### 12.6 object-storage (B)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| B1 | `api` | `/db.nsf/files` | — | 25 | `gf:object-storage` | `.nsf` Domino fragment |
| B2 | `api` | `/foo.nsf/v/$FILE/123/doc.pdf` | — | 35 | `gf:idor` | `$file`+`.nsf` → object-storage(25); also `123` numeric with context → idor(35). best=35 → `gf:idor`; reason ⊇ {gf:object-storage, gf:idor} |
| B3 | `api` | `/s3/bucket/key` | — | 25 | `gf:object-storage` | `/s3/` cloud fragment |
| B4 | `api` | `/app/docscat/list` | — | 25 | `gf:object-storage` | `docscat` fragment |
| B5 | `api` | `/files/document.pdf` | — | 0 | `path:/files/document.pdf` | NO bare `/files/` fragment (override #2); no id segment; falls through |
| B6 | `api` | `/static/files/logo.png` | — | 0 | `path:/static/files` | override #2 — must NOT match object-storage |

### 12.7 deserialization (D)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| D1 | `api` | `/sfsites/l/eyJtb2RlIjoxfQ/bootstrap.js` | — | 40 | `gf:deserialization` | `/sfsites/` prefix; `.js` does NOT demote it |
| D2 | `api` | `/render` | `__VIEWSTATE=...` | 40 | `gf:deserialization` | `__viewstate` key |
| D3 | `api` | `/static/app.js` | — | 0 | `path:/static/app.js` | ordinary `.js` stays low (roster) — no sfsites, no deserial param |
| D4 | `api` | `/save` | `body:viewState=...` | 40 | `gf:deserialization` | `viewstate` body key |

### 12.8 websocket / webhook / jwt / sso (W)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| W1 | `api` | `/ws/feed` | — | 30 | `gf:websocket` | `/ws` fragment |
| W2 | `api` | `/wsdl` | — | 0 | `path:/wsdl` | `/ws` boundary-anchored → does NOT match `/wsdl` |
| W3 | `api` | `/socket.io/?EIO=4` | — | 30 | `gf:websocket` | `/socket.io` fragment |
| W4 | `api` | `/webhooks` | — | 30 | `gf:webhook` | fragment |
| W5 | `api` | `/notify` | — | 30 | `gf:webhook` | fragment |
| W6 | `api` | `/jwt` | — | 30 | `gf:jwt` | fragment |
| W7 | `api` | `/api/auth/token` | `access_token=...` | 40 | `gf:auth` | `/auth/login`? no — but `access_token` key → jwt(30); `/api/auth/token`: no auth path fragment matches (no `/login` etc.)… see note ⓐ |
| W8 | `api` | `/sso/login` | — | 35 | `gf:sso` | `/sso/` fragment |
| W9 | `api` | `/saml2` | — | 35 | `gf:sso` | `/saml2` fragment (separate from `/saml`) |
| W10 | `api` | `/Login.aspx` | `SAMLResponse=...` | 40 | `gf:auth` | `/login` fragment (auth 40) + `samlresponse` key (sso 35); best 40 → `gf:auth`; reason ⊇ {gf:auth, gf:sso} |

> **Note ⓐ (W7):** `/api/auth/token` — check each fragment: `auth` fragments are
> `/auth/login`,`/auth/signin`,`/auth/verify` (compound) — none match `/api/auth/token`.
> `jwt` path fragments are `/jwt`,`/bearer`,`/refresh-token` — none match `/token` (bare
> `/token` deliberately omitted, §6.10). So the ONLY firing is the `access_token` PARAM key
> → `jwt`(30). Therefore **W7 correct expectation is score 30, cluster `gf:jwt`,
> reason ⊇ {gf:jwt}**. (The `/token` surface is owned by `trust_surface` only when the path
> literally contains `/token`; here it does, so `trust_surface`(35) ALSO fires via its
> `/token` fragment!). Re-evaluate: `/api/auth/token` contains `/token` at a boundary →
> `trust_surface`(35) fires. So matches = trust_surface(35) + jwt(30). best=35 →
> **cluster `gf:trust_surface`, score 35, reason ⊇ {gf:trust_surface, gf:jwt}**. THIS is
> W7's locked expectation (corrects the row above): `score 35, cluster gf:trust_surface,
> reason ⊇ {gf:trust_surface, gf:jwt}`. Override #8's "jwt low incremental, secondary
> reason" is exactly this outcome.

### 12.9 idor path-object-ref precision (I) — from §4.4

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| I1 | `api` | `/api/users/1024/profile` | — | 35 | `gf:idor` | numeric, context |
| I2 | `api` | `/files/550e8400-e29b-41d4-a716-446655440000` | — | 35 | `gf:idor` | uuid arm |
| I3 | `api` | `/orders/000000000000000000001000` | — | 35 | `gf:idor` | long-hex arm |
| I4 | `api` | `/efi/{id}` | — | 35 | `gf:idor` | placeholder, short prefix context |
| I5 | `api` | `/wps/{id}` | — | 35 | `gf:idor` | placeholder, short prefix context |
| I6 | `api` | `/user/{id}` | — | 35 | `gf:idor` | placeholder, context `user` |
| I7 | `api` | `/{id}/reports/{id}` | — | 35 | `gf:idor` | trailing `{id}` after `reports` |
| I8 | `api` | `/2024/` | — | 0 | `path:/{year}` | year excluded + no context (normalized cluster) |
| I9 | `api` | `/{n}/` | — | 0 | `path:/{n}` | lone placeholder, no context |
| I10 | `api` | `/page/2` | — | 0 | `path:/page/2` | small-int `2` excluded (`2` is 1-digit) |
| I11 | `api` | `/about/company/history` | — | 0 | `path:/about/company` | no id-shaped segment (regression pin §10.3) |
| I12 | `api` | `/api/list` | `workspace_id=acme` | 35 | `gf:idor` | param-key idor (regression pin) |

> I8 cluster note: `/2024/` normalizes the lone `2024` year segment to `{year}` →
> `path:/{year}`. If the implementer's `first_two_path_segments` of a single segment yields
> `/{year}`, that is the locked value. (The point under test is score 0 + NOT `gf:idor`;
> the exact normalized fallback string is secondary but specified for determinism.)

### 12.10 normalize_path_for_cluster (N)

| id | type | url_path | score | cluster | assertion |
|----|------|----------|------:|---------|-----------|
| N1 | `unknown` | `/explore-mvps/2024/M0004` | 0 | `path:/explore-mvps/{year}` | year collapsed |
| N2 | `unknown` | `/explore-mvps/2023/G0058` | 0 | `path:/explore-mvps/{year}` | SAME cluster as N1 (override #6) |
| N3 | `unknown` | `/orders/000000000000000000001000/view` | 35 | `gf:idor` | path-object-ref fires (raw url) → NOT a fallback row; proves §4 runs on raw url, not normalized. (Listed to assert normalization does NOT suppress idor.) |
| N4 | `unknown` | `/about/company/history` | 0 | `path:/about/company` | no id segments → unchanged (regression pin) |

### 12.11 ssrf/redirect key move (S) — from §7

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| S1 | `api` | `/login` | `next=/x` | 40 | `gf:auth` | auth(40)+redirect(25); reason ⊇ {gf:auth, gf:redirect}; **reason ∌ gf:ssrf** |
| S2 | `api` | `/account/settings` | `next=/x` | 25 | `gf:redirect` | redirect(25) only; **reason ∌ gf:ssrf** (override #7 core) |
| S3 | `api` | `/proxy/fetch` | `url=http://169.254.169.254/` | 40 | `gf:ssrf` | ssrf via `url` key + `/proxy/`/`/fetch/` path; reason ⊇ {gf:ssrf} |
| S4 | `api` | `/api/fetch` | `callback=https://x` | 0 | `path:/api/fetch` | `callback` removed from ssrf; `callback` is NOT a redirect key either; `/fetch/` IS an ssrf path fragment → ssrf fires on PATH! → re-eval: see note ⓑ |

> **Note ⓑ (S4):** `/api/fetch` contains `/fetch` at end boundary → `/fetch/` ssrf path
> fragment fires → ssrf(40). So S4's locked expectation is **score 40, cluster `gf:ssrf`,
> reason ⊇ {gf:ssrf}** — the ssrf path anchor still catches fetchers even though `callback`
> left the key set. This demonstrates override #7's "ssrf still fires on … the /proxy/
> /fetch/ path fragments". (If the intent were to test a pure non-path redirect-only key,
> use a path with no `/fetch`/`/proxy`, e.g. S2.)

### 12.12 debug_logic extension (DL) — override #3

| id | type | url_path | score | cluster | assertion |
|----|------|----------|------:|---------|-----------|
| DL1 | `api` | `/healthz` | 30 | `gf:debug_logic` | added fragment |
| DL2 | `api` | `/actuator/env` | 30 | `gf:debug_logic` | added (and `/actuator` bare also matches) |
| DL3 | `api` | `/package.json` | 30 | `gf:debug_logic` | added fragment |
| DL4 | `api` | `/server-status` | 30 | `gf:debug_logic` | added fragment |
| DL5 | `api` | `/prometheus` | 30 | `gf:debug_logic` | added fragment |
| DL6 | `api` | `/health-benefits/coverage` | 0 | `path:/health-benefits/coverage` | bare `/health` not a fragment; `/healthz`≠`/health-benefits` → MUST score 0 (override #3) |
| DL7 | `api` | `/info/about` | 0 | `path:/info/about` | bare `/info` not added (override #3) |
| DL8 | `api` | `/version/notes` | 0 | `path:/version/notes` | bare `/version` not added (override #3) |
| DL9 | `api` | `/metrics/raw` | 0 | `path:/metrics/raw` | bare `/metrics` not added (override #3) |

### 12.13 file-upload / upload_fields (U) — §6.12.1

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| U1 | `upload` | `/api/users/avatar` | `body:file=avatar.png` | 40 | `gf:upload_fields` | REGRESSION PIN: reason **==** `gf:lfi+gf:upload_fields` (§10.2) |
| U2 | `api` | `/api/x/attachments` | — | 30 | `gf:upload_fields` | new REST fragment `/attachments` (path-only fire) |
| U3 | `api` | `/file-upload` | — | 30 | `gf:upload_fields` | new REST fragment |
| U4 | `api` | `/submit` | `body:multipart=...&mime_type=image/png` | 30 | `gf:upload_fields` | new keys `multipart`,`mime_type` |

### 12.14 cross-fire / tie-break sanity (X)

| id | type | url_path | params | score | cluster | assertion |
|----|------|----------|--------|------:|---------|-----------|
| X1 | `api` | `/admin/exec/run` | `cmd=id` | 50 | `gf:rce` | rce(50, key `cmd` + `/exec/` path) beats debug_logic(30, `/admin`); reason ⊇ {gf:rce, gf:debug_logic} |
| X2 | `api` | `/graphql/admin` | — | 45 | `gf:graphql` | graphql(45, `/graphql`) beats debug_logic(30, `/admin`); declaration order graphql(#2) before debug_logic(#13) |
| X3 | `api` | `/sso/saml/acs` | `SAMLResponse=x` | 40 | `gf:auth` | auth(40 via `/saml/acs`) > sso(35 via `/sso/`,`/saml`); tie-break N/A (40>35); reason ⊇ {gf:auth, gf:sso} |
| X4 | `api` | `/v1/users/1024` | — | 35 | `gf:idor` | api-versioning(25) + idor(35 via `1024` numeric, context `users`/`v1`); best 35 → `gf:idor` |

**Matrix row count: 93 rows across 14 groups** — T1–T13 = 13, G1–G4 = 4, A1–A7 = 7,
V1–V8 = 8, O1–O4 = 4, B1–B6 = 6, D1–D4 = 4, W1–W10 = 10, I1–I12 = 12, N1–N4 = 4,
S1–S4 = 4, DL1–DL9 = 9, U1–U4 = 4, X1–X4 = 4
(13+4+7+8+4+6+4+10+12+4+4+9+4+4 = **93**), comfortably exceeding the ~70-row floor.

> Every positive bucket has ≥1 positive row and ≥1 negative guard; every soundness
> override has a dedicated row (override #1: V1–V5; #2: B1–B6; #3: DL1–DL9; #4: T1–T13;
> #5/#6: I1–I12, N1–N4; #7: S1–S4; #8: A3–A5, W7; #9: U1, O4, I11, +§10).

---

## 13. Implementer checklist (GREEN)

1. Add 5th tuple field `regex_fragments` to `_BUCKETS`; append `()` to every existing
   tuple; fix the two `for name, weight, _, _ in _BUCKETS` unpacks to 5-tuple.
2. Insert the 13 new/extended buckets at the §1 positions with the §6 definitions.
3. Narrow `ssrf` key set per §7.
4. Add `regex_fragment_in_path` + cache; extend `bucket_matches` per §3.3.
5. Add `_TYPE_FLOOR` (§2.1) and the floor application in `classify_row` (§2.2).
6. Redesign `_PATH_OBJECT_REF_SEGMENT` matching into a predicate function (§4) covering
   numeric precision + placeholder arm + collection-noun gate; keep it on the RAW url.
7. Add `normalize_path_for_cluster` (§5); use it ONLY in the path fallback branch.
8. Add `GF_BUCKET_TO_CLASS` entries (§11) in `vuln_taxonomy.py`.
9. Update DRIFT.md + add/extend gf-patterns/*.md per convention.
10. Run the full §12 matrix + the entire existing `test_work_buffer.py` — all green,
    zero regressions.
</content>
</invoke>
