---
name: idor-testing
description: Insecure direct object reference testing for broken access control
origin: Vigil
---

# IDOR Testing (Insecure Direct Object Reference)

> **`vigil assess kali` audit flags:** use `--technique IDOR` for object-reference probes, `--technique AUTH` for identity/tenant override. `--probe-kind payload` for ID-swap/divergence tests, `--probe-kind exploit` for confirmed cross-user access.

This is the **entry-point skill** for broken object-level authorization. It covers the
full BOLA/IDOR workflow and tells you when to escalate into the specialist skills
(split-brain, BFF override, mass assignment, GraphQL, JWT, cache poisoning).

## When to Activate

- API endpoints reference objects by ID (numeric, UUID, slug)
- User-specific resources accessible via direct reference
- Multi-tenant application with shared API surface

## Tools

- `vigil assess kali exec -- curl ...` for all target-facing requests (mandatory audit pipeline)
- `vigil assess classify-payload <value> --mutations` to type an ID and emit attack variants
- `vigil assess anomaly-score <file.jsonl> --top N` to rank batch-sweep response outliers
- `vigil oob mint` / `vigil oob poll` for blind / side-effect confirmation
- Two or more test accounts (different privilege levels + separate tenants for SaaS)
- Burp Suite Repeater + Autorize / Auth Analyzer / AuthMatrix for differential replay
- Burp Comparer for response diffing

## Methodology

### 1. Map Object References

- [ ] Identify all IDs in URLs: `/api/users/123`, `/orders/456`
- [ ] Identify IDs in request body and query params
- [ ] Identify IDs in headers (custom auth, tenant ID)
- [ ] Note ID formats: numeric, UUID, base64-encoded, hashed
- [ ] Catalog all CRUD operations per object type

### 2. Fingerprint the Identifier Type (Decision Branch)

Before swapping anything, parse the captured ID and branch — the right tactic depends on
the scheme, and so does the eventual VRT severity (iterable IDs score higher):

- **Sequential int** → sweep neighbors/boundaries; mass-harvestable, highest severity.
- **UUID** → read the version nibble (the digit after the 2nd hyphen group):
  - **v1 / v6** are time + MAC derived and therefore *predictable* → timestamp-bracketing /
    "sandwich" attack to reconstruct a victim's GUID.
  - **v4** is random → guessing is hopeless; switch to **harvest-not-guess** (§7).
- **Time-ordered schemes** (UUIDv7, ULID, Snowflake, KSUID, Mongo ObjectId) leak creation
  time → window-bounded enumeration around a known timestamp.

Keep this branch short — the full scheme table, version-nibble cheatsheet, and per-scheme
enumeration recipes live in `agent/references/access-control/idor-identifier-prediction.md`.

### 3. ID Manipulation Techniques

Do not hand-pick the variants. Feed the captured ID to `vigil assess classify-payload`,
which recognises the type (`sequential_id`, `uuid`, `integer`, `base64`, `hex`, ...) and
emits intent-keyed attack variants so you cover neighbor/boundary/escalation/format/empty
systematically:

```bash
# Numeric / auto-increment ID → neighbours, boundaries, escalation IDs, type-confusion
vigil assess classify-payload 1042 --mutations
#   type:  sequential_id
#   neighbor:   '1043' '1041' '1044' '1040' '2084'        ← adjacent objects (horizontal IDOR)
#   boundary:   '0' '-1' '1' '99999999' '2147483647'      ← edge IDs (first record / overflow)
#   escalation: '1' '0' '2' 'admin' 'root'                ← likely-privileged IDs
#   format:     '"1042"' '[1042]' '{"id": 1042}' 'null'   ← type confusion (string/array/object)
#   empty:      '' 'null' 'undefined' ' ' '\x00'

# UUID → increment last group, all-zeros / all-Fs, first-user GUID, case + no-hyphen confusion
vigil assess classify-payload 550e8400-e29b-41d4-a716-446655440000 --mutations --json
```

- [ ] Run `classify-payload --mutations` on each captured ID; fire the `neighbor` and
      `boundary` variants for **horizontal** access (adjacent / first objects) and the
      `escalation` variants (`1`, `0`, `00000000-...-000000000001`, `admin`) for **vertical** access
- [ ] UUID: also try the real UUID of another user's object (obtained via another endpoint) —
      `classify-payload` covers the structural guesses, not values you can only observe
- [ ] Use the `format` variants for type-confusion (int as `"1042"` string / `[1042]` array /
      `{"id":1042}` object) — some authz checks only validate the scalar shape
- [ ] Base64 / hex IDs: `classify-payload` classifies them and the `format`/`boundary` intents
      emit decode-modify-reencode and truncation variants; confirm whether the value is predictable
- [ ] Array injection: `id[]=1&id[]=2` — may return multiple objects
- [ ] Wildcard or special values: `*`, `all`, `null`

### 4. Horizontal Access Testing (Same Role)

- [ ] Create two accounts: User A and User B
- [ ] As User A, access User B's resources by swapping ID
- [ ] Test on GET (read), PUT/PATCH (modify), DELETE (remove)
- [ ] Test POST with another user's parent ID (e.g., create order for User B)
- [ ] Check file/document access: `/files/{fileId}`
- [ ] Check export/download endpoints with swapped IDs

### 5. Vertical Access Testing (Cross Role)

- [ ] As regular user, access admin-only resource IDs
- [ ] Swap user ID to admin ID in requests
- [ ] Test admin actions (delete user, change role) with user token
- [ ] Check if API hides endpoints but doesn't enforce authz on IDs

### 6. Per-Verb Authorization Matrix

Authorization is frequently wired to a single verb. For **every** protected object route,
replay the swapped-ID request across all methods — a GET may be blocked while PUT/PATCH/HEAD
leak or write.

> Real example: `GET /api/v4/user/1` → 403, but `PUT /api/v4/user/1?include=email` → 200
> returning the victim's PII. The write path skipped the read-path authz filter.

```bash
# Replay one victim object ID across every verb; rank what diverges
for m in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  vigil assess kali exec --technique IDOR --probe-kind payload -- \
    curl -s -o /dev/null -w "$m %{http_code} %{size_download}\n" \
    -X "$m" -H "Cookie: session=USER_A_TOKEN" \
    "https://target/api/v4/user/VICTIM_ID?include=email"
done
```

- [ ] Note that `HEAD` often shares GET's handler but skips its authz wrapper
- [ ] `OPTIONS` can leak the allowed verb set (the unprotected one is your candidate)
- [ ] When a verb returns differently, escalate it through §7–§10 with a real victim ID

### 7. Harvest Victim Object IDs (When Guessing Fails)

A random v4 UUID / opaque key does **not** mean "safe — stop." It means *guessing* is dead;
go *harvest* real victim IDs from the application's own over-sharing, then replay them:

- [ ] **Cross-endpoint over-sharing** — list / search / `/me` / dashboard / activity-feed
      responses leak *other* users' IDs in nested fields, author refs, assignee lists
- [ ] **Export / report metadata** — CSV/PDF/XLSX exports embed raw object IDs
- [ ] **GraphQL GID decode** — base64 `gid://platform/Type/123` exposes the underlying int
- [ ] **JWT claims** — decode the token; `sub`, `org_id`, `tenant_id` are object IDs
- [ ] **Autocomplete / mention / typeahead APIs** — `@`-mention and share-dialog endpoints
      enumerate users org-wide
- [ ] **Public/shared links + OSINT** — Wayback, CommonCrawl, URLScan, JS bundles, source maps
      (`.map` files) leak historical IDs and internal route shapes
- [ ] **Activation / bulk-action oracles** — "select all" / bulk-action requests echo every
      object ID in scope
- [ ] **Notification side-channels** — webhooks, emails, in-app notifications carry IDs
- [ ] **404-vs-403 / length / timing oracle** — distinguish "exists but forbidden" from
      "does not exist" to confirm an ID before full enumeration

Then replay each harvested ID through the access tests above. For the *prediction* side
(when IDs are semi-structured), see `agent/references/access-control/idor-identifier-prediction.md`.

### 8. Two-Session Differential Replay (Primitive)

Make this a first-class setup step, not an afterthought. Stand up:

- **Account A** = victim (owns objects)
- **Account B** = attacker at the **same tier** (horizontal) AND a separate run at a **higher
  tier** (vertical)
- **Unauthenticated** context (no session)
- For SaaS, put A and B in **separate tenants/orgs**

Replay every owner request under (a) the other-user session and (b) unauthenticated. This is
the **Burp Autorize / Auth Analyzer / AuthMatrix** model — they automate exactly this replay.

Use **content-length + body-fingerprint** as the oracle, not status code alone.

```bash
# Capture each replayed response as a record, then rank divergence
vigil assess kali exec --technique IDOR --probe-kind payload -- \
  curl -s -o b_resp.json -w '{"url":"%{url_effective}","status":%{http_code},"content_length":%{size_download}}\n' \
  -H "Cookie: session=USER_B_TOKEN" "https://target/api/orders/VICTIM_ORDER_ID" >> replay.jsonl
vigil assess anomaly-score replay.jsonl --top 5
```

**Critical caveat (state this explicitly in findings):** request-level automation can only
*hint* at BOLA. A `200`-vs-`403` or a length delta is a candidate, not a confirmation — the
tool has no object-ownership context. **`404` ≠ safe** (scoping can mask an existing object),
and a matching length can be coincidental. **Always hand-verify that the returned data actually
belongs to the other account** (names, emails, order contents) before reporting.

### 9. 403 → IDOR Bypass Ladder

When a straight ID swap returns `401/403/404`, do not abandon — escalate systematically. These
variants frequently pass a scalar-shape validator at the edge but reach the data layer intact.
Cross-ref `agent/references/api-security/API01-broken-object-level-authz.md`.

- [ ] **JSON type-confusion on the ID:** `[1234,1235]` array · `true` · `*` / `%` wildcard ·
      `00001235` zero-pad · `-1` · `1235.0` float · `"1234,1235"` CSV-string
- [ ] **Object / array wrapping:** `{"id":1234}` · `[1234]` · nested `[[1234]]` ·
      `{"id":{"id":1234}}`
- [ ] **Path mangling:** `%00` null byte · `/own/../victim/` traversal · trailing `;` or `.json` ·
      wildcard segment `/workspaces/*/users`
- [ ] **Content-Type swap:** json ↔ form-encoded ↔ xml (different binders, different authz)
- [ ] **Version-prefix swap:** `/v1/` vs `/v2/` (older/newer route may lack the check)
- [ ] **Case + trailing-slash:** `/API/Users/123`, `/api/users/123/`

```bash
# Type-confusion / wrapping sweep on a blocked ID
for body in '1235' '[1234,1235]' 'true' '{"id":1235}' '[1235]' '"1234,1235"' '00001235' '1235.0'; do
  vigil assess kali exec --technique IDOR --probe-kind payload -- \
    curl -s -o /dev/null -w "$body -> %{http_code} %{size_download}\n" \
    -X PATCH -H "Cookie: session=USER_A_TOKEN" -H "Content-Type: application/json" \
    -d "{\"id\":$body}" "https://target/api/orders"
done
```

### 10. Split-Brain IDOR (Body/Route Divergence)

The server validates authorization against the URL ID but operates on the body ID. This
bypasses standard IDOR protections where ownership is checked on the route param.

- [ ] On PUT/PATCH: send request with YOUR ID in the URL + VICTIM's ID in the body
  ```
  PUT /api/orders/MY_ORDER_ID
  {"_id": "VICTIM_ORDER_ID", "status": "cancelled"}
  ```
- [ ] Test all body ID field names: `_id`, `id`, `objectId`, `orderId`, `userId`, `documentId`
- [ ] Verify which ID the server actually used: read the object back and check which one changed
- [ ] Test nested object IDs: `{"items": [{"_id": "VICTIM_ITEM"}]}`
- [ ] Test bulk endpoints: `{"ids": ["MY_ID", "VICTIM_ID"]}`
- [ ] If body ID is normally omitted, test what happens when you ADD it (may override URL routing)

**Confirmation protocol:** (1) baseline with matching URL+body IDs → works, (2) swap body ID to victim → check if victim's object was modified, (3) remove override → confirm reversion.

This is a full specialist workflow — escalate into `agent/skills/split-brain-idor/SKILL.md`
once the basic divergence pattern is confirmed.

### 11. Second-Order / Workflow-Resume & Object-Rebinding

Ownership is often validated at object *creation* but NOT re-checked when a later step resumes,
approves, or schedules it.

- [ ] **Workflow resume:** in create→approve / create→resume / create→schedule flows, store your
      own ID then replay the **later** step against a *foreign* object (the resume handler trusts
      the earlier authz)
- [ ] **Client-supplied scope fields:** always test `owner_id` / `account_id` / `sender` /
      `tenant_id` body fields as authorization-scope inputs — set them to the **victim's** value
- [ ] **Lifecycle replay:** deactivated / archived / dissociated / removed members can often still
      read objects with a previously issued session or token

(Client-supplied scope fields overlap with mass assignment — see §13 cross-reference.)

### 12. Blind IDOR — Confirm via Side Effects

When a write returns no data (empty `204`, generic `200 {}`), do not abandon the finding — prove
cross-object impact out-of-band:

- [ ] Victim receives a **notification / email / state change** triggered by your write
- [ ] **200-vs-error / length / timing oracle** distinguishes "did something" from "no-op"
- [ ] Wire the proof to OOB infra:

```bash
TOKEN=$(vigil oob mint --label idor-blind-write)
# inject the OOB callback where the victim's object would surface it (webhook URL, email, etc.)
vigil oob poll --token "$TOKEN" --timeout 60   # a hit confirms the write reached the victim object
```

### 13. Bulk / Mass Assignment

- [ ] Test listing endpoints without filter: `/api/orders` returns all
- [ ] Remove or blank the user filter parameter
- [ ] GraphQL: query relationships to access other users' nested data

Privileged-field and `owner_id`-rebinding injection is its own specialist workflow —
do not duplicate it here; escalate into `agent/skills/mass-assignment/SKILL.md`.

### 14. Web Cache Deception Delivers IDOR Without the Victim's ID

Confidence: situational. Appending a cacheable suffix to an authed JSON view —
`/account/settings/x.css`, `;x.js`, `%2f..%2f`, `%23.css` — can cause a CDN/proxy to cache the
victim's **personalized** response under a static key that the attacker then fetches
**unauthenticated**. Check `cf-cache-status` / `x-cache: HIT` to confirm the cache landed.
Cross-ref `agent/skills/cache-poisoning/SKILL.md`; the per-architecture cache/IDOR catalog lives
in `agent/references/access-control/idor-modern-architectures.md`.

### 15. Validate Impact

- [ ] Confirm data belongs to another user (check names, emails)
- [ ] Demonstrate modification: change another user's data
- [ ] Demonstrate deletion if safe to do so (staging only)

## What to Record

- Endpoint, HTTP method, and parameter with IDOR
- Auth context (which user token was used) and the verb/variant that worked
- Object accessed/modified and its owner — **hand-verified** as belonging to another account
- Horizontal vs vertical access; cross-tenant if SaaS
- Request/response evidence (redact sensitive data)
- **VRT severity (BugCrowd model — iterability is the multiplier):**
  - iterable + sensitive + **modify** → **P1**
  - **modify** of an *iterable* ID → P2
  - **view** of an *iterable* ID → P3
  - modify/view gated behind a complex GUID/UUID → **P4 (still in scope — report it, not informational)**
  - view of non-sensitive data → P5
- **CWE tag:** default **CWE-639** (authz bypass through user-controlled key); use **CWE-566**
  for the SQL-primary-key variant; **CWE-862** if there is no authz check at all, **CWE-863** if a
  check exists but is wrong; **CWE-602** when enforcement is only client-side. Pillar is CWE-284.
- **Class the finding correctly:** BOLA (OWASP API1) = wrong *object* · BOPLA (API3) = wrong
  *property* · BFLA (API5) = wrong *function* — file it under the right one.
- Remediation: enforce server-side ownership checks tied to session identity; use indirect /
  unpredictable references; re-check authz on every verb and every workflow step.

## Kill Signals — Stop Testing When

- Every verb + every wrapping/type-confusion variant + the unauthenticated and other-user
  differential replays all return identical **owner-scoped** data (you only ever see your own)
- A hard `403` persists where identity is **server-side session-derived** and there is **no
  client-controllable scope field** (no `owner_id`/`tenant_id`/body ID to override)
- IDs are random **v4 UUIDs** AND harvesting (§7) yields no foreign IDs AND no oracle leaks them
- The object truly does not exist (confirmed, not just `404`-masked) across all accounts

## Escalate When

- One ID swap returns **another user's data** → sweep all object types and every endpoint;
  harvest at scale (GraphQL batching / aliasing) and enumerate the population
- The leak is on a profile / settings / reset / password endpoint → chain to **account takeover**
- A write/delete verb succeeds cross-user → demonstrate destructive impact (P1/P2)
- Straight IDOR is blocked but a body ID diverges → escalate to **split-brain-idor**
- A client-supplied identity/scope param changes the response → escalate to
  **bff-parameter-override**
- Privileged fields bind on create/update → escalate to **mass-assignment**

## Extended Resources

This skill is the **entry point**; the following are SEPARATE specialist skills to escalate into
once you have confirmed the matching pattern:

- `agent/skills/split-brain-idor/SKILL.md` — body/route ID divergence (specialist)
- `agent/skills/bff-parameter-override/SKILL.md` — client-supplied identity/scope override (specialist)
- `agent/skills/mass-assignment/SKILL.md` — privileged-field / `owner_id` rebinding (specialist)
- `agent/skills/graphql-testing/SKILL.md` — `node(id)` / batching / GID enumeration (specialist)
- `agent/skills/jwt-testing/SKILL.md` — claim-derived object IDs and identity tampering (specialist)
- `agent/skills/cache-poisoning/SKILL.md` — web cache deception delivering IDOR (specialist)

Reference material (link, don't inline):

- `agent/references/access-control/idor-modern-architectures.md` — GraphQL / JWT / signed-refs /
  cloud / AI-LLM / realtime / mesh / cache IDOR per-architecture probes
- `agent/references/access-control/idor-identifier-prediction.md` — ID-scheme prediction table +
  ID-harvesting techniques
- `agent/references/api-security/API01-broken-object-level-authz.md` — OWASP API Security
  Top 10:2023 BOLA checklist
