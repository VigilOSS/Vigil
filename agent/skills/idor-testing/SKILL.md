---
name: idor-testing
description: Insecure direct object reference testing for broken access control
origin: Vigil
---

# IDOR Testing (Insecure Direct Object Reference)

## When to Activate

- API endpoints reference objects by ID (numeric, UUID, slug)
- User-specific resources accessible via direct reference
- Multi-tenant application with shared API surface

## Tools

- curl with multiple auth tokens
- Burp Suite Repeater + Autorize extension
- Two or more test accounts (different privilege levels)
- Burp Comparer for response diffing

## Methodology

### 1. Map Object References

- [ ] Identify all IDs in URLs: `/api/users/123`, `/orders/456`
- [ ] Identify IDs in request body and query params
- [ ] Identify IDs in headers (custom auth, tenant ID)
- [ ] Note ID formats: numeric, UUID, base64-encoded, hashed
- [ ] Catalog all CRUD operations per object type

### 2. Horizontal Access Testing (Same Role)

- [ ] Create two accounts: User A and User B
- [ ] As User A, access User B's resources by swapping ID
- [ ] Test on GET (read), PUT/PATCH (modify), DELETE (remove)
- [ ] Test POST with another user's parent ID (e.g., create order for User B)
- [ ] Check file/document access: `/files/{fileId}`
- [ ] Check export/download endpoints with swapped IDs

### 3. Vertical Access Testing (Cross Role)

- [ ] As regular user, access admin-only resource IDs
- [ ] Swap user ID to admin ID in requests
- [ ] Test admin actions (delete user, change role) with user token
- [ ] Check if API hides endpoints but doesn't enforce authz on IDs

### 4. ID Manipulation Techniques

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

### 5. Split-Brain IDOR (Body/Route Divergence)

The server validates authorization against the URL ID but operates on the body ID.
This bypasses standard IDOR protections where ownership is checked on the route param.

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

See also: `agent/skills/split-brain-idor/SKILL.md` for the full methodology.

### 6. Bypass Techniques

- [ ] Change HTTP method: GET blocked → try PUT/PATCH/DELETE
- [ ] Add wrapping: `/api/users/me/../123`
- [ ] Parameter pollution: `?id=myId&id=victimId`
- [ ] Case change on endpoints: `/API/Users/123`
- [ ] Version switch: `/v1/users/123` if `/v2/` is protected
- [ ] JSON body vs query param: move ID between locations

### 7. Account Isolation Testing (Shared Platforms)

On shared/SaaS platforms, test whether object IDs are scoped to the current account:

- [ ] Obtain object IDs from a second account instance if available
- [ ] Test REST API with out-of-account IDs — 404 (scoped) vs data returned (leak)
- [ ] Test GraphQL `node(id)` with global IDs (base64 GID format like `gid://platform/Type/ID`) — federated GraphQL often uses globally-routable node IDs
- [ ] Test incremental/bulk export endpoints — do they scope to the current account or return cross-account data?
- [ ] Test header and parameter overrides: `X-Account-Id`, `?account_id=`, `Host` header
- [ ] Test webhook/integration callbacks — does event-triggered execution stay within the correct account's data?
- [ ] Check 404 vs 403 — a 403 on an out-of-account ID confirms the object exists (ID oracle)

When you sweep a *batch* of IDs (a `classify-payload` neighbor set, a `seq` range, or a list of
out-of-account IDs), do not eyeball every response for the one that leaked. Capture each response
as a record (`url`, `status`, `content_length`, optionally `title`/`words`/`lines`) into a JSONL
or JSON-array file and rank the outliers:

```bash
# one {url,status,content_length} object per swept ID → idor_sweep.jsonl, then:
vigil assess anomaly-score idor_sweep.jsonl --top 5
#   #1  score=4.17  status=200  len=1561  url=.../api/users/1   ← the ID that returned a record
#       ^ status='200'  ^ length_bucket='len_512_4096'          while the rest 403/404'd
```

The record that breaks from the population (a `200` among `403`s, a larger body bucket, a
different `title`) is the candidate leak — pull it and confirm the data belongs to another
account. The oracle clusters near-equal sizes into buckets, so it surfaces *category* outliers
(status flip, size-class jump, title change), not sub-bucket byte deltas — for two-response
ownership confirmation use the direct read in §8 below.

### 8. Bulk / Mass Assignment

- [ ] Test listing endpoints without filter: `/api/orders` returns all
- [ ] Remove or blank the user filter parameter
- [ ] GraphQL: query relationships to access other users' nested data

### 8. Validate Impact

- [ ] Confirm data belongs to another user (check names, emails)
- [ ] Demonstrate modification: change another user's data
- [ ] Demonstrate deletion if safe to do so (staging only)

## What to Record

- Endpoint, HTTP method, and parameter with IDOR
- Auth context (which user token was used)
- Object accessed/modified and its owner
- Horizontal vs vertical access
- Request/response evidence (redact sensitive data)
- Severity: High (data access) or Critical (data modification/deletion)
- Remediation: enforce server-side ownership checks, indirect references

## Extended Resources

- `agent/references/api-security/API01-broken-object-level-authz.md` — OWASP API Security Top 10:2023 BOLA checklist
