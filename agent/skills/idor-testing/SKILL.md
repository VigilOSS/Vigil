---
name: idor-testing
description: Insecure direct object reference testing for broken access control
origin: AI Threat Hunting
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

- [ ] Numeric: increment/decrement (`123` → `124`, `122`)
- [ ] UUID: try UUID of another user's object (obtained via other endpoint)
- [ ] Base64: decode, modify, re-encode
- [ ] Hashed/encoded: check if predictable (MD5 of sequential number)
- [ ] Negative or zero IDs: `-1`, `0`
- [ ] Array injection: `id[]=1&id[]=2` — may return multiple objects
- [ ] Wildcard or special values: `*`, `all`, `null`

### 5. Bypass Techniques

- [ ] Change HTTP method: GET blocked → try PUT/PATCH/DELETE
- [ ] Add wrapping: `/api/users/me/../123`
- [ ] Parameter pollution: `?id=myId&id=victimId`
- [ ] Case change on endpoints: `/API/Users/123`
- [ ] Version switch: `/v1/users/123` if `/v2/` is protected
- [ ] JSON body vs query param: move ID between locations

### 6. Account Isolation Testing (Shared Platforms)

On shared/SaaS platforms, test whether object IDs are scoped to the current account:

- [ ] Obtain object IDs from a second account instance if available
- [ ] Test REST API with out-of-account IDs — 404 (scoped) vs data returned (leak)
- [ ] Test GraphQL `node(id)` with global IDs (base64 GID format like `gid://platform/Type/ID`) — federated GraphQL often uses globally-routable node IDs
- [ ] Test incremental/bulk export endpoints — do they scope to the current account or return cross-account data?
- [ ] Test header and parameter overrides: `X-Account-Id`, `?account_id=`, `Host` header
- [ ] Test webhook/integration callbacks — does event-triggered execution stay within the correct account's data?
- [ ] Check 404 vs 403 — a 403 on an out-of-account ID confirms the object exists (ID oracle)

### 7. Bulk / Mass Assignment

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
