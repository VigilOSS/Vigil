# API1:2023 — Broken Object Level Authorization

> See also: [A01-broken-access-control](../vuln-checklists/A01-broken-access-control.md) | Skill: `idor-testing`

## REST BOLA/IDOR — CRUD Coverage
- [ ] Test every CRUD endpoint with swapped IDs — map all endpoints accepting object IDs first
- [ ] Test GET with other user's ID: `curl -H "Authorization: Bearer USER_B_TOKEN" https://api/v1/users/USER_A_ID`
- [ ] Test PUT/PATCH with other user's ID: `curl -X PUT -H "Authorization: Bearer USER_B_TOKEN" -d '{"name":"hacked"}' https://api/v1/users/USER_A_ID`
- [ ] Test DELETE with other user's ID: `curl -X DELETE -H "Authorization: Bearer USER_B_TOKEN" https://api/v1/users/USER_A_ID`
- [ ] Test nested resources: `/api/users/VICTIM_ID/orders/ORDER_ID` — both IDs must be validated
- [ ] Test batch/bulk endpoints: `POST /api/users/bulk {"ids": [1, 2, 3]}` — are all IDs authorized?

## ID Prediction & Enumeration
- [ ] Test sequential integer IDs: increment/decrement to find adjacent objects
- [ ] Harvest UUIDs from other API responses (listing endpoints, search results, shared links)
- [ ] Check for UUIDv1 which contains timestamp + MAC — predictable if generation time known
- [ ] Test ID type confusion: send string `"admin"` where numeric ID expected
- [ ] Test negative IDs, zero, `MAX_INT` values

## Parameter Injection for BOLA
- [ ] Test array injection: `?user_id[]=1&user_id[]=2` — returns data for both users?
- [ ] Test comma-separated IDs: `?ids=1,2,3`
- [ ] Test JSON array in body: `{"user_ids": [1, 2, 3]}`
- [ ] Test wildcard or glob patterns if supported: `?id=*`, `?id=1*`

## GraphQL Object Access
- [ ] Query other users' objects via nested resolution:
  ```
  query { user(id: "VICTIM_ID") { email orders { total items { name } } } }
  ```
- [ ] Test mutations with other users' object IDs
- [ ] Test node/relay-style queries: `query { node(id: "base64_VICTIM_ID") { ... on User { email } } }`
- [ ] Exploit relationship traversal: query your own object, then follow relations to others' data

## Tenant Isolation
- [ ] Swap `X-Tenant-ID`, `org_id`, or `workspace_id` headers/parameters between accounts
- [ ] Test if API keys from one tenant can access another tenant's resources
- [ ] Check if tenant context is derived from token vs. user-supplied parameter (latter is exploitable)

## API Versioning Bypass
- [ ] Test older API versions for missing auth checks: `/v1/users/ID` vs `/v2/users/ID`
- [ ] Check if deprecated endpoints still accessible and lack newer security controls

---
> Cross-reference: A01 checklist, `idor-testing` skill
