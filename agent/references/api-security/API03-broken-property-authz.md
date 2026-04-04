# API3:2023 — Broken Object Property Level Authorization

> See also: [A01-broken-access-control](../vuln-checklists/A01-broken-access-control.md) | Skill: `parameter-fuzzing`

## Mass Assignment — Extra Fields in Write Requests
- [ ] Add `"role": "admin"` to user profile update: `curl -X PUT -d '{"name":"test","role":"admin"}' https://api/users/me`
- [ ] Add `"is_admin": true`, `"is_staff": true`, `"verified": true` to registration/update
- [ ] Add `"permissions": ["*"]` or `"groups": ["admin"]` to user endpoints
- [ ] Add `"price": 0`, `"discount": 100` to order/product endpoints
- [ ] Add `"approved": true`, `"status": "active"` to bypass approval workflows
- [ ] Test with nested objects: `{"profile": {"role": "admin"}}` in case flat-field filtering misses nested
- [ ] Add `"id": 1` or `"user_id": VICTIM_ID` to creation endpoints to hijack ownership

## Excessive Data Exposure in Responses
- [ ] Compare GET response fields with what the UI actually renders — extra fields are exposure
- [ ] Check for password hashes in user object responses: `password_hash`, `encrypted_password`
- [ ] Check for internal IDs, database IDs, or debug fields: `_id`, `internal_id`, `debug_info`
- [ ] Check for PII not needed by the client: SSN, full DOB, phone number in listing endpoints
- [ ] Check for other users' data leaked in shared resource responses
- [ ] Test verbose mode parameters: `?verbose=true`, `?fields=all`, `?include=private`

## GraphQL Field-Level Access
- [ ] Request sensitive fields in GraphQL queries that the UI never requests:
  ```
  query { user(id: "ME") { email password_hash ssn internal_notes admin_flag } }
  ```
- [ ] Use introspection to discover all available fields, then request hidden/sensitive ones
- [ ] Test field aliases to bypass field-level filtering: `query { u1: user { email } u2: user { ssn } }`

## REST API Specific Checks
- [ ] Check `?fields=` or `?select=` query parameters for field filtering bypass
- [ ] Test `?expand=` or `?include=` parameters to pull related objects with sensitive data
- [ ] Send `PATCH` with only sensitive fields to test if they're writable: `{"salary": 999999}`
- [ ] Compare responses from different roles — same endpoint may return different field sets

---
> Cross-reference: A01 checklist, `parameter-fuzzing` skill
