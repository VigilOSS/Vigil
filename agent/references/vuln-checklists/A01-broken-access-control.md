# A01:2025 — Broken Access Control

## IDOR / Object-Level Authorization
- [ ] Swap numeric IDs in every endpoint: `/api/users/123` -> `/api/users/124`
- [ ] Swap UUIDs — harvest valid UUIDs from other responses, search results, or public listings
- [ ] Test array parameter injection: `?id[]=1&id[]=2` to access multiple objects in one request
- [ ] Test ID type confusion: send string where int expected, hex-encoded IDs, negative IDs
- [ ] Check IDOR in file download/export endpoints: `/api/reports/123/download`
- [ ] Test IDOR in DELETE and PUT/PATCH — write operations often lack checks that GET has

## Privilege Escalation
- [ ] Access admin endpoints (`/admin`, `/api/admin/*`) with regular user tokens
- [ ] Modify role/permission fields in profile update requests: `{"role":"admin"}`, `{"is_staff":true}`
- [ ] Test vertical escalation: low-priv user hitting high-priv API actions
- [ ] Check if removing a cookie/token grants more access than including an invalid one (fail-open)
- [ ] Test tenant isolation: swap `X-Tenant-ID` or `org_id` parameters between accounts

## CORS Misconfigurations
- [ ] Test wildcard origin: `curl -I -H "Origin: https://evil.example" https://target/api/`
- [ ] Test null origin: `curl -I -H "Origin: null" https://target/api/`
- [ ] Check if `Access-Control-Allow-Credentials: true` paired with reflected/wildcard origin
- [ ] Test subdomain reflection: `curl -I -H "Origin: https://attacker.target.example" https://target/api/`

## Forced Browsing & Path Traversal
- [ ] Access authenticated URLs without session: `/dashboard`, `/settings`, `/api/me`
- [ ] Path traversal for ACL bypass: `/api/users/../admin/settings`
- [ ] URL-encoded traversal: `/api/users/%2e%2e%2fadmin/settings`
- [ ] Test API version rollback: `/v1/endpoint` may lack controls added in `/v2/endpoint`
- [ ] Check for unprotected static file paths: `/uploads/`, `/backups/`, `/exports/`

## HTTP Method & Verb Tampering
- [ ] Change GET to PUT/DELETE/PATCH on read-only endpoints
- [ ] Use HEAD or OPTIONS to bypass method-based ACL checks
- [ ] Test method override headers: `X-HTTP-Method-Override: DELETE`, `X-Method-Override: PUT`
- [ ] Send POST with `_method=DELETE` parameter (Rails, Laravel convention)

## JWT & Token Claims
- [ ] Change `alg` to `none` and strip signature
- [ ] Modify `sub`, `role`, `groups` claims and re-sign with known/weak key
- [ ] Test `kid` header injection: path traversal, SQL injection in `kid` value
- [ ] Swap RS256 to HS256 and sign with the public key (algorithm confusion)
- [ ] Test expired tokens — verify server actually rejects them

## GraphQL Authorization
- [ ] Query nested objects to access other users' data: `{ user(id:1) { orders { ... } } }`
- [ ] Test mutations without proper role: `mutation { deleteUser(id:2) { success } }`
- [ ] Use introspection to find admin-only queries/mutations, then call them with user tokens
- [ ] Test field-level auth: request sensitive fields (`ssn`, `password_hash`) in queries

## Framework-Specific Checks
- [ ] **Django**: Test `@login_required` missing on views, check Django REST `permission_classes`
- [ ] **Rails**: Check `before_action` filters — missing `:only`/`:except` on auth callbacks
- [ ] **Express**: Verify middleware ordering — auth middleware must come before route handler
- [ ] **Spring**: Test `@PreAuthorize` annotations, check Spring Security filter chain ordering
- [ ] **Next.js**: Test API routes in `pages/api/` — middleware.ts may not cover all routes
- [ ] **Laravel**: Check `Gate`/`Policy` definitions, test `authorize()` calls in controllers

---
> Cross-reference skills: `auth-bypass`, `idor-testing`, `cors-testing`
