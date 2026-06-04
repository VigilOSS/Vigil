---
description: Admin endpoint access with user tokens
skill: auth-bypass
---

# API5:2023 — Broken Function Level Authorization

> Skill: `auth-bypass`

## Admin Endpoint Access with User Tokens
- [ ] Test admin paths with regular user token: `curl -H "Authorization: Bearer USER_TOKEN" https://api/admin/users`
- [ ] Test admin actions: `curl -H "Authorization: Bearer USER_TOKEN" -X DELETE https://api/admin/users/123`
- [ ] Enumerate admin endpoints from OpenAPI spec, JS bundles, or common paths: `/admin/`, `/manage/`, `/internal/`
- [ ] Check if admin frontend routes hint at admin API endpoints not tested

## HTTP Method-Based Access Control Bypass
- [ ] If GET is allowed but DELETE is blocked, test with method override: `curl -X POST -H "X-HTTP-Method-Override: DELETE" https://api/resource/123`
- [ ] Test `_method=DELETE` parameter (Rails, Laravel): `curl -X POST -d "_method=DELETE" https://api/resource/123`
- [ ] Test if PUT/PATCH on read-only endpoints is accepted with user token
- [ ] Try HEAD and OPTIONS on restricted endpoints — may leak info or bypass checks

## Hidden Admin API Paths
- [ ] Fuzz for admin endpoints: `/api/admin/`, `/api/internal/`, `/api/management/`, `/api/debug/`
- [ ] Check for GraphQL admin mutations not exposed in the frontend:
  ```
  mutation { deleteUser(id: "123") { success } }
  mutation { updateRole(userId: "123", role: "admin") { success } }
  ```
- [ ] Test undocumented endpoints found in JS source or OpenAPI spec

## Version-Specific Authorization Gaps
- [ ] Test `/v1/admin/users` with user token (if `/v2/admin/users` is properly secured)
- [ ] Check if deprecated API versions lack authorization middleware added in newer versions
- [ ] Test beta/preview endpoints: `/beta/`, `/preview/`, `/canary/` — often under-secured

## Role & Permission Boundary Testing
- [ ] Test with different role tokens: viewer accessing editor endpoints, editor accessing admin
- [ ] Verify function-level checks are not only on the frontend (call API directly)
- [ ] Test if creating/modifying resources in one scope allows cross-scope access
- [ ] Check if organization member can access organization-admin functions

## gRPC Function Authorization
- [ ] Test gRPC methods with user-level metadata instead of admin metadata
- [ ] Use `grpcurl` to call admin service methods with non-admin tokens:
  ```
  grpcurl -H "authorization: Bearer USER_TOKEN" target:443 admin.AdminService/ListUsers
  ```

---
> Cross-reference: A01 checklist, `auth-bypass` skill
