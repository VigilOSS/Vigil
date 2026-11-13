---
description: Mass-assignment field families and excessive property exposure (REST and GraphQL)
skill: parameter-fuzzing, mass-assignment
---

# API3:2023 — Broken Object Property Level Authorization

Workflow and Vigil mechanics: `agent/skills/mass-assignment/SKILL.md`. Class boundary (BOLA vs
BOPLA vs BFLA): `API01-broken-object-level-authz.md`.

## Mass Assignment — Extra Fields in Write Requests

Field families to add to register/profile/order/settings writes, flat and nested
(`{"profile":{"role":"admin"}}`, since flat-field filtering often misses nesting):
- privilege: `role`, `is_admin`, `is_staff`, `permissions: ["*"]`, `groups: ["admin"]`;
- financial: `price: 0`, `discount: 100`, `salary` (a PATCH carrying only the sensitive field shows
  whether it is writable);
- verification and state: `verified`, `approved`, `status: "active"` (approval-workflow bypass);
- ownership: `id` or `user_id: VICTIM_ID` on create, to hijack ownership.

## Excessive Data Exposure in Responses

Fields the response returns but the UI never renders: password hashes (`password_hash`,
`encrypted_password`), internal or debug fields (`_id`, `internal_id`, `debug_info`), PII on listing
endpoints, and other users' data inside shared resources. Projection parameters widen it:
`?fields=` / `?select=` / `?fields=all`, `?expand=` / `?include=private`, `?verbose=true`. Compare
the same endpoint across roles; the field set often differs. Whether exposed data is non-public is
`agent/rules/reporting.md` §4.

## GraphQL Field-Level Access

Request fields the UI never asks for (introspection or a leaked schema lists them), and split
sensitive fields across aliases (`u1: user { email } u2: user { ssn }`) to get past field-level
filtering. Schema recovery without introspection: `agent/skills/graphql-testing/SKILL.md`.
