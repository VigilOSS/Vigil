---
name: gf-patterns:mass-assignment
description: Privilege/state-field body parameter patterns that signal mass assignment (autobinding / over-posting) surfaces
origin: Vigil (vuln-taxonomy-audit 2026-07 — no upstream 1ndianl33t/Gf-Patterns equivalent exists)
bucket: mass-assignment
skill: bff-parameter-override, mass-assignment
weight: 30
---

# gf: mass-assignment

## What this bucket classifies

Requests whose body already carries a privilege- or state-shaped field name — the kind of
autobinding target that lets an attacker add an unintended parameter (`isAdmin`, `role`,
`verified`, ...) to a create/update request and have the framework bind it straight onto the
model, granting privilege the endpoint never meant to expose. Known as Mass Assignment in
Rails/Node and Autobinding in Spring MVC/ASP.NET MVC. OWASP API Security Top 10:2023 folds this
into **API3:2023 — Broken Object Property Level Authorization**, a top-3 API risk.

## Load this reference when

- A captured create/update request body already contains a key like `role`, `isAdmin`,
  `permissions`, `verified`, `access_level`, or `account_type`
- The endpoint is a user/account/profile create-or-update route (registration, profile edit,
  org-member invite) — the classic over-posting target
- The operator is choosing between `mass-assignment` and `bfla`/`privileged_action` — mass
  assignment is the **body-field** variant of the same authorization-bypass family that
  `privileged_action` models via **state-verb path segments**

## Parameter keys that match

`role, roles, admin, isadmin, is_admin, permissions, permission, verified, is_verified,
isverified, approved, is_approved, isapproved, access_level, accesslevel, privilege,
privileges, account_type, accounttype, user_type, usertype, user_role, userrole, is_active,
isactive`

Every key is DELIBERATELY NOVEL — verified against every other bucket's key set, including
`privileged_action`'s state-verb set (`grant`/`delete`/`create`/`disable`/...) and
`oauth-oidc`'s `scope` — so this bucket cannot recluster a single existing row.

## Path patterns that match

None — this bucket is keyed entirely off parameter names. Mass assignment is a body-shape
issue, not a path signal.

## Weight and priority interpretation

- Baseline priority score: 30 (tied with `privileged_action`/`servicenow`/`debug_logic` —
  real bfla-adjacent authorization risk, but a marginal field name alone does not prove the
  binding is actually unchecked server-side)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/users/register` with body `{"email": "...", "isAdmin": true}` —
  classic over-posting on registration
- `https://target.example/api/orgs/42/members` with body `{"user_id": 7, "role": "owner"}` —
  privilege field on an invite/member-add endpoint
- `https://target.example/api/profile` (PATCH) with body containing `verified` or
  `account_type` — profile-update over-posting

## What it does NOT classify

- GET/read requests that merely **display** a `role`/`verified` field — the exploit requires a
  write path (POST/PUT/PATCH) that autobinds the body onto a persisted model; this bucket
  flags the field name only, verification still requires confirming the write actually
  persists an unauthorized value
- Function-level authorization bypass via a state-change **path segment**
  (`/api/users/1024/grant`) — that is `privileged_action`'s signal, not this bucket's

## Sources

- [OWASP API Security Top 10:2023 — API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Cheat Sheet Series — Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP WSTG — Testing for Mass Assignment](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment)

## Related

- `agent/skills/mass-assignment/SKILL.md` and `agent/skills/bff-parameter-override/SKILL.md` —
  the follow-up test skills (already existed before this bucket; both declare
  `vuln_class: mass-assignment`)
- `agent/references/gf-patterns/privileged_action.md` — adjacent bucket (bfla via path verb
  vs. this bucket's bfla-adjacent body-field signal)
