---
description: BFLA on APIs — admin functions with user tokens, method-override verb tampering, version and gRPC gaps
skill: auth-bypass
---

# API5:2023 — Broken Function Level Authorization

Workflow: `agent/skills/auth-bypass/SKILL.md`. Class boundary (BOLA vs BOPLA vs BFLA):
`API01-broken-object-level-authz.md`. Classifier signals for state-change verbs:
`agent/references/gf-patterns/privileged_action.md`.

## Admin Endpoint Access with User Tokens

Call every admin or higher-role function directly with a lower-role token (viewer → editor →
org-admin → admin), reads and destructive actions both. Candidates come from the OpenAPI spec, JS
bundles, admin frontend routes, and GraphQL mutations the frontend never sends (`deleteUser`,
`updateRole`); a function hidden in the UI but callable through the API is the finding.

## HTTP Method-Based Access Control Bypass

When GET is allowed and DELETE refused, send `POST` with `X-HTTP-Method-Override: DELETE` or
`_method=DELETE` in the body (Rails, Laravel); PUT/PATCH on endpoints exposed read-only; HEAD and
OPTIONS on restricted endpoints, which may share GET's handler and skip its check.

## Version and Scope Gaps

`/v1/admin/…` or `/beta/`, `/preview/`, `/canary/` routes that predate or bypass the authz
middleware the current version enforces; a resource created in one org or project scope that grants
a function in another.

## gRPC Function Authorization

Call admin service methods (`admin.AdminService/ListUsers`-style) with user-level
`authorization` metadata. gRPC-web decode and replay:
`agent/references/access-control/idor-modern-architectures.md` "WebSocket / gRPC / SSE / Event-Driven".
