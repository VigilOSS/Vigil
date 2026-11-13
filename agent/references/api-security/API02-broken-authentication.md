---
description: API token and key lifecycle, scope and transport checks (expiry, logout, password change, refresh reuse, key scope)
skill: auth-bypass
---

# API2:2023 — Broken Authentication

Workflow: `agent/skills/auth-bypass/SKILL.md`; JWT signature and header attacks:
`agent/skills/jwt-testing/SKILL.md`; OAuth/OIDC flows: `agent/skills/oauth-oidc-testing/SKILL.md`.

## Token Rotation & Revocation

Replay the old credential after each lifecycle event and record which survive: access token after
logout, after password change and after revoking another session; a refresh token used twice
(single-use?); an expired token and one with no `exp` claim; an empty `Bearer `, a token without the
`Bearer` prefix, and no `Authorization` header at all.

## API Key Scope

A read-only key performing writes, a user-scoped key on admin endpoints, a key for one service
accepted by another, and IP restrictions on a key that are declared but not enforced. Keys in query
strings land in proxy and server logs; keys in JS bundles or mobile builds are
`agent/skills/source-analysis/SKILL.md` and the mobile skills' territory; keys leaked in public
repositories are `agent/skills/osint-recon/SKILL.md`. Credential transport: Basic auth or a
credential body over plain HTTP, and `?username=&password=` accepted in the query string.

## Method-Based Auth Bypass

See [API05 HTTP Method-Based Access Control Bypass](API05-broken-function-authz.md).
