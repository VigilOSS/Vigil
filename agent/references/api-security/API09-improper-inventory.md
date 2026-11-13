---
description: API inventory gaps (endpoints in client code and archives, deprecated and pre-release versions, internal, staging and dev-helper routes)
skill: source-analysis
---

# API9:2023 — Improper Inventory Management

Endpoint extraction from bundles and source maps: `agent/skills/source-analysis/SKILL.md`.
Historical URLs: `agent/skills/gau-triage/SKILL.md`. Path discovery under the VDP's brute-force
terms: `agent/skills/directory-fuzzing/SKILL.md`.

What makes an inventory gap a finding is a weaker control on the forgotten surface, so replay the
current version's auth, authz and rate-limit tests against it:

- **Versions:** `/v0/`–`/v3/`, `/api/vN/`, `Accept: application/vnd.api.v1+json` negotiation, and
  `/beta/`, `/preview/`, `/canary/`, `/next/` routes that predate the current middleware.
- **Client code:** admin/internal routes referenced in JS but not linked in the UI; staging, dev and
  internal API base URLs baked into client builds.
- **Archives and artifacts:** Wayback snapshots of old API docs; Postman collections
  (`collection.json`), Insomnia/Thunder Client exports, Slate/Swagger/Redoc artifacts.
- **Internal and service routes:** `/internal/`, `/private/`, `/debug/`, `/legacy/`, `/old/`,
  `/backup/`, per-service prefixes (`/users-service/`, `/payment-service/`), health, status and
  metrics (`/health`, `/healthz`, `/ready`, `/status`, `/ping`, `/metrics`, `/prometheus`, `/stats`).
- **Staging and dev helpers in production:** `/api/test/`, `/api/mock/`, `/api/fixture/`,
  `/api/seed/`, `/api/reset-db`, `/api/create-test-user`, `/api/populate` (establish that a
  destructive helper exists without invoking it; running it is `--destructive` under exploit
  approval), and `api-staging.` / `api-dev.` subdomains
  (`agent/skills/subdomain-enumeration/SKILL.md`), including APIs from acquisitions.
