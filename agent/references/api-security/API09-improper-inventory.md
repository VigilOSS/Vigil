# API9:2023 — Improper Inventory Management

> See also: [A02-security-misconfiguration](../vuln-checklists/A02-security-misconfiguration.md) | Skill: `source-analysis`

## Undocumented Endpoint Discovery via JS Analysis
- [ ] Extract API endpoints from JavaScript bundles: search for `/api/`, `fetch(`, `axios.`, `$.ajax`
- [ ] Check source maps if available: `curl https://target/main.js.map` — full original source
- [ ] Look for admin/internal endpoints referenced in JS but not linked in the UI
- [ ] Check for environment-specific URLs: staging, dev, internal API references in client code

## Deprecated API Versions
- [ ] Test older versions for missing security patches: `/v1/users` vs `/v2/users`
- [ ] Enumerate versions: `/v1/`, `/v2/`, `/v3/`, `/v0/`, `/api/v1/`, `/api/v2/`
- [ ] Check if deprecated versions lack rate limiting, auth checks, or input validation added in newer versions
- [ ] Test beta/preview endpoints: `/beta/`, `/preview/`, `/canary/`, `/next/`
- [ ] Check if version negotiation headers bypass: `Accept: application/vnd.api.v1+json`

## Shadow & Zombie APIs
- [ ] Use historical URL databases to find old endpoints: `gau target.example | grep /api/`
- [ ] Check Wayback Machine for archived API documentation pages
- [ ] Test common API path patterns not in current documentation:
  ```
  /api/internal/  /api/private/  /api/debug/  /api/test/
  /api/legacy/    /api/old/      /api/backup/
  ```
- [ ] Check for APIs from merged acquisitions: subdomain enumeration + API path fuzzing

## Internal APIs Exposed Publicly
- [ ] Test for internal service endpoints accessible from the internet: `/internal/`, `/service/`
- [ ] Check for microservice routing leaks: `/users-service/`, `/payment-service/`, `/auth-service/`
- [ ] Test health/status endpoints: `/health`, `/healthz`, `/ready`, `/status`, `/ping`
- [ ] Check for metrics endpoints: `/metrics`, `/prometheus`, `/stats`

## Test/Staging Endpoints in Production
- [ ] Test for staging remnants: `curl https://api/test/login`, `curl https://api/staging/data`
- [ ] Check for mock/fixture endpoints: `/api/mock/`, `/api/fixture/`, `/api/seed/`
- [ ] Test for development helpers: `/api/reset-db`, `/api/create-test-user`, `/api/populate`
- [ ] Check subdomains for exposed staging APIs: `api-staging.target.example`, `api-dev.target.example`

## API Documentation Artifacts
- [ ] Check for Postman collections: `curl https://target/collection.json`
- [ ] Check for exported Insomnia/Thunder Client configs
- [ ] Look for API documentation generators: Swagger, Redoc, Slate artifacts in common paths

---
> Cross-reference: A02 checklist, `source-analysis` skill
