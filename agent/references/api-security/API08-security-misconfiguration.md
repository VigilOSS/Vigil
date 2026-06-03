---
description: CORS, debug endpoints, verbose errors
skill: web-recon
---

# API8:2023 — Security Misconfiguration

> Skill: `web-recon`

## CORS Misconfiguration on APIs
- [ ] Test wildcard CORS with credentials: `curl -I -H "Origin: https://evil.example" https://api/data` — check for `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- [ ] Test origin reflection: does the API reflect any origin back? `curl -I -H "Origin: https://attacker.example" https://api/data`
- [ ] Test null origin: `curl -I -H "Origin: null" https://api/data`
- [ ] Check preflight responses for overly permissive `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`

## Exposed API Documentation
- [ ] Check for Swagger UI: `/swagger`, `/swagger-ui.html`, `/swagger-ui/`, `/api-docs`
- [ ] Check for OpenAPI spec: `/openapi.json`, `/openapi.yaml`, `/v2/api-docs`, `/v3/api-docs`
- [ ] Check for Redoc: `/redoc`, `/docs`
- [ ] Test if API docs expose internal-only endpoints not intended for public access
- [ ] Check if Swagger UI allows "Try it out" functionality against the live API

## GraphQL Introspection
- [ ] Test introspection query: `curl -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name fields { name } } } }"}' https://api/graphql`
- [ ] If introspection is enabled, enumerate all queries, mutations, and subscriptions
- [ ] Look for admin-only types, sensitive fields, or internal naming patterns in the schema
- [ ] Test GraphQL Playground/GraphiQL: `/graphql`, `/graphiql`, `/playground`

## Debug Headers & Verbose Errors
- [ ] Check for debug headers in responses: `X-Debug-Token`, `X-Debug-Token-Link`, `X-Request-Id`
- [ ] Trigger errors and check for stack traces in JSON error responses
- [ ] Test `?debug=true`, `?verbose=true`, `?trace=true` query parameters
- [ ] Check for `Server`, `X-Powered-By`, `X-AspNet-Version` version disclosure headers

## Content-Type Validation
- [ ] Send JSON body with `Content-Type: text/plain` — does the API still parse it?
- [ ] Send XML body to JSON endpoint — does it trigger XXE processing?
- [ ] Send `Content-Type: application/x-www-form-urlencoded` to JSON endpoint and vice versa
- [ ] Test multipart form data on endpoints expecting JSON — parser confusion

## Unnecessary HTTP Methods
- [ ] Test `OPTIONS` on all endpoints — what methods are allowed?
- [ ] Test `TRACE` for cross-site tracing: `curl -X TRACE https://api/endpoint`
- [ ] Test `PUT`/`DELETE` on endpoints that should only accept `GET`/`POST`

## API-Specific Security Headers
- [ ] Check for missing `X-Content-Type-Options: nosniff` on API responses
- [ ] Check for missing `Cache-Control: no-store` on sensitive API responses
- [ ] Verify API responses include appropriate `Content-Type` header (not `text/html` for JSON)

---
> Cross-reference: A02 checklist, `web-recon` skill
