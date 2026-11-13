---
description: API misconfiguration surfaces (CORS, exposed API docs, GraphQL consoles, debug output, content-type parser confusion) and when they rate above informational
skill: web-recon
---

# API8:2023 — Security Misconfiguration

Missing headers, stack traces, verbose errors, version banners and schema exposure are informational
unless they directly enable a proven higher-impact attack (`agent/rules/reporting.md` §3). Treat
each as a lead to chain, not a finding on its own.

- **CORS:** `agent/skills/cors-testing/SKILL.md`.
- **API documentation:** Swagger UI, OpenAPI JSON/YAML (`/v2/api-docs`, `/v3/api-docs`), Redoc. The
  value is internal-only operations it lists and a live "Try it out" console; feed the spec into
  route coverage.
- **GraphQL:** introspection, GraphiQL/Playground consoles and schema recovery with introspection
  off: `agent/skills/graphql-testing/SKILL.md`.
- **Debug output:** Symfony profiler (`X-Debug-Token-Link`), `?debug=true` / `?trace=true`, stack
  traces in JSON errors; harvest them for internal hostnames, paths and secrets.
- **Content-type confusion:** a JSON endpoint that still parses `text/plain`, form-encoded or
  multipart bodies (CSRF without preflight, `agent/skills/csrf-testing/SKILL.md`), or accepts XML
  (`agent/skills/xxe-testing/SKILL.md`).
- **Methods:** `OPTIONS` for the allowed set; `TRACE` enabled; PUT/DELETE accepted where only
  GET/POST should be.
- **Response headers:** `nosniff` and `Content-Type` on JSON (a JSON body served as `text/html` can
  render as HTML), `Cache-Control: no-store` on sensitive responses (cache exposure,
  `agent/skills/cache-poisoning/SKILL.md`).
