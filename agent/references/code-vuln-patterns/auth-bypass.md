---
description: Generic/C auth gaps, trusted proxy header injection, token validation gaps. Framework-specific → see `web-app-auth.md`
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS (frameworks → web-app-auth)
---

# Authentication Bypass — Logic-Level Authentication Gaps

Generic and C/C++ authentication gaps, client-controlled "infrastructure" headers, and token claim
checks. Framework middleware, decorator, path-normalization, role-check, session, and method
patterns are in `web-app-auth.md`.

## What You're Hunting (LLM-Advantage Patterns)

### Auth checked at the wrong point

- Auth evaluated before request parsing, while a redirect or rewrite produced by parsing reaches the
  handler afterwards.
- An error-recovery path that continues without re-checking.
- A TLS client-certificate failure that falls back to basic auth or to anonymous access.

### Token validation gaps

- JWT signature verified but `exp` not checked, or `aud` not validated (a token for one service
  accepted by another).
- An API key checked for existence but not scope, so any valid key reaches any resource.
- The `sub` claim never compared with the owner of the requested resource.

### Trusted proxy header injection

A header that looks like infrastructure metadata is ordinary client input at the edge unless a
fronting proxy is guaranteed to strip or overwrite it. Find where the value feeds a security decision,
then confirm from the deployment configuration, not the handler, that it cannot originate from the
client.

- **`X-Forwarded-Host`/`Host` into reset links, redirects, or cache keys.**
  ```python
  host = request.headers.get("X-Forwarded-Host", request.host)
  reset_url = f"https://{host}/reset?token={make_token(user)}"   # emailed to the victim
  ```
  `X-Forwarded-Host: attacker.example` puts the victim's valid token in a link to the attacker.
  Grep `X-Forwarded-Host`, `request.host`, `HTTP_HOST`, and `Host` reads feeding URL construction,
  redirects, or cache keys; the fix is a hostname allowlist or a configured canonical host.
- **`X-Original-URL`/`X-Rewrite-URL` honored for routing.** The auth middleware or an upstream
  matcher evaluates the request path (`/public/x`) while a front controller dispatches on the header
  (`/admin/delete`); older Symfony and Zend setups trusted it. Verify the auth layer evaluated the same
  path value the router dispatches on.
- **`X-Forwarded-For`/`X-Real-IP` for allowlists and rate limits.** `req.headers['x-forwarded-for']
  .split(',')[0]` is whatever the client sent. The trusted-proxy setting must honor the header only
  from a known immediate upstream: Express `trust proxy` set to that hop (not `true`), Flask/Werkzeug
  `ProxyFix(x_for=1)` with the right hop count, Django custom middleware (Django has no built-in
  trusted-proxy IP setting; `SECURE_PROXY_SSL_HEADER` only governs `request.is_secure()`). Grep
  `X-Forwarded-For`, `X-Real-IP`, `req.ip`, `remote_addr` feeding allowlist, internal, rate-limit, or
  geofence decisions.

## C/C++ Specifics

- An auth check inside a wrapper that internal callers bypass by calling the underlying function.
- Unchecked `setuid`/`setgid`/`setgroups` return values: a failed drop leaves the process privileged.
- Capabilities granted more broadly than the operation needs, or retained across `exec`.
- Auth state in a global shared across forked workers or threads.
- Auth tokens left in buffers that are reused or not zeroed.

For every privileged operation, trace back to the check and confirm it tests the right principal,
permission, and resource on every path that reaches the operation.

## Real CVE Examples

- **CVE-2021-41773 (Apache httpd 2.4.49).** The new normalization missed `/.%2e/`, so the encoded
  traversal passed the `<Directory>` access check and was decoded later in the file-serving path; the
  auth layer and the file layer disagreed on which path was requested.
- **CVE-2023-22602 (Apache Shiro with Spring Boot 2.6+).** Spring Boot switched its default matcher to
  `PathPatternParser`, so requests Spring routed (trailing slashes, path variants) were not matched by
  Shiro's Ant-style filter chain. Fixed in Shiro 1.11.0, with `spring.mvc.pathmatch.matching-strategy
  =ant_path_matcher` restoring agreement.
