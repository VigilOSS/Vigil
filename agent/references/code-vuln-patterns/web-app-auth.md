---
description: Middleware ordering, decorator bypass, role check logic, path normalization, OAuth implementation flaws
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS, Java
---

# Web Application Authentication & Authorization — Logic-Level Gaps in Frameworks

The framework provides the building blocks and the gap is in how they are assembled: ordering,
coverage, inheritance, and normalization. Generic and C-level auth gaps, trusted proxy headers, and
token-claim checks are in `auth-bypass.md`; object-level authorization is in
`web-app-data-exposure.md`.

## What You're Hunting (LLM-Advantage Patterns)

### 1. Ordering and inheritance

- Django: a view overriding `dispatch()` without calling `super().dispatch()` skips
  `LoginRequiredMixin`, which must also sit leftmost in the bases.
- Express: a route registered before `app.use(authMiddleware)` is served without it.
- FastAPI: one route in a router missing `Depends(get_current_user)`; and `include_router()` copies
  routes at call time, so routes added to a router after it was included are not registered with
  the parent's dependencies.
- Spring method security is proxy-based: `@PreAuthorize` does not apply to self-invocation
  (`this.deleteUser()`), private methods, or final methods, so an internal call path skips the check.

### 2. Global auth with exemptions

Exempt lists drift as routes are added. An unanchored exempt regex (`^/api/webhook` without `$`)
exempts `/api/webhooks` and `/api/webhook-admin`. `express-jwt`/`express-unless`: string entries
match the path exactly, while RegExp entries are where prefix leaks come from. `app.use('/admin', mw)`
matches `/admin/anything` by prefix. List every exemption and compare it against newly added routes.

### 3. Frame protection exemptions

The same exemption drift strips clickjacking protection from sensitive routes (login, payment,
account settings, admin): Django `@xframe_options_exempt` on a view; an Express route that sets its
own `Content-Security-Policy` header, which replaces helmet's whole policy and drops
`frame-ancestors`; a Spring `SecurityFilterChain` with `frameOptions().disable()` for an embeddable
widget that also serves an HTML console. Grep the header middleware (`django.middleware.clickjacking`,
`helmet()`, `headers().frameOptions`, hand-rolled setters) and enumerate exempted or overridden
routes.

### 4. Role check logic

- Substring matching: `role.includes("admin")` matches `readonly-admin`; regex and Python `in` on role
  strings likewise.
- String ordering: `userRole >= requiredRole` compares lexicographically (`"user" > "admin"`).
- Case drift: the database stores `Admin`, the check compares with `admin`.
- Bitwise OR for AND: `perms | WRITE` is always truthy.
- Java `role.ordinal() >= required.ordinal()` silently changes meaning when the enum is reordered.

### 5. Path normalization differentials

The auth layer and the router normalize differently: case (`/Admin`), `//admin`, `/./admin`,
`/%61dmin` (decoded before or after the check?), Tomcat path parameters (`/admin;.js`, `/admin..;/`),
and `%00` in C-backed servers. Spring: suffix-pattern matching (`/admin.json` routed to `/admin`) was
on by default before Spring MVC 5.3, and trailing-slash matching (`/admin/`) before Spring 6; a
Security 5.x `antMatchers("/admin")` rule did not match `/admin/` while MVC still routed it.
`requestMatchers` (Security 6) follows MVC's own matching.

### 6. Fail-open fallbacks

Each `except`/`catch` in the auth path: an LDAP error that returns `True`, an MFA timeout that
proceeds, middleware that calls `next()` whether or not the API key validated (leaving `req.user`
undefined but the request served). Generic error-path fail-open is in `error-handling.md`.

### 7. Session state across login

Express without `req.session.regenerate()` at login keeps the attacker-planted session id (fixation).
Django's `login()` rotates the key with `cycle_key()` but keeps session data, so values planted before
login (a `redirect_url`, a cart owner, a tenant id) survive into the authenticated session unless
the view flushes them.

### 8. OAuth/OIDC

`jwt.verify(idToken, key)` without the `audience` option accepts tokens minted for another client;
the ID token's `nonce` not compared with the session's allows replay. `redirect_uri` prefix matching
is covered in `open-redirect.md`; `state` from `Math.random()` in `crypto-misuse.md`.

### 9. HTTP method confusion

Auth on some methods of one endpoint and not others. In a Django class-based view, a bare
`@login_required` on `get()` receives `self` as the request and fails; method-level protection needs
`@method_decorator(login_required)`, and a sibling `post()` without it is open. Method-override
mechanisms (`_method`, `X-HTTP-Method-Override`, Express `method-override`) matter when they run after
the method-based authorization check; Spring Boot's `HiddenHttpMethodFilter` is off by default since
2.2, reads only `_method`, and runs before the Security filter chain when enabled.

## Python Specifics

- DRF: `DEFAULT_PERMISSION_CLASSES` overridden by a view's `permission_classes = []`;
  `@permission_required` checks model permissions, not object ownership.
- `@csrf_exempt` on views where CSRF was the only protection.
- Flask: `before_request` hooks are blueprint-scoped, so a route on the app escapes a blueprint's hook;
  Flask-Login `@login_required` and Flask-HTTPAuth `@auth_required` have different semantics.
- FastAPI `BackgroundTasks` run after the response, outside the request's auth context.

## JavaScript Specifics

- Next.js middleware is the only check on many apps: CVE-2025-29927 let an
  `x-middleware-subrequest` header skip middleware entirely; auth done only in client components is
  bypassable; each `app/api/` route file imports its own auth.
- NestJS `@Public()` on a method under a controller-level `@UseGuards(AuthGuard)`; guard order such
  as `[RoleGuard, AuthGuard]` running the role check before a user exists.
- An Express error-handler path that continues after the auth middleware throws.

## Java Specifics

- Multiple `SecurityFilterChain` beans: the first matching chain wins.
- `@Secured` needs `@EnableMethodSecurity(securedEnabled = true)` (formerly
  `@EnableGlobalMethodSecurity`); without it the annotation silently does nothing.
- `WebSecurityConfigurerAdapter` was removed in Spring Security 6.0; migrations to `SecurityFilterChain`
  beans can drop rules.
- Servlet `<security-constraint>` `url-pattern` exact, prefix, and extension semantics differ;
  `@RolesAllowed` on EJB and JAX-RS go through different interceptors; `isUserInRole()` checks
  container roles, not application roles.

## Detection Questions

- Which routes touch this resource, and does each one enforce auth itself rather than relying on a
  global layer an exemption or ordering can skip?
- Do the auth matcher and the router agree on case, slashes, encoded characters, path parameters, and
  method?

## Real CVE Examples

- **CVE-2019-19844 (Django password reset).** Users were looked up by a case-insensitive email match,
  but the reset mail went to the address as submitted; a Unicode address that case-folds to the
  victim's received a valid reset link. The bug lives between collation, case folding, and which
  address the token is bound to.
- **CVE-2022-22978 (Spring Security `RegexRequestMatcher`).** The pattern lacked `DOTALL`, so a `%0a`
  in the path made `.` fail to match and the constraint not apply while the servlet still routed the
  request.
- **CVE-2023-42793 (JetBrains TeamCity).** The authentication interceptor skipped any request path
  ending in `/RPC2`, so an unauthenticated request to a token-creation endpoint with that suffix
  minted an admin token.
- **CVE-2023-32681 (requests).** `Proxy-Authorization` built for the proxy hop was also sent to the
  destination through the HTTPS tunnel on redirect, leaking proxy credentials to the origin;
  cross-host stripping of `Authorization` existed, so reading that check suggested the library was
  safe. Fixed in 2.31.0.
