# Authentication Bypass — Logic-Level Authentication Gaps

## What SAST Already Catches

- Missing authentication middleware on route definition
- Hardcoded credentials in source code
- `strcmp` for password comparison (timing attack)
- Missing CSRF token validation on state-changing routes

Skip these patterns.

## What You're Hunting (SAST-Surviving Patterns)

### Auth Check on Wrong Operation or Wrong Point
The auth check exists but is applied incorrectly:
- Auth checked before request parsing, but redirect after parsing bypasses the check
- Auth checked on the GET handler, but the same endpoint's POST handler lacks the check
- Auth checked in middleware, but a route exception list accidentally includes the sensitive route
- Auth checked before processing, but error recovery path continues without re-checking

### Privilege Confusion Across Roles
Role A's capabilities are accidentally granted to role B:
- Role check compares `user.role` against `"admin"` but the DB stores `"Admin"` (case sensitivity)
- JWT role claim checked with `includes("admin")` which matches `"readonly-admin"` or `"admin-viewer"`
- Permission bitfield operations use OR when AND was intended, granting union of permissions
- Role hierarchy check uses string comparison (`"user" < "admin"`) which is locale-dependent

### Session State Surviving Auth Boundaries
Pre-auth state leaks into post-auth context:
- Session created during login page visit, retains attacker-set values after successful authentication
- Cart/preferences set by user A persist when user B logs into the same session (session fixation variant)
- OAuth state parameter reused across different authentication flows
- Cookie scope too broad — auth cookie set for `.example.com` accessible by `evil.example.com`

### Fallback Path Bypasses
When primary auth fails, the fallback is weaker or absent:
- TLS client certificate auth fails → falls back to basic auth (or no auth)
- LDAP auth unavailable → fails open instead of fails closed
- API key validation fails → request proceeds with anonymous privileges instead of being rejected
- MFA verification timeout → user proceeds without completing MFA

### Path Normalization Bypass
Auth middleware checks normalized path, but the handler receives the raw path:
- `/admin/` blocked but `/admin` (no trailing slash) allowed
- `/admin` blocked but `//admin`, `/./admin`, `/%61dmin` (URL encoding) allowed
- `/api/admin/users` blocked but `/api/users/../admin/users` allowed
- Case-insensitive filesystem + case-sensitive route matching: `/Admin` vs `/admin`

### HTTP Method Confusion
Auth applies to one method but not others on the same endpoint:
- GET `/api/config` requires admin → blocked. PUT `/api/config` has no auth check → writable by anyone
- DELETE requires auth but OPTIONS pre-flight response leaks information
- PATCH handler added later without copying the auth middleware from GET/POST

### Token Validation Gaps
Token is validated but incompletely:
- JWT signature verified but expiration (`exp`) claim not checked
- JWT verified but audience (`aud`) claim not validated — token from one service accepted by another
- API key checked for existence but not scoped — any valid key accesses any resource
- OAuth token validated but `sub` claim not matched to the requested resource's owner

## C/C++ Specific

**Dangerous patterns**:
- Auth check in wrapper function, but direct callers bypass the wrapper via internal function call
- `setuid`/`setgid` not checked for failure (can fail silently on some systems, leaving elevated privileges)
- `capabilities(7)` set incorrectly — `CAP_NET_BIND_SERVICE` granted when `CAP_NET_RAW` was intended
- Auth state stored in global variable, shared across forked processes or threads
- Buffer containing auth token not zeroed after use (info leak via memory reuse)

**Detection approach**: For every privileged operation, trace backward to find the auth check. Verify it checks the right principal, the right permission, and cannot be bypassed via any alternative code path.

## Python Specific

**Dangerous patterns**:
- Decorator ordering: `@login_required` applied after `@route()` may not fire as expected in all frameworks
- Django `permission_classes` on ViewSet but not on individual actions (`retrieve` vs `list` vs `create`)
- Flask `@before_request` exception — a new route added without the auth blueprint
- FastAPI dependency injection: auth dependency declared but `Depends()` forgotten on a specific endpoint
- `getattr(user, 'is_admin', False)` — defaults to False when attribute is missing, which is correct, but `getattr(user, 'is_admin', True)` defaults to True (seen in copy-paste errors)

**Framework-specific**:
- Django REST Framework: `IsAuthenticated` checks auth but not object-level permissions
- Flask-Login: `@login_required` but `current_user.is_authenticated` can be overridden by user model
- FastAPI: `Security()` dependency vs `Depends()` — subtle difference in OpenAPI schema generation but identical runtime behavior (often confused)

## JavaScript Specific

**Dangerous patterns**:
- Express middleware ordering: auth middleware added after the route it should protect
- Next.js `middleware.ts` matcher configuration: `matcher: ['/dashboard/:path*']` doesn't match `/dashboard` (no trailing content)
- JWT verification with `algorithms: ['HS256', 'none']` — `none` algorithm bypass
- Prototype pollution setting `isAdmin: true` on the request object before auth check reads it
- `res.redirect()` before `next()` — response sent but middleware chain continues executing

**Framework-specific**:
- Express: `app.use('/admin', authMiddleware)` vs `app.use('/admin/', authMiddleware)` — trailing slash semantics
- Next.js App Router: server component auth vs client component auth — client-side checks are bypassable
- Nest.js: Guard applied at controller level but a specific route uses `@Public()` decorator (intended but often over-applied)

## Detection Questions

1. **For every sensitive operation, where is the auth check?** Trace from the operation backward to find it. If you can't find it, that's a finding.
2. **Can the auth check be bypassed via an alternative path?** Different HTTP method, URL encoding, redirect, error path?
3. **Is the auth check checking the right thing?** Right user, right permission, right resource, right scope?
4. **What happens when auth fails?** Reject? Fallback? Fail open?
5. **Are there any paths that were added after the auth middleware and might have been missed?** Check git log for routes added after the initial auth implementation.

## Real CVE Patterns

**Pattern 1 — Path normalization in web servers**: Nginx/Apache/Tomcat path traversal where `..` sequences or URL encoding bypass location-based access controls. The auth layer normalizes differently than the file-serving layer.

**Pattern 2 — JWT audience confusion**: Token issued for Service A is accepted by Service B because both share the same signing key and neither validates the `aud` claim. Attacker obtains a low-privilege token from A and uses it for high-privilege operations on B.

**Pattern 3 — HTTP method override**: Application blocks DELETE requests to `/api/resources/{id}` for non-owners, but accepts `POST /api/resources/{id}` with `X-HTTP-Method-Override: DELETE` header, and the override header is processed after the auth check.
