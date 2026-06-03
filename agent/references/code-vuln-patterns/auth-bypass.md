---
description: Generic/C auth gaps, fallback bypasses, token validation gaps. Framework-specific → see `web-app-auth.md`
skill: code-vulnerability-analysis
languages: C/C++ (frameworks → web-app-auth)
---

# Authentication Bypass — Logic-Level Authentication Gaps

> For web framework-specific auth bypass patterns (Django, Flask, FastAPI, Express, Next.js, NestJS, Spring),
> see `web-app-auth.md` which provides per-framework code examples and CVEs. This file covers
> generic/C/C++ auth bypass patterns and cross-framework logic bugs.

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Missing authentication middleware on route definition
- Hardcoded credentials in source code
- `strcmp` for password comparison (timing attack)
- Missing CSRF token validation on state-changing routes

## What You're Hunting (LLM-Advantage Patterns)

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

## Python / JavaScript / Java Framework-Specific

See `web-app-auth.md` for comprehensive per-framework patterns including:
- Django decorator ordering, DRF permission_classes, Flask @before_request gaps
- Express middleware ordering, Next.js middleware matcher, NestJS guard bypass
- Spring @PreAuthorize, antMatchers vs mvcMatchers, HiddenHttpMethodFilter
- FastAPI Depends() gaps, Flask-Login overrides, JWT algorithm confusion

The patterns below in C/C++ Specific are NOT covered in web-app-auth.md and remain here.

## Detection Questions

1. **For every sensitive operation, where is the auth check?** Trace from the operation backward to find it. If you can't find it, that's a finding.
2. **Can the auth check be bypassed via an alternative path?** Different HTTP method, URL encoding, redirect, error path?
3. **Is the auth check checking the right thing?** Right user, right permission, right resource, right scope?
4. **What happens when auth fails?** Reject? Fallback? Fail open?
5. **Are there any paths that were added after the auth middleware and might have been missed?** Check git log for routes added after the initial auth implementation.

## Real CVE Examples

### CVE-2021-41773 (Apache httpd — path normalization auth bypass)
Apache 2.4.49 introduced a path normalization flaw where `/.%2e/` sequences bypassed
`<Directory>` access controls. The URL decoder resolved `%2e` to `.` after the auth
check had already evaluated the un-decoded path. The auth layer and the file-serving
layer disagreed on which path was being accessed — a classic multi-function normalization
mismatch across the request processing pipeline.

### CVE-2023-22602 (Apache Shiro + Spring Boot — path matching bypass)
Shiro's `PathMatchingFilter` used Ant-style path matching while Spring Boot used its
own path matching. Requests with trailing slashes or path parameters (`;param`) matched
in Spring but not in Shiro, bypassing auth checks. The fix required Shiro to delegate
path matching to the framework rather than maintaining its own matcher.

### CVE-2019-19844 (Django — Unicode case-folding password reset)
Django's password reset accepted email addresses that differed only in Unicode case
folding. An attacker could request a reset for `admin@example.com` using a
confusable Unicode equivalent, and the reset email would be sent to the attacker's
address if the email system resolved the confusable differently than Django's
`iexact` lookup. The auth check (email lookup) and the action (send email) operated
on different normalizations of the same input.
