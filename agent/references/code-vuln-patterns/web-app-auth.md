# Web Application Authentication & Authorization — Logic-Level Gaps in Frameworks

> Target: Auth bugs in web frameworks that survive SAST because the auth mechanism is
> framework-specific (decorators, middleware, annotations) and the gap is in composition,
> ordering, or coverage — not in a single function. The framework provides the building
> blocks; the developer assembles them incorrectly.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Missing `@login_required` on a route (basic linter check)
- Hardcoded credentials in source
- `==` instead of constant-time compare for tokens
- Direct password storage without hashing
- Missing CSRF token on a form

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Middleware/Decorator Ordering Bugs

Auth middleware registered AFTER the route handler, or class-level auth overridden
by a method that doesn't call super.

```python
# Django: LoginRequiredMixin position in MRO matters
class AdminView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        # BUG: override dispatch() without calling super() → auth never checked
        return self.get(request, *args, **kwargs)

# Correct: super().dispatch() invokes LoginRequiredMixin.dispatch()
```

```javascript
// Express: middleware ordering — auth AFTER route = unprotected
const app = express();

app.get('/admin', adminHandler);        // ← registered first, NO auth
app.use(authMiddleware);                 // ← auth middleware registered after
app.get('/dashboard', dashboardHandler); // ← protected

// The /admin route is served before authMiddleware runs.
```

```java
// Spring: @PreAuthorize on interface method, concrete class doesn't inherit
public interface UserService {
    @PreAuthorize("hasRole('ADMIN')")
    void deleteUser(Long id);
}

// Implementation — annotation is NOT inherited by default in Spring AOP
@Service
public class UserServiceImpl implements UserService {
    public void deleteUser(Long id) { /* runs without auth check */ }
}
```

```python
# FastAPI: Depends(get_current_user) missing from one route in a router
router = APIRouter()

@router.get("/users", dependencies=[Depends(get_current_user)])
async def list_users(): ...

@router.get("/users/{id}")  # ← missing Depends, no auth
async def get_user(id: int): ...
```

### 2. Route-Level vs Global Auth Gaps

Global auth applied, but specific routes excluded via allowlist. New routes added
without updating the allowlist become unprotected.

```python
# Django middleware with exempt URL pattern
class AuthMiddleware:
    LOGIN_EXEMPT_URLS = [
        re.compile(r'^/public/'),
        re.compile(r'^/health$'),
        re.compile(r'^/api/webhook$'),  # added 6 months ago
    ]

    def process_request(self, request):
        if any(pat.match(request.path) for pat in self.LOGIN_EXEMPT_URLS):
            return None  # skip auth
        # ... check auth ...

# New dev adds /api/webhook/internal but doesn't add to exempt list → protected (correct)
# But /api/webhooks (typo plural) IS matched by the regex if re.compile(r'^/api/webhook') → unprotected
```

```javascript
// Express: express-jwt unless() grows stale
app.use(jwt({ secret: SECRET }).unless({
    path: ['/public', '/health', '/login', '/api/webhook']
}));

// Six months later: POST /api/webhook/stripe added → matched by '/api/webhook' prefix?
// Depends on unless() implementation: exact match vs startsWith.
```

```java
// Spring Security: antMatchers with API versioning gap
http.authorizeRequests()
    .antMatchers("/public/**").permitAll()
    .antMatchers("/api/v1/public/**").permitAll()
    .anyRequest().authenticated();

// API v2 deployed: /api/v2/public/docs → NOT matched by /api/v1/public/** → requires auth
// Dev adds /v2/public/** but forgets the /api prefix → still not matched
```

### 3. Role Check Logic Errors

Role comparison using substring matching, locale-dependent ordering, or wrong bitfield operators.

```javascript
// Substring match on role name
function isAdmin(user) {
    return user.role.includes("admin");  // matches "readonly-admin", "admin-viewer"
}

// Locale-dependent comparison
function hasHigherRole(userRole, requiredRole) {
    return userRole >= requiredRole;  // string comparison: "user" > "admin" → true!
}
```

```python
# Bitfield permission error: OR instead of AND
WRITE = 0x02
ADMIN = 0x04

def can_write(user):
    return user.permissions | WRITE  # BUG: always truthy (bitwise OR, not AND)
    # Correct: user.permissions & WRITE
```

```java
// Enum ordinal comparison — brittle if enum order changes
public boolean isAtLeast(Role required) {
    return user.getRole().ordinal() >= required.ordinal();
    // If someone reorders the enum, all auth checks break silently
}
```

### 4. Path Normalization Bypass

Auth checks a normalized path, handler receives the raw path. Different normalization
between auth layer and routing layer.

```
/admin         → blocked by auth middleware
/Admin         → case-insensitive match? depends on framework
//admin        → double slash — many normalizers collapse, some don't
/./admin       → dot segment — removed by some normalizers
/%61dmin       → URL-encoded 'a' — decoded before or after auth check?
/admin;.js     → Tomcat path parameter — stripped by Tomcat, not by auth
/admin..;/     → Tomcat semicolon bypass
/admin%00      → null byte — may terminate string comparison early in C-backed servers
```

```python
# Django: APPEND_SLASH + auth interaction
# Auth middleware blocks /admin/ but request comes as /admin (no slash)
# CommonMiddleware issues 301 redirect to /admin/
# If redirect is followed internally, auth is re-checked. If externally, it depends on client.
```

```java
// Spring: trailing slash and case sensitivity
// SecurityFilterChain checks "/admin/**"
// Controller mapped to @RequestMapping("/Admin") — Spring routing is case-sensitive
// by default, but security matcher may not be → gap between what's protected and what's routed
```

### 5. Fallback Auth Bypass

Primary auth fails, system degrades to weaker auth or no auth instead of failing closed.

```python
# LDAP unavailable → fail open
def authenticate(username, password):
    try:
        return ldap_auth(username, password)
    except LDAPError:
        logger.warning("LDAP unavailable, skipping auth")
        return True  # BUG: fail open

# MFA timeout → proceed without MFA
def verify_mfa(user, code):
    try:
        return mfa_service.verify(user, code, timeout=5)
    except TimeoutError:
        return True  # BUG: MFA bypassed on timeout
```

```javascript
// API key invalid → anonymous access
async function authenticate(req, res, next) {
    const key = req.headers['x-api-key'];
    if (key) {
        const user = await validateApiKey(key);
        if (user) { req.user = user; }
        // BUG: if key is invalid, req.user is undefined but request proceeds
    }
    next();  // always calls next(), even without valid auth
}
```

### 6. Session State Across Auth Boundaries

Pre-auth session data persists after login. Attacker sets session values before
victim authenticates, poisoning the post-auth session.

```python
# Django: session data set before login persists after login
# unless request.session.flush() or request.session.cycle_key() is called
def login_view(request):
    user = authenticate(request, username=..., password=...)
    login(request, user)
    # BUG: pre-auth session data (attacker-controlled) survives
    # Attacker set request.session['redirect_url'] = 'https://evil.example'
```

```javascript
// Express: session fixation — attacker's session ID reused
app.post('/login', (req, res) => {
    const user = authenticate(req.body);
    req.session.user = user;
    // BUG: session ID not regenerated — attacker who set the session cookie
    // via XSS or network injection now has an authenticated session
    // Fix: req.session.regenerate(() => { req.session.user = user; });
});
```

### 7. OAuth/OIDC Implementation Flaws

Framework provides OAuth integration, but developer misimplements critical validation steps.

```javascript
// redirect_uri validated with startsWith instead of exact match
function validateRedirectUri(uri, registeredUri) {
    return uri.startsWith(registeredUri);
    // registered: https://app.com/callback
    // attacker:   https://app.com/callback.evil.example → passes
}

// state parameter generated with Math.random()
const state = Math.random().toString(36).substring(7);
// BUG: Math.random() is not cryptographically secure — CSRF via state prediction

// ID token audience not validated
const decoded = jwt.verify(idToken, publicKey);
req.user = decoded.sub;
// BUG: token from a different client_id accepted — audience confusion
```

```python
# nonce not bound to session
def callback(request):
    token = oauth_client.fetch_token(request.url)
    claims = decode_id_token(token['id_token'])
    # BUG: nonce from token not compared against session-stored nonce
    # Allows token replay attacks
```

### 8. HTTP Method Confusion

Auth applied to specific HTTP methods but not all methods on the same endpoint.

```python
# Django: method-specific auth
class ResourceView(View):
    @login_required
    def get(self, request, pk):
        return JsonResponse(Resource.objects.get(pk=pk).__dict__)

    def post(self, request, pk):  # ← no auth decorator
        resource = Resource.objects.get(pk=pk)
        resource.data = request.body
        resource.save()
        return JsonResponse({"status": "updated"})
```

```java
// X-HTTP-Method-Override bypasses method-based auth
// Security filter blocks DELETE on /api/resources
// But POST with X-HTTP-Method-Override: DELETE is routed as DELETE by the framework
// and the security filter only checked the original POST method
@Override
protected void configure(HttpSecurity http) {
    http.authorizeRequests()
        .antMatchers(HttpMethod.DELETE, "/api/resources/**").hasRole("ADMIN")
        .anyRequest().authenticated();
    // HiddenHttpMethodFilter converts POST + _method=DELETE → DELETE
    // but Spring Security checks the ORIGINAL method (POST) → auth bypassed
}
```

---

## Python Specific

**Django**:
- `LoginRequiredMixin` must be the FIRST parent in class MRO, or `dispatch()` may bypass it
- `@permission_required` checks against `Permission` model but not object-level ownership
- `django-rest-framework`: `DEFAULT_PERMISSION_CLASSES` in settings vs per-view overrides — a view that sets `permission_classes = []` strips all auth
- `@csrf_exempt` on API views can hide broader auth gaps when CSRF is the only protection

**Flask**:
- `@login_required` from Flask-Login vs `@auth_required` from Flask-HTTPAuth — different semantics, easy to confuse
- `before_request` hooks are blueprint-scoped — a route registered on the app (not the blueprint) escapes the hook
- `flask-principal` `Permission.require()` as context manager — exception in the block may not properly deny access

**FastAPI**:
- `Depends()` vs `Security()` — both enforce dependencies but `Security` adds OpenAPI metadata; neither is "more secure"
- Global dependencies on `APIRouter` are not inherited by sub-routers unless explicitly passed
- `BackgroundTasks` run after response — auth context may be lost in background task execution

## JavaScript Specific

**Express**:
- `app.use(path, middleware)` — path matching uses `path-to-regexp`, not exact string match; `/admin` matches `/admin/anything`
- Middleware error handlers `(err, req, res, next)` — if auth middleware throws, error handler may skip remaining auth
- `express-session` `resave: true` + `saveUninitialized: true` = session fixation risk

**Next.js**:
- `middleware.ts` matcher: `'/dashboard/:path*'` does NOT match `/dashboard` (empty path segment)
- Server components vs client components — auth checks in client components are completely bypassable
- API routes in `app/api/` — each route file independently imports auth; missing import = no auth
- `revalidatePath` / `revalidateTag` — cache invalidation can serve stale (pre-auth) content to authenticated users

**NestJS**:
- `@UseGuards(AuthGuard)` at controller level, but `@Public()` decorator on a method removes protection
- Guard execution order with multiple guards: `[RoleGuard, AuthGuard]` — if RoleGuard runs first without a user object, it may throw or pass incorrectly

## Java Specific

**Spring Security**:
- `antMatchers` vs `mvcMatchers` — `antMatchers("/admin")` does NOT match `/admin/` (trailing slash); `mvcMatchers` does
- `@Secured` annotation not processed unless `@EnableGlobalMethodSecurity(securedEnabled = true)` is set — silent failure
- `WebSecurityConfigurerAdapter` deprecated in Spring 6 — migration to `SecurityFilterChain` beans may drop rules
- Multiple `SecurityFilterChain` beans: order matters — first matching chain wins, subsequent chains ignored

**Jakarta EE / Servlet**:
- `web.xml` `<security-constraint>` with `<url-pattern>` — exact match vs prefix match vs extension match semantics differ
- `@RolesAllowed` on EJB vs on JAX-RS resource — different interceptor chains, may not compose
- `HttpServletRequest.isUserInRole()` — checked against container-managed roles, not application-level roles

---

## Detection Questions

1. **"Is the auth check applied to ALL routes that handle this resource, or just the ones the developer remembered?"**
   Enumerate every route that touches the resource. Check each one individually — don't assume global middleware covers them all.

2. **"Can the auth middleware be bypassed by path manipulation, method override, or content-type change?"**
   Test path variations (`/admin` vs `/Admin` vs `//admin` vs `/admin;.js`), method override headers, and alternative content types.

3. **"What happens when the primary auth mechanism is unavailable — does the system fail open or closed?"**
   Trace every `except`/`catch` in the auth path. If any returns `True`, allows `next()`, or sets a default user, that is fail-open.

4. **"Are role checks using exact equality or substring/contains matching?"**
   Search for `.includes()`, `.contains()`, `in`, or regex matching on role strings. These almost always match more than intended.

5. **"Does the framework's auth mechanism compose correctly with routing — are there ordering dependencies?"**
   Check middleware registration order against route registration order. Check whether class-level decorators are inherited by methods. Check MRO for Python mixins.

---

## Real CVE Examples

### CVE-2019-19844 (Django — Password Reset Email Case Confusion)
Django's password reset mechanism looked up users by email address using a case-insensitive
database query, but then sent the reset email to the address as submitted by the user (not
as stored in the database). An attacker could request a password reset for `Admin@Example.com`
(with a Unicode character that case-folds to the same value), and the reset token would be
valid for the real admin account but the email would be sent to an attacker-controlled address.
SAST cannot catch this because the vulnerability is in the interaction between database
collation, Unicode case-folding, and which email address the reset token is bound to.

### CVE-2022-22978 (Spring Security — RegexRequestMatcher Bypass)
Spring Security's `RegexRequestMatcher` used `java.util.regex.Pattern` without the `DOTALL`
flag. This meant `.` in the regex did not match newline characters. An attacker could add
a newline (`%0a`) in the request path, causing the regex to fail to match, and the security
constraint would not apply. The route handler still processed the request normally because
the servlet container stripped or ignored the newline. The gap was between how the regex
engine interpreted the path and how the servlet container routed it.

### CVE-2023-32681 (Requests Library — Auth Header Leak on Redirect)
Python's `requests` library sent the `Authorization` header when following redirects to a
different host. An attacker who controlled a redirect target could steal bearer tokens and
API keys. The auth was correctly applied to the original request, but the redirect handling
didn't strip credentials when crossing trust boundaries. This is a composition bug between
the auth layer and the redirect-following layer that no single-function SAST rule would flag.
