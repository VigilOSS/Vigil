---
name: bff-parameter-override
description: Test for hidden middleware/BFF parameters that override backend identity, authorization, or object resolution when supplied by the client
origin: Vigil
vuln_class: mass-assignment, bola
---

# BFF Parameter Override Testing

> **`vigil assess kali` audit flags:** use `--technique AUTH` for identity-override probes, `--technique IDOR` for object-override probes. Use `--probe-kind payload` for injection attempts, `--probe-kind exploit` for confirmed override demonstrations.

## When to Activate

- Target architecture uses a BFF (Backend-for-Frontend), API gateway, or Express/Next.js middleware that proxies requests to internal services
- Source analysis or recon reveals parameters that appear in backend calls but not in client-side code
- Application uses a multi-tier architecture where the frontend server enriches requests before forwarding
- Tech stack is Node.js/Express, Next.js, Nuxt, Django REST Framework, Rails API, or Spring Cloud Gateway
- Any endpoint where the middleware sets identity-bearing parameters (userId, tenantId, accountId) before forwarding

## Core Concept

BFF/middleware layers frequently enrich requests by injecting internal parameters (user identity, tenant context, permissions) before forwarding to backend services. The vulnerability occurs when:

1. The middleware sets parameter X (e.g., `userId`) from the session
2. The middleware does NOT strip client-supplied values of parameter X from the incoming request
3. The backend trusts parameter X unconditionally because "it comes from the BFF"

The attacker supplies the internal parameter directly, overriding the value the middleware would have set.

## Tools

- `vigil assess kali exec -- curl ...` for all probing (mandatory audit pipeline)
- Source analysis output (if available) for parameter name discovery
- Browser DevTools / mitmproxy for observing request enrichment patterns

---

## Phase 1: Parameter Discovery

### 1.1 Passive Discovery (from source analysis, JS bundles, error messages)

- [ ] Check source-analyzer output for middleware parameter names
- [ ] Search JS bundles for internal parameter references (often in API client wrappers)
- [ ] Check error messages — validation errors may leak expected parameter names
- [ ] Review API documentation / OpenAPI specs for undocumented parameters
- [ ] Check response bodies — internal parameters sometimes leak back in responses

### 1.2 Framework-Specific Internal Parameters

Load the full parameter wordlist from `agent/references/payloads/bff-override-params.md` — it contains framework-specific parameter lists for Express, Next.js, Django, Rails, Spring, and Kong. Select the section matching the detected tech stack and test each parameter in all locations (query, body, header, cookie).

**Quick-start (top 10 highest-value params to test first regardless of framework):**
```
userId, $id$, notAuthUserId, tenantId, isAdmin
X-User-Id, X-Forwarded-User, X-Tenant-Id
checkPassword, skipValidation
```

### 1.3 Active Discovery via Parameter Injection

- [ ] Add each candidate parameter to an authenticated request (both query string and JSON body)
- [ ] Monitor for behavior changes: different data returned, different user context, different permissions
- [ ] Use a second account's ID as the override value — if the response changes to show the second account's data, override is confirmed

When you inject the **whole candidate-parameter wordlist** (from
`agent/references/payloads/bff-override-params.md`) one parameter per request, do not eyeball each
response for the one that took effect. Capture every response as a record and rank the divergence —
the parameter the BFF actually honoured produces a response that breaks from the
identical-to-baseline cluster:

```bash
# one {url,status,content_length,title} record per injected param → bff_inject.jsonl
# (set url to the param name you injected so the ranking names the culprit), then:
vigil assess anomaly-score bff_inject.jsonl --top 5
#   #1  score=4.17  status=200  len=2210  url=param:notAuthUserId   ← this override changed the response
#       ^ length_bucket=...  ^ title='...'                          every ignored param matched baseline
```

The top-ranked record is the override candidate (its body/size/status diverged); the flat tail is
the params the backend ignored. The oracle surfaces category-level breaks (size-class jump, status
flip, title change), so confirm the winner with the pairwise baseline→override→revert protocol in
Phase 3 before calling it.

---

## Phase 2: Override Testing

### 2.1 Identity Override (Critical — Account Takeover)

The most impactful variant: overriding the authenticated user's identity.

```bash
# Baseline: authenticated request as User A
curl -H "Cookie: session=USER_A_TOKEN" \
  https://target/api/profile
# Returns User A's profile

# Override: inject userId parameter
curl -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"notAuthUserId": "USER_B_ID"}' \
  https://target/api/profile
# If returns User B's profile → CRITICAL

# Try as query param
curl -H "Cookie: session=USER_A_TOKEN" \
  "https://target/api/profile?userId=USER_B_ID"

# Try as header
curl -H "Cookie: session=USER_A_TOKEN" \
  -H "X-User-Id: USER_B_ID" \
  https://target/api/profile
```

**Test matrix for identity override:**
- [ ] Query parameter: `?userId=VICTIM_ID`, `?user_id=VICTIM_ID`, `?notAuthUserId=VICTIM_ID`
- [ ] JSON body field: `{"userId": "VICTIM_ID"}`, `{"$id$": "VICTIM_ID"}`
- [ ] Custom header: `X-User-Id`, `X-Forwarded-User`, `X-Real-User-Id`
- [ ] Cookie field: add `userId=VICTIM_ID` cookie alongside session cookie

**No second account?** Generate the override value from your *own* identity. Classify your
session-derived ID and use its `escalation`/`boundary`/`neighbor` variants as the `VICTIM_ID`
candidates — these surface the first/admin object and adjacent records without needing a captured
victim ID:
```bash
vigil assess classify-payload "$MY_USER_ID" --mutations
#   sequential_id → escalation '1' '0' 'admin' 'root';  neighbor ±1/±2;  boundary 0/-1/99999999
#   uuid          → escalation 00000000-...-000000000000 / ...-000000000001 (likely first/admin user)
```

### 2.2 Tenant/Organization Override (High — Cross-Tenant Access)

```bash
# Test org/agency context override
curl -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"$agencyId$": "OTHER_AGENCY_ID", "$originId$": "OTHER_ORIGIN_ID"}' \
  https://target/api/orders

# Try as query param
curl -H "Cookie: session=USER_A_TOKEN" \
  "https://target/api/orders?tenantId=OTHER_TENANT&orgId=OTHER_ORG"
```

### 2.3 Permission/Role Override (High — Privilege Escalation)

```bash
# Test role escalation via hidden params
curl -H "Cookie: session=REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"isAdmin": true, "role": "admin", "checkPassword": false}' \
  https://target/api/admin/users

# Test validation bypass
curl -H "Cookie: session=USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"nonAuthorizedUpdate": true, "skipValidation": true}' \
  https://target/api/users/SELF/role
```

### 2.4 Object Resolution Override (High — IDOR via BFF)

When the BFF resolves object ownership but the backend accepts a different object:

```bash
# BFF sets $objectOwnerId$ from session, but client can override
curl -H "Cookie: session=USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orderId": "VICTIM_ORDER_ID", "$ownerId$": "VICTIM_USER_ID"}' \
  https://target/api/orders/export
```

---

## Phase 3: Confirm Override vs Ignore

A parameter that gets silently ignored is not a finding. Confirm the override by demonstrating a state change:

### Confirmation Protocol

1. **Baseline**: Make the request normally, capture response (User A data)
2. **Override**: Add the internal parameter pointing to User B
3. **Verify divergence**: Response contains User B's data, not User A's
4. **Prove it's the parameter**: Remove the override, confirm response reverts to User A
5. **Cross-validate**: Use a third identity to confirm it's not coincidental

### False Positive Signals (Stop Testing)

- Parameter is accepted but response is identical to baseline → backend ignores it
- Parameter triggers a validation error with the internal name → backend validates but rejects
- Parameter works but only in combination with a valid admin session → not an override, just an admin feature

---

## Phase 4: Escalate Impact

Once override is confirmed, demonstrate the full attacker outcome:

- [ ] **Identity override**: Access victim's sensitive data (PII, financial, messages)
- [ ] **Identity override + write**: Modify victim's account (change email, add payment method)
- [ ] **Tenant override**: Access cross-organization data
- [ ] **Role override**: Perform admin actions (create accounts, export data, delete resources)
- [ ] **Chain**: Override + another finding (e.g., override identity → access admin panel → export all user data)

---

## Discovery Heuristic: The "Mirror Parameter" Test

When you find a parameter in a response or error message that matches a session-derived value, test whether you can supply it:

1. Response contains `"userId": "abc123"` and you're logged in as `abc123`
2. Hypothesis: the BFF set this from your session
3. Test: supply `userId=xyz789` in the request
4. If the response now shows `"userId": "xyz789"` with different data → override confirmed

---

## What to Record

- Endpoint, HTTP method, and the overridable parameter name
- The parameter location (query, body, header, cookie) that achieved the override
- Auth context: whose session was used, whose data was accessed
- Proof of divergence: baseline response vs override response
- Attacker outcome: what the attacker gains (not just "parameter is accepted")
- Severity:
  - **Critical**: Identity override enabling account takeover or full impersonation
  - **High**: Tenant/org override enabling cross-tenant data access, or role elevation
  - **Medium**: Object resolution override with limited data exposure
  - **Low**: Override accepted but limited to non-sensitive context

## Kill Signals — Stop Testing When

- All candidate parameters are rejected with validation errors → middleware strips or validates
- Backend returns identical responses regardless of override values → parameter is ignored
- Override requires an existing admin session to work → it's an admin feature, not a vulnerability
- Content-Type switching and parameter location variants all produce the same result → the app has type validation on internal params

## Escalate When

- A single parameter override changes the response to show another user's data → full account takeover path, test every endpoint with the override
- The override works on write endpoints (PUT, POST, DELETE) → demonstrate destructive impact (modify victim data)
- The override works without any authentication → unauthenticated access to any user's data via the override parameter alone
- Multiple override parameters are accepted simultaneously → combine for maximum impact (identity + tenant + role)

## Extended Resources

- `agent/references/payloads/bff-override-params.md` — Framework-specific internal parameter wordlists
- `agent/references/api-security/API01-broken-object-level-authz.md` — OWASP BOLA context
- `agent/references/api-security/API05-broken-function-authz.md` — OWASP BFLA context
