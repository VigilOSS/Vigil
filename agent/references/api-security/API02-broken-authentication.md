---
description: Missing auth, token validation flaws
skill: auth-bypass
---

# API2:2023 — Broken Authentication

> Skill: `auth-bypass`

## API Key Exposure
- [ ] Search JavaScript bundles for API keys: `grep -r "api[_-]key\|apiKey\|API_KEY" *.js`
- [ ] Check for API keys in URL query strings: `curl "https://api/data?api_key=KEY"` (logged by proxies)
- [ ] Look for keys in mobile app decompiled source or traffic intercepts
- [ ] Check public repositories (GitHub) for leaked API keys matching the target domain
- [ ] Test if API keys are passed in headers vs query params — query params are logged

## Bearer Token Weaknesses
- [ ] Test expired tokens: are they actually rejected? `curl -H "Authorization: Bearer EXPIRED_TOKEN" https://api/me`
- [ ] Test tampered tokens: modify payload, test with corrupt signature
- [ ] Send empty bearer: `curl -H "Authorization: Bearer " https://api/me`
- [ ] Send no auth header at all — is the endpoint truly protected?
- [ ] Test token without `Bearer` prefix: `curl -H "Authorization: TOKEN_VALUE" https://api/me`
- [ ] Check if tokens lack expiry (`exp` claim in JWT) — indefinite session

## Token Rotation & Revocation
- [ ] After password change, test if old tokens still work
- [ ] After logout, test if the access token is invalidated: `curl -H "Authorization: Bearer OLD_TOKEN" https://api/me`
- [ ] Test refresh token reuse: use same refresh token twice — is it single-use?
- [ ] Check if revoking one session invalidates tokens from other sessions

## API Key Scope
- [ ] Test if a read-only API key can perform write operations
- [ ] Test if a user-scoped key can access admin endpoints
- [ ] Check if API keys have IP restrictions that are actually enforced
- [ ] Test if a key scoped to one service can access other services

## Basic Auth & Credential Transport
- [ ] Check for Basic Auth over HTTP (credentials in cleartext): `curl -u user:pass http://api/endpoint`
- [ ] Test if API accepts credentials in query parameters: `?username=x&password=y`
- [ ] Check for credentials in request body without TLS

## Method-Based Auth Bypass
- See [API05 HTTP Method-Based Access Control Bypass](API05-broken-function-authz.md) for full method override and verb tampering tests

---
> Cross-reference: A07 checklist, API05 checklist, `auth-bypass` skill
