# A07:2025 — Authentication Failures

## Credential Stuffing & Brute Force
- [ ] Test login endpoint with 50+ requests using wrong passwords — any rate limiting?
- [ ] Check for CAPTCHA on login after N failures
- [ ] Test if account lockout triggers after repeated failures (and how many)
- [ ] Test if lockout is per-IP, per-account, or both
- [ ] Verify lockout cannot be bypassed with `X-Forwarded-For` or `X-Real-IP` header rotation
- [ ] Test with default credentials: `admin:admin`, `admin:password`, `test:test`

## User Enumeration
- [ ] Compare login error messages: "Invalid username" vs "Invalid password" (should be identical)
- [ ] Test registration: does it reveal existing usernames/emails?
- [ ] Test password reset: different responses for valid vs invalid emails?
- [ ] Check response timing differences between valid and invalid usernames
- [ ] Test enumeration via API error messages: `/api/users/check?email=...`

## Session Management
- [ ] Test session fixation: set a known session ID before login, check if it changes after auth
- [ ] Verify session ID regeneration on privilege change (login, role change, password change)
- [ ] Test logout: does the session cookie get invalidated server-side? `curl -b "session=OLD_TOKEN" https://target/profile`
- [ ] Check session token in URL parameters (leaked via Referer header, logs, browser history)
- [ ] Test session timeout: does the session expire after reasonable inactivity (15-30 min)?
- [ ] Test concurrent sessions: can the same account have unlimited active sessions?
- [ ] Check session token entropy: collect 10+ tokens and analyze for patterns
- [ ] Verify session cookies have `HttpOnly`, `Secure`, `SameSite` flags

## Password Reset Flaws
- [ ] Test reset token predictability: are tokens sequential, timestamp-based, or short?
- [ ] Test reset token expiry: does a 24-hour-old token still work?
- [ ] Test token reuse: can the same reset link be used multiple times?
- [ ] Test host header poisoning: `Host: evil.example` — does the reset email contain evil.example URL?
  ```
  curl -X POST https://target/reset -H "Host: evil.example" -d "email=victim@target.example"
  ```
- [ ] Test if reset link leaks via Referer header when page loads external resources
- [ ] Check if password reset invalidates existing sessions

## MFA Bypass
- [ ] Test if MFA step can be skipped by directly accessing post-auth endpoints
- [ ] Test brute force on OTP codes (4-6 digits) without lockout
- [ ] Check if MFA backup codes are predictable or reusable
- [ ] Test if MFA can be disabled without re-authentication
- [ ] Check for MFA bypass via API endpoints that don't enforce 2FA
- [ ] Test response manipulation: change MFA verification response from `false` to `true`

## OAuth & SSO Misconfigurations
- [ ] Test `redirect_uri` manipulation: open redirect, parameter pollution, path traversal
- [ ] Check for OAuth `state` parameter — missing or predictable (CSRF in OAuth flow)
- [ ] Test token exchange with tampered authorization codes
- [ ] Verify `scope` parameter cannot be escalated by the client
- [ ] Check if OAuth tokens have appropriate expiry
- [ ] Test for account linking flaws: can attacker link their OAuth to victim's account?

## JWT Weaknesses
- [ ] Test `alg: none` bypass — remove signature, set algorithm to none
- [ ] Test algorithm confusion: change RS256 to HS256 and sign with public key
- [ ] Modify claims (`sub`, `role`, `admin`) and test with re-signed or stripped tokens
- [ ] Test `kid` header for injection: path traversal, SQLi
- [ ] Check for JWK/JWKS injection via `jku` or `x5u` headers
- [ ] Verify token expiry (`exp` claim) is actually enforced server-side

## Remember-Me Token Security
- [ ] Check if "remember me" tokens are invalidated on password change
- [ ] Test if remember-me tokens are predictable (username + timestamp)
- [ ] Verify remember-me tokens expire after reasonable period (30 days max)
- [ ] Check if remember-me bypasses MFA requirement

## Framework-Specific Checks
- [ ] **Django**: Check `SESSION_COOKIE_AGE`, `SESSION_EXPIRE_AT_BROWSER_CLOSE`, `CSRF_COOKIE_HTTPONLY`
- [ ] **Rails**: Test `has_secure_password` implementation, check `config.force_ssl`
- [ ] **Express**: Check `express-session` configuration: `resave`, `saveUninitialized`, `cookie.secure`
- [ ] **Spring Security**: Test remember-me token generation, check `SessionCreationPolicy`
- [ ] **Next.js**: Test `next-auth` session strategy, check JWT secret strength
- [ ] **Laravel**: Check `session.lifetime`, `session.expire_on_close`, guard configuration

---
> Cross-reference skills: `auth-bypass`, `jwt-testing`, `user-enumeration`
