# A06:2025 — Insecure Design

## Business Logic Flaws
- [ ] Test negative quantity/price in e-commerce: `{"quantity": -1}`, `{"price": 0.01}`
- [ ] Test workflow step skipping: jump from step 1 to step 3 in multi-step checkout/registration
- [ ] Test parameter manipulation in pricing: modify discount codes, coupon values, shipping costs
- [ ] Test for coupon/promo code reuse beyond intended limits
- [ ] Test currency rounding abuse: small transactions that round in attacker's favor
- [ ] Verify referral system abuse: self-referral, circular referral chains
- [ ] Test gift card / store credit creation and balance manipulation
- [ ] Check if removing items from cart after applying discount retains the discount

## Missing Rate Limits
- [ ] Test login endpoint: send 100+ requests with wrong password — is there throttling?
- [ ] Test registration: can you create unlimited accounts from same IP?
- [ ] Test password reset: unlimited reset emails to a victim?
- [ ] Test OTP/2FA verification: can you brute-force 4-6 digit codes without lockout?
- [ ] Test API endpoints for missing rate limits: `for i in $(seq 1 200); do curl -s ...; done`
- [ ] Check if rate limits apply per-IP only — can you bypass with `X-Forwarded-For` rotation?
- [ ] Test SMS/email bombing via API endpoints that trigger notifications

## Anti-Automation Gaps
- [ ] Check for missing CAPTCHA on login, registration, password reset, contact forms
- [ ] Test if CAPTCHA token is reusable across multiple requests
- [ ] Test if CAPTCHA can be bypassed by removing the CAPTCHA parameter entirely
- [ ] Check for missing bot detection on scraping-sensitive endpoints (search, listings)

## Workflow & Process Bypass
- [ ] Test state manipulation: complete payment without completing address step
- [ ] Replay successful transaction requests to duplicate actions
- [ ] Test race conditions in balance/inventory operations (see `race-condition-testing` skill)
- [ ] Concurrent requests to claim same resource: `parallel curl ... ::: {1..10}`
- [ ] Test TOCTOU (Time-of-check-to-time-of-use) in file operations and transactions

## Account Security Design
- [ ] Test for missing account lockout after N failed login attempts
- [ ] Check if locked accounts can still use "remember me" tokens or API keys
- [ ] Test account takeover via predictable security question answers
- [ ] Verify email/phone verification cannot be skipped in registration flow
- [ ] Test if account deletion is truly permanent or if data persists and is re-accessible

## Resource & Upload Limits
- [ ] Test unlimited file uploads: no count limit per user?
- [ ] Test oversized file uploads: 100MB, 1GB files accepted?
- [ ] Test resource creation without limits: unlimited projects, teams, API keys
- [ ] Check for missing pagination on data export endpoints (memory exhaustion)

## Trust Boundary Violations
- [ ] Test if client-side validation is the only validation (bypass with direct API calls)
- [ ] Check if frontend role/permission checks are enforced server-side
- [ ] Test if hidden form fields or disabled UI elements are enforced server-side
- [ ] Verify that client-supplied data used in server-side decisions is validated

## Predictable Resource Locations
- [ ] Test for sequential/predictable file names in uploads: `/uploads/1001.pdf`, `/uploads/1002.pdf`
- [ ] Check if temporary/generated URLs follow predictable patterns
- [ ] Test for predictable backup locations: `/backup/db_2024-01-01.sql`

## Framework-Specific Checks
- [ ] **Django**: Check for `LoginRequiredMixin` missing on CBVs, `ATOMIC_REQUESTS` for race conditions
- [ ] **Rails**: Test `strong_parameters` bypass, check `skip_before_action` misuse
- [ ] **Express**: Verify input validation middleware (express-validator, joi) on all routes
- [ ] **Spring**: Check `@Transactional` isolation levels for race conditions
- [ ] **Next.js**: Test if middleware-based auth can be bypassed via direct API route access
- [ ] **Laravel**: Check for mass assignment via `$fillable`/`$guarded` misconfiguration

---
> Cross-reference skills: `business-logic-testing`, `race-condition-testing`
