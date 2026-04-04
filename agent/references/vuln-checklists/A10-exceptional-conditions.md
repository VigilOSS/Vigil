# A10:2025 — Mishandling of Exceptional Conditions

## Error-Based Information Disclosure
- [ ] Send malformed JSON body and inspect error response for framework details
- [ ] Send wrong Content-Type header and check for stack trace in response
- [ ] Trigger 500 errors with long strings, special characters, null bytes (`%00`)
- [ ] Test with unexpected data types: string where int expected, array where string expected
- [ ] Check error pages for server version, framework version, file paths, class names
- [ ] Send oversized headers to trigger buffer/parsing errors with verbose output
- [ ] Test with invalid Unicode sequences to trigger encoding error disclosure
- [ ] Force errors in different response formats: add `Accept: application/json` vs `text/html`

## Fail-Open Conditions
- [ ] Test authentication when backend auth service is slow: does timeout grant access?
- [ ] Send malformed auth tokens — does the app fail-open or fail-closed?
- [ ] Test with empty `Authorization` header vs missing `Authorization` header (different behavior?)
- [ ] Remove CSRF token entirely — does the request succeed? (fail-open CSRF)
- [ ] Test with invalid session cookie — does it create a new authenticated session?
- [ ] Check if rate limiter failure grants unlimited access instead of blocking

## Resource Exhaustion
- [ ] Send repeated requests that trigger errors — does error handling itself exhaust resources?
- [ ] Test connection pool exhaustion: open many connections without completing requests
- [ ] Send requests that trigger expensive error processing (large regex, complex parsing)
- [ ] Test file descriptor exhaustion via rapid file upload/download requests
- [ ] Check for memory leaks triggered by specific error conditions

## Transaction Rollback Abuse
- [ ] Interrupt multi-step transactions at each step — does partial state persist incorrectly?
- [ ] Test payment flow: complete payment step, force error on confirmation — is money deducted but order not created?
- [ ] Test concurrent conflicting operations: simultaneous update + delete on same resource
- [ ] Check if failed transactions leave database in inconsistent state
- [ ] Test idempotency: replay a successful request — does it duplicate the action?

## Race Conditions in Error Handlers
- [ ] Send concurrent requests that trigger the same error handler — thread-safety issues?
- [ ] Test for TOCTOU in error recovery paths (file cleanup, temp file handling)
- [ ] Send simultaneous requests to error-prone endpoints to test shared state corruption
- [ ] Check if error logging under load introduces race conditions or data loss

## Graceful Degradation Bypasses
- [ ] Test behavior when a dependent microservice is unavailable
- [ ] Check if feature flags / circuit breakers expose unprotected fallback behavior
- [ ] Test if degraded mode bypasses security controls (auth, rate limiting, input validation)
- [ ] Verify that fallback endpoints maintain the same security posture as primary endpoints

## Error Page XSS & Injection
- [ ] Test for reflected XSS in custom error pages: `https://target/<script>alert(1)</script>`
- [ ] Check if 404 pages reflect the requested URL without encoding
- [ ] Test for injection in error messages that echo user input: `Invalid value: [USER_INPUT]`
- [ ] Check if error pages load external resources that could be manipulated

## Unhandled Exception Patterns
- [ ] Send `null` / `undefined` / `NaN` / `Infinity` in numeric fields
- [ ] Test with empty arrays `[]` and objects `{}` where scalar values expected
- [ ] Send extremely long strings (10K+ chars) in each parameter
- [ ] Test with special float values: `1e308`, `-1e308`, `1e-324`
- [ ] Send deeply nested JSON objects (100+ levels) to test stack depth limits
- [ ] Test with circular reference patterns in JSON (if custom parser)

## Framework-Specific Checks
- [ ] **Django**: Check `DEBUG=True` in production (detailed tracebacks), `ALLOWED_HOSTS` empty
- [ ] **Rails**: Check `config.consider_all_requests_local`, custom error pages in `public/`
- [ ] **Express**: Check for default error handler exposing stack traces, `NODE_ENV` not set to `production`
- [ ] **Spring**: Check `server.error.include-stacktrace`, custom `@ControllerAdvice` coverage
- [ ] **Next.js**: Check custom `_error.js` / `error.tsx` pages, API route error handling
- [ ] **Laravel**: Check `APP_DEBUG=true` in production, custom exception handler coverage

---
> Cross-reference skills: `info-disclosure-testing`, `race-condition-testing`
