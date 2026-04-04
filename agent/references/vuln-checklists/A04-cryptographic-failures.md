# A04:2025 — Cryptographic Failures

## TLS Configuration
- [ ] Enumerate cipher suites: `nmap --script ssl-enum-ciphers -p 443 target`
- [ ] Check for SSLv3, TLS 1.0, TLS 1.1 support (should be disabled)
- [ ] Test for weak ciphers: RC4, DES, 3DES, export-grade ciphers
- [ ] Check for BEAST, POODLE, CRIME, BREACH, Heartbleed vulnerabilities
- [ ] Verify certificate chain validity, expiry, and hostname match
- [ ] Check for HTTP endpoints serving sensitive data without TLS redirect
- [ ] Test HSTS header: `curl -I https://target/` — look for `Strict-Transport-Security`

## Hardcoded Secrets in Source
- [ ] Search JavaScript files for API keys: `apiKey`, `api_key`, `secret`, `token`, `password`
- [ ] Check for AWS credentials in source: `AKIA`, `aws_secret_access_key`
- [ ] Look for private keys embedded in JS bundles or config files
- [ ] Check `.env` exposure: `curl https://target/.env`
- [ ] Check source maps for secrets: `curl https://target/main.js.map`
- [ ] Search for base64-encoded credentials in HTML/JS source
- [ ] Check for Firebase/GCP/Azure credentials in client-side code

## Weak Password Hashing
- [ ] If password hashes are exposed, identify the algorithm (MD5, SHA1, SHA256, bcrypt, scrypt, argon2)
- [ ] Check for unsalted hashes — identical passwords produce identical hashes
- [ ] Verify bcrypt cost factor is >= 10 (if observable from timing or source)
- [ ] Check for reversible encryption used instead of hashing for passwords
- [ ] Look for custom/homegrown hashing schemes in source code

## Insecure Randomness
- [ ] Collect multiple session tokens and analyze for sequential patterns
- [ ] Check reset tokens for predictability: timestamp-based, sequential, short length
- [ ] Test if CSRF tokens are reusable or predictable
- [ ] Verify OTP/verification codes have sufficient entropy (6+ digits, not sequential)
- [ ] Check UUID versions in API responses — UUIDv1 contains timestamp and MAC address

## Sensitive Data Exposure
- [ ] Check API responses for unnecessary sensitive fields: password hashes, SSNs, full CC numbers
- [ ] Look for PII in URL query strings (logged by proxies, servers, browsers)
- [ ] Check if sensitive form data transmitted via GET instead of POST
- [ ] Test for sensitive data in HTTP Referer header leaking to third-party resources
- [ ] Check browser caching headers on sensitive pages: `Cache-Control`, `Pragma`, `Expires`
- [ ] Look for sensitive data in error messages and stack traces

## Cookie Security
- [ ] Verify session cookies have `Secure` flag (prevents transmission over HTTP)
- [ ] Check for sensitive tokens in cookies without `Secure` flag
- [ ] Test if session tokens are transmitted over HTTP on any endpoint

## Encryption at Rest
- [ ] Check if database backups are encrypted (if backup files accessible)
- [ ] Look for cleartext credentials in configuration files
- [ ] Check for sensitive data stored in localStorage/sessionStorage (client-side, unencrypted)
- [ ] Test for sensitive data in browser cache after visiting sensitive pages

## Key Management
- [ ] Check for exposed key material: `/keys/`, `/certs/`, `/.ssh/`
- [ ] Look for JWT secrets in source code or configuration files
- [ ] Check if the same key is used for multiple purposes (signing + encryption)
- [ ] Verify key rotation — are old keys still accepted?

## Framework-Specific Checks
- [ ] **Django**: Check `SECRET_KEY` exposure, verify `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`
- [ ] **Rails**: Check `secret_key_base` exposure, verify `force_ssl` in production
- [ ] **Express**: Check for `express-session` with default secret, missing `secure` cookie flag
- [ ] **Spring**: Check for `jasypt` encrypted properties with weak passwords, exposed `application.properties`
- [ ] **Laravel**: Check `APP_KEY` exposure in `.env`, verify `HTTPS` enforcement

---
> Cross-reference skills: `sensitive-data-detection`, `jwt-testing`
