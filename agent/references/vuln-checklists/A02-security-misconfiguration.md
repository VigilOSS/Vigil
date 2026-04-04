# A02:2025 — Security Misconfiguration

## Default Credentials & Admin Panels
- [ ] Test default credentials on login forms: `admin:admin`, `admin:password`, `root:toor`, `test:test`
- [ ] Check common admin paths: `/admin`, `/administrator`, `/manager`, `/wp-admin`, `/phpmyadmin`
- [ ] Test database admin panels: phpMyAdmin, Adminer, pgAdmin default creds
- [ ] Check for default API keys or tokens in documentation/sample configs

## Verbose Errors & Information Disclosure
- [ ] Trigger errors with malformed input and check for stack traces in responses
- [ ] Send invalid Content-Type to provoke framework error pages
- [ ] Check for detailed error messages: SQL errors, file paths, class names, versions
- [ ] Test 404/500 pages for framework/server version disclosure
- [ ] Send oversized headers or body to trigger buffer-related error messages

## Debug Endpoints
- [ ] **Spring Boot Actuator**: `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`
- [ ] **Django**: `/admin/`, `/__debug__/`, check `DEBUG=True` error pages
- [ ] **Rails**: `/_rails/info/properties`, `/rails/info/routes`
- [ ] **Express**: Check for `NODE_ENV=development` behaviors, `/debug`, `/status`
- [ ] **Laravel**: `/_ignition`, `/_debugbar`, `/telescope`
- [ ] **ASP.NET**: `/elmah.axd`, `/trace.axd`, `/__browserLink`
- [ ] **PHP**: `/info.php`, `/phpinfo.php`, `?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000`
- [ ] **Symfony**: `/_profiler`, `/_wdt`
- [ ] **Next.js**: `/_next/data/`, `/__nextjs_original-stack-frame`

## HTTP Security Headers
- [ ] Check headers: `curl -I https://target/`
- [ ] Missing `Strict-Transport-Security` (HSTS) — allows SSL stripping
- [ ] Missing `Content-Security-Policy` (CSP) — enables XSS exploitation
- [ ] Missing `X-Frame-Options` or CSP `frame-ancestors` — clickjacking risk
- [ ] Missing `X-Content-Type-Options: nosniff` — MIME-type sniffing attacks
- [ ] Missing `Referrer-Policy` — leaks URLs to third parties
- [ ] Missing `Permissions-Policy` — unrestricted browser feature access
- [ ] Overly permissive CSP: `unsafe-inline`, `unsafe-eval`, wildcard sources

## Directory Listing & File Exposure
- [ ] Test directory listing: `curl https://target/images/`, `curl https://target/uploads/`
- [ ] Check for exposed configuration files: `/.env`, `/config.yml`, `/web.config`, `/wp-config.php.bak`
- [ ] Test backup file discovery: `/index.php.bak`, `/app.js.old`, `/database.sql`
- [ ] Check for `.DS_Store`, `Thumbs.db` files leaking directory contents

## CORS Misconfiguration
- [ ] Test `Access-Control-Allow-Origin: *` with credential-bearing requests
- [ ] Check for reflected origin without validation
- [ ] Test with `Origin: null` header

## Unnecessary HTTP Methods
- [ ] `curl -X OPTIONS https://target/` — check for TRACE, PUT, DELETE enabled unnecessarily
- [ ] Test TRACE method for cross-site tracing: `curl -X TRACE https://target/`

## TLS Misconfiguration
- [ ] Check for SSLv3, TLS 1.0, TLS 1.1 support: `nmap --script ssl-enum-ciphers -p 443 target`
- [ ] Test for weak ciphers (RC4, DES, export ciphers)
- [ ] Check certificate validity, hostname mismatch, self-signed certs
- [ ] Test HTTP to HTTPS redirect — is sensitive data sent over HTTP first?

## Cookie Flags
- [ ] Verify `Secure` flag on session cookies (not sent over HTTP)
- [ ] Verify `HttpOnly` flag (not accessible via JavaScript)
- [ ] Verify `SameSite=Strict` or `SameSite=Lax` (CSRF protection)
- [ ] Check cookie `Path` and `Domain` scope — overly broad?

## Cloud & Storage Misconfiguration
- [ ] S3 bucket permissions: `curl https://BUCKET.s3.amazonaws.com/` (list), `curl -X PUT` (write)
- [ ] Azure blob public access: `curl https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list`
- [ ] GCS bucket listing: `curl https://storage.googleapis.com/BUCKET`

---
> Cross-reference skills: `info-disclosure-testing`, `web-recon`
