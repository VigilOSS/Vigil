# API10:2023 — Unsafe Consumption of APIs

> Skill: `ssrf-testing`

## SSRF via Third-Party API Integration
- [ ] Identify endpoints that fetch external data: URL import, link preview, feed parsing
- [ ] Test if user-controlled URLs are passed to backend HTTP clients without validation
- [ ] Check if third-party API URLs are configurable by the user (webhook URLs, callback URLs)
- [ ] Test redirect following: does the backend follow 302 redirects from external APIs to internal IPs?

## Webhook Receiver — Unsigned Payloads
- [ ] Test incoming webhook endpoints without signature header: `curl -X POST -d '{"event":"payment.success","amount":0}' https://api/webhooks/stripe`
- [ ] Test with invalid signature: modify `X-Hub-Signature` or equivalent header value
- [ ] Test webhook replay: resend a captured webhook payload — is there replay protection?
- [ ] Test webhook body manipulation: change event type, amounts, user IDs in the payload
- [ ] Check if webhook endpoints are publicly discoverable and accessible without auth

## OAuth Token Exchange Validation
- [ ] Test if the application validates the `issuer` in tokens received from OAuth providers
- [ ] Check if the application blindly trusts claims from the identity provider without verification
- [ ] Test token substitution: use token from one OAuth provider where another is expected
- [ ] Check if `audience` (`aud`) claim is validated — token meant for another service accepted?

## Data from Trusted Partners
- [ ] Check if data received from partner APIs is sanitized before storage/display (XSS, SQLi)
- [ ] Test if partner API response fields are blindly trusted for access control decisions
- [ ] Check if price/inventory data from external APIs is validated before business logic use
- [ ] Test for injection via partner-supplied data rendered in the UI without encoding

## Third-Party API Failure Handling
- [ ] Test behavior when a third-party API is unavailable — fail-open or fail-closed?
- [ ] Check if timeout on external API calls leads to denial of service or resource exhaustion
- [ ] Test if error responses from third-party APIs leak internal state to the user
- [ ] Check for verbose logging of external API requests (may expose secrets in logs)

## Supply Chain via API Dependencies
- [ ] Identify all external API dependencies: payment processors, auth providers, analytics, CDNs
- [ ] Check if any external APIs are accessed over HTTP (not HTTPS)
- [ ] Verify TLS certificate validation on outbound API calls (not disabled for convenience)
- [ ] Check for hardcoded third-party API credentials in application source

---
> Cross-reference: A05 checklist, `ssrf-testing` skill
