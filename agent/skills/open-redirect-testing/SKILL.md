---
name: open-redirect-testing
description: Detect open redirect vulnerabilities and chain them with OAuth token theft, XSS, and SSRF for real impact
origin: Vigil
vuln_class: open-redirect
---

# Open Redirect Testing

## When to Activate

- A parameter carries a URL or path (`next`, `returnTo`, `redirect_uri`, `RelayState`, `url`),
  login/logout and SSO flows, payment completion, email-verification return URLs, or any
  user-influenced `Location`.

An open redirect alone is usually a chain component (`agent/agents/vulnerability-analyst.md`
"Conditionally Valid Chains"); the work is finding the chain. Phishing value goes in the narrative
without inflating severity.

`--technique OPEN-REDIRECT`. Parameter names and bypass families (protocol-relative, `/\`,
userinfo `@`, subdomain suffix, double encoding, backslash, null, tab/newline, CRLF, fragment,
traversal, IDN/punycode): `agent/references/payloads/open-redirect-payloads.md`. Seed variants with
`vigil assess classify-payload <value> --mutations` (`boundary` gives `javascript:`/`file:`
probes, `format` scheme-downgrade and quoted variants), then sweep them so each response keeps its
body and `Location`:

```bash
vigil assess kali sweep --technique OPEN-REDIRECT --intent "redirect bypass sweep" \
  --probe-kind payload --phase consume-test --timeout 30 --values-file variants.txt \
  -- curl -s -i "https://target.example/login?next={}"
```

## Method

1. **Server-side (3xx) or client-side (JavaScript)?** Server redirects carry cookies and take part
   in OAuth flows; client-side redirects can become XSS. When a redirect is blocked, read the page:
   a failed redirect sometimes renders the URL into HTML or JS.
2. **Map the validator** from which variants pass: substring, `startsWith`, `endsWith` or
   host-parsed. `https://trusted.example.attacker.example` and `https://attacker.example/
   trusted.example` separate them.
3. **Chain:**
   - **OAuth/OIDC** (`agent/skills/oauth-oidc-testing/SKILL.md`): with a lax `redirect_uri`, or a
     strict prefix that admits the open redirect, the code or token leaves the trusted origin. A
     302 does not carry the original query string onward, so a `?code=` reaches the attacker only
     through the fragment (implicit flow, `response_mode=fragment` — fragments survive
     redirects), the `Referer`, or a redirector that appends the query. `response_mode=form_post`
     delivers the code in a POST body and defeats the chain.
   - **XSS:** `javascript:` or `data:` accepted into `window.location`, an anchor `href` or meta
     refresh is reflected XSS (`agent/skills/xss-testing/SKILL.md`).
   - **SSRF gadget:** a server-side fetcher (webhooks, previews, imports) that follows redirects
     turns the trusted redirect into an allowlist bypass. A callback through the redirect shows the
     fetcher follows it; impact needs internal reach (`agent/skills/ssrf-testing/SKILL.md`). No
     callback can mean egress filtering or a fetcher that does not follow redirects, not only a
     client-side redirect.

## What to Record

Parameter and endpoint, the bypass that worked and which were blocked (the validator's logic),
server- vs client-side, the chain and its demonstrated outcome (`agent/rules/hunting.md` §2), and a
working PoC link. Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- Every bypass family failing on every redirect parameter → validation holds; record the negative
  with its run ids (`agent/rules/hunting.md` §13).
- A confirmed chain on one parameter → check sibling redirect parameters and flows
  (`agent/rules/hunting.md` §6).
- Escalate when the parser disagrees with the browser (any of the confusion forms passes), the
  parameter sits in an OAuth/SSO/SAML/reset flow, or a script scheme is accepted.
