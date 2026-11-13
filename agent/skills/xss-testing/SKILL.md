---
name: xss-testing
description: Detect and exploit cross-site scripting vulnerabilities in web applications — DOM XSS in modern SPAs, framework-specific sinks, CSP bypass, blind XSS, and impact escalation
origin: Vigil
vuln_class: xss
---

# Cross-Site Scripting (XSS) Testing

## When to Activate

- Input reflects into HTML, attributes, scripts or URLs; an SPA renders user data client-side;
  content persists and renders to other users, admins, emails, PDFs or logs.

`--technique XSS`. Scanner: the typed `vigil assess kali dalfox` verb (flags, pipe mode, blind
mode: `agent/references/tools/exploitation/dalfox.md`); manual probes through
`vigil assess kali exec … -- curl …`. Payload families (the framework sink table, CSP bypass
gadgets including AngularJS `ng-csp`, filter evasion without parentheses or `alert`, hidden-input
handlers, mutation XSS, polyglots):
`agent/references/payloads/xss-payloads.md` and `agent/references/web/waf-bypass-and-safe-testing.md`.
Prioritise client-side framework sinks in modern apps over classic reflection.

## Where to spend effort

- **dalfox vs manual.** Run dalfox on server-rendered pages with visible reflection or a large
  parameter surface (pipe hundreds of URLs). Skip it for SPAs that render client-side,
  WebSocket-driven UIs, multi-step stored flows, and heavily rate-limited WAF targets: it misses
  DOM sinks and cannot test stored flows.
- **DOM:** trace taint from `location`, hash, `postMessage`, `window.name`, `document.referrer`
  and fetched text to sinks before spraying payloads. **DOMPurify misconfiguration** is common:
  dangerous tags allowlisted (`ADD_TAGS: ['iframe']`), sanitising after the sink
  (`innerHTML = x; sanitize(el)`), code paths that skip it, or an old or custom sanitizer that
  mutation XSS (namespace confusion, payload reference "Mutation XSS") gets through.
- **Framework escape hatches** (payload reference "Framework Sinks"): React
  `dangerouslySetInnerHTML`, `ref.innerHTML` and `javascript:` hrefs (React logs a warning in
  older versions rather than blocking; confirm the version's behaviour), Angular
  `bypassSecurityTrust*` and the AngularJS sandbox, Vue `v-html` and runtime compile, jQuery
  `.html()`/`$()`, markdown renderers with raw HTML (rehypeRaw). **SSR hydration mismatch:** the
  server renders sanitised HTML and the client hydrates from a different source (Next.js
  `getServerSideProps` vs `useSearchParams`).
- **Context break-outs:** a marker surviving even encoded means walk the contexts — attribute,
  `<script>` body, `href`/`src`, `on*`, JSON assigned to a JS variable (`</script>` inside a JSON
  string), template literals.
- **CSP** is gadget-driven: `unsafe-inline`/`unsafe-eval`, wildcard or JSONP hosts on allowed
  origins, `data:` in `script-src`, missing `base-uri`, AngularJS or other script gadgets.
- **Stored:** a unique canary per field, then visit every render surface (profile, admin user
  lists, search, HTML email, PDF export, API consumers); admin views often escape less. Filenames
  and image/document metadata render in file managers and logs.
- **Blind:** plant in fields an internal tool renders (ticket subject/body/filenames, profile
  fields, headers that reach log viewers, upload metadata, moderation queues). Mint one OOB host
  per field with the field in `--param` so the hit names it
  (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)").
  Fields that reach human staff (support tickets, contact forms) need the side-effect preflight
  (`agent/shared-constraints.md` §2d). Triggers can fire days or weeks later: poll periodically.
  A bare fetch of the script URL can come from a renderer, prefetcher or scanner; execution is
  proven by the exfil body (`location.href`, a DOM excerpt) arriving.

## Proof and severity

`alert(1)` proves execution; the report needs the attacker outcome (`agent/rules/hunting.md` §2):
the page it fired on, a session or token reachable, the admin action reachable. Severity follows
`agent/references/finding-fp-and-severity-gate.md`; a blind XSS inherits the blast radius of the
panel it fires in (user management, payments, config, API keys). Chains worth checking: cookie or
token theft → account takeover; stored → admin list → admin CSRF; XSS + permissive CORS →
cross-origin reads; subdomain XSS + wildcard CSP → main-domain bypass; self-XSS + login CSRF.

## Kill Signals

- Pure JSON API with no HTML rendering.
- Strict CSP with none of the gaps above.
- Framework auto-escaping everywhere and no escape-hatch usage found.
- dalfox plus manual DOM tracing find no reflection across the full parameter set (record the
  negative with its tier and run ids, `agent/rules/hunting.md` §13).

A confirmed stored XSS on one endpoint is a reason to check its other render surfaces and
sibling fields, not to stop (`agent/rules/hunting.md` §6).
