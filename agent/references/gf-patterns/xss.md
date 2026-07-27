---
name: gf-patterns:xss
description: Reflected-input parameter patterns that signal cross-site scripting surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: xss
skill: xss-testing
weight: 20
---

# gf: xss

## What this bucket classifies

Parameters commonly reflected back into HTML, JSON, or HTML-attribute contexts. These are
the starting surfaces for reflected XSS, DOM XSS via server-rendered payloads, and stored
XSS when the parameter feeds a comment/message sink.

## Load this reference when

- The corpus contains `?q=`, `?search=`, `?message=`, `?comment=`, or `?name=` query keys
- Known-vulnerable frameworks (jQuery mobile, older Rails ERB templates) show in tech fingerprinting
- Operator wants XSS candidates to feed dalfox scanning separate from the search/sqli list

## Parameter keys that match

`q, query, search, keyword, name, message, comment, text, content, input, data`

## Path patterns that match

None — xss is keyed entirely off parameter names.

## Weight and priority interpretation

- Baseline priority score: 20 (lower than sqli because reflection context varies)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/search?q=<script>alert(1)</script>` — classic reflected
- `https://target.example/profile/update?name=<img src=x onerror=alert(1)>` — stored vector via display name
- `https://target.example/contact?message=...&email=...` — message field reflected into confirmation page
- `https://target.example/notes?content=...&text=...` — rich-text editor sink
- `https://target.example/api/feedback?comment=...&input=...` — comment surface reflected into admin UI

## What it does NOT classify

- JSON-only API endpoints where `Content-Type: application/json` prevents script execution in most clients — record as surface but de-prioritize until a browser-rendering sink is proved
- Login form POST body values without reflection — those land in auth-bypass testing, not xss
- Output in downloaded PDFs/DOCX — covered by file-upload-testing reaction chains, not gf

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

## Related

- `agent/skills/xss-testing/SKILL.md` — the follow-up test skill
- `agent/references/payloads/xss-payloads.md` — payload library (filter bypass, CSP bypass, polyglots)
- `agent/references/tools/exploitation/dalfox.md` — XSS-focused scanner
