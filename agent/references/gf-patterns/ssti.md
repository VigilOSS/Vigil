---
name: gf-patterns:ssti
description: Template-rendering parameter patterns that signal server-side template injection surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: ssti
skill: ssti-testing
weight: 25
---

# gf: ssti

## What this bucket classifies

Parameters whose names suggest the server picks a template, theme, or layout name from
user input. These are the surfaces for Jinja2, Twig, Freemarker, ERB, and Pug template
injection — often a direct RCE path in modern stacks.

## Load this reference when

- The corpus has `?template=`, `?tpl=`, `?theme=`, `?layout=`, or `?view=` keys
- Tech fingerprinting identified a template-engine-backed stack (Flask/Jinja2, Symfony/Twig, Spring/Freemarker)
- Operator wants to separate SSTI candidates from LFI candidates (both share `template`)

## Parameter keys that match

`template, tpl, theme, layout, view`

## Path patterns that match

None — ssti is keyed entirely off parameter names.

## Weight and priority interpretation

- Baseline priority score: 25
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/render?template=welcome` — classic Jinja2/Twig surface
- `https://target.example/preview?view=product-card` — render-from-name endpoint
- `https://target.example/theme/switch?theme=dark` — theme name fed into template resolver
- `https://target.example/email/send?tpl=invite&to=...` — email template picker
- `https://target.example/dashboard?layout=admin&view=report` — compound layout+view surface

## What it does NOT classify

- File-include style LFI that happens to use `?page=` — those land in `lfi`
- Pure static theme CSS swaps with no server-side template resolution — surface as low-risk and skip deeper testing

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

## Related

- `agent/references/payloads/ssti-payloads.md` — per-engine detection and RCE payloads
- `agent/references/gf-patterns/lfi.md` — adjacent bucket (overlaps on `template` keys)
- `agent/references/gf-patterns/rce.md` — adjacent bucket (confirmed SSTI typically escalates to rce)
