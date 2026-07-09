---
name: gf-patterns:prototype-pollution
description: Object-merge gadget key patterns (__proto__/constructor/prototype) that signal server-side prototype pollution surfaces
origin: Vigil (vuln-taxonomy-audit 2026-07 — no upstream 1ndianl33t/Gf-Patterns equivalent exists)
bucket: prototype-pollution
weight: 35
---

# gf: prototype-pollution

## What this bucket classifies

Requests whose query/body/path parameters already carry a literal `__proto__`, `constructor`,
or `prototype` key — the exact gadget names that reach a vulnerable recursive object-merge
(Lodash `merge`/`defaultsDeep`-style helpers, or an equivalent in any language) and pollute
`Object.prototype`, corrupting every object's default property lookups. Server-side prototype
pollution can escalate to denial-of-service, auth bypass, or RCE via a gadget chain depending
on how the polluted property is later consumed.

## Load this reference when

- A captured request body already contains a `__proto__`, `constructor`, or `prototype` key —
  including as a **compound bracket path** such as `constructor[prototype][isAdmin]`, which
  `classify_buckets.expand_compound_key` decomposes so the inner `constructor`/`prototype`
  token still matches
- Tech fingerprinting shows a Node.js/Express backend, or any framework known to use a
  deep-merge utility (Lodash, jQuery `$.extend(true, ...)`, custom JSON-merge config loaders)
- The operator is deciding whether to run PortSwigger's server-side PP detection technique
  (reflected-property / async-property scan) against a JSON-accepting endpoint

## Parameter keys that match

`__proto__, constructor, prototype`

All three are DELIBERATELY NOVEL — none collide with any other bucket's key set (verified
against the full `_BUCKETS` table), so this bucket cannot recluster a single existing row.
Note these are unusually rare as *organically observed* parameter names — a captured request
that already contains one is high-precision signal (either a legitimate deep-object client
feature, or someone/something already probing).

## Path patterns that match

None — this bucket is keyed entirely off parameter names. Prototype pollution is a body-shape
issue with no distinctive path, mirroring `ssti`/`cors`/`sqli`.

## Weight and priority interpretation

- Baseline priority score: 35 (tied with `idor`/`nosqli`/`sso`/`oauth-oidc` — real severity,
  but keyed on rare literal names rather than a proven interpreter sink)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/config` with body `{"__proto__": {"isAdmin": true}}` — classic
  gadget
- `https://target.example/api/users` with body `{"constructor": {"prototype": {"role": "admin"}}}`
  — compound bracket-notation form
- `https://target.example/settings/merge` with body containing a `prototype` key inside a
  nested options object passed to a config-merge helper

## What it does NOT classify

- Client-side (DOM) prototype pollution — the same canonical class (`prototype-pollution`)
  covers both, but this bucket only sees server-received request parameters, not client-side
  JS sinks; those are found via `browser-semantic-analysis` / source review, not this classifier
- A `constructor`/`prototype` string appearing as a **value** rather than a **key** — this
  bucket keys off parameter names via `collect_keys`, not parameter values

## Sources

- [PortSwigger Research — Server-side prototype pollution: Black-box detection without the DoS](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger — Server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side)
- [OWASP WSTG — Testing for Prototype Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_Prototype_Pollution)

## Related

- `agent/skills/prototype-pollution/SKILL.md` — the follow-up test skill (already existed
  before this bucket; `vuln_class: prototype-pollution`)
- `agent/references/gf-patterns/nosqli.md` — adjacent bucket; both rely on
  `expand_compound_key`'s `[`/`]` bracket-splitting to surface the operator/gadget token
