---
name: gf-patterns:deserialization
description: Unsafe deserialization path and parameter patterns (Java serial, ASP.NET ViewState, Siteforce loader-state)
origin: local overlay (no upstream gf equivalent)
bucket: deserialization
weight: 40
---

# gf: deserialization

## What this bucket classifies

Endpoints and parameters that accept or process serialized object graphs where an attacker can
supply a malicious payload for gadget-chain remote code execution. Includes Java deserialization
endpoints, ASP.NET ViewState, Python pickle, and Salesforce/Siteforce Aura loader-state paths.

## Load this reference when

- The corpus contains `/deserialize`, `/pickle`, `/java-serial` paths or explicit
  `__viewstate`/`viewstate` POST parameters
- The corpus has Salesforce/Siteforce `/sfsites/l/{...}/` paths (see Siteforce note below)
- Operator is assessing Java-heavy or ASP.NET applications where deserialization gadget chains
  are a plausible RCE pathway

## Parameter keys that match

`data, payload, blob, object, serialized, viewstate, __viewstate`

`viewstate` and `__viewstate` are the highest-signal deserialization parameters: they identify
ASP.NET ViewState or Java object graphs that the server deserializes without a verified MAC.
`data`, `payload`, `blob`, and `object` are broader but necessary to catch frameworks that
use opaque names for their serialized request bodies.

## Path patterns that match

Explicit deserialization routes:
`/deserialize`, `/marshal`, `/unmarshal`, `/pickle`, `/java-serial`

Siteforce/Salesforce loader-state prefix:
`/sfsites/`

The `/sfsites/` fragment captures Salesforce Aura/Siteforce community pages whose URLs embed
a JSON-encoded loader-state segment: e.g.
`/sfsites/l/%7B%22mode%22%3A%22PROD%22%2C%22app%22%3A%22siteforce%3AcommunityApp%22%2C...%7D/bootstrap.js`.
These URLs look like static asset deliveries (they end in `.js`, `.css`, or `/app.js`) but the
path embeds serialized Aura framework state (`mode`, `app`, `fwuid`, `loaded`,
`serializationVersion`, `siteforce:communityApp`) that the server deserializes on the way to
serving the resource. The `/sfsites/` FRAGMENT fires even when the URL ends `.js`, so Aura
loader-state URLs are not silently classified as inert static assets.

## Weight and priority interpretation

- Baseline priority score: 40
- Deserialization RCE is a direct code-execution pathway — weight matches `ssrf`, `sqli`,
  `lfi`, and `auth` at 40, below only `rce` (50) and `graphql` (45)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Explicit route matches:

- `https://target.example/api/deserialize?data=rO0ABXNy...` — Java serialized object
- `https://target.example/marshal/load?payload=b64-data` — marshal endpoint
- `https://target.example/api/pickle?blob=gASV...` — Python pickle load

ViewState matches (param-key):

- `https://target.example/checkout` (POST with `__VIEWSTATE=AAAA...`) — ASP.NET ViewState

Siteforce loader-state (path-fragment):

- `https://target.example/sfsites/l/%7B%22mode%22%3A%22PROD%22%7D/bootstrap.js` — Siteforce
  community bootstrap (path contains `/sfsites/`)
- `https://target.example/sfsites/l/.../app.js` — Aura app loader

## What it does NOT classify

- `/sfsites/c/` paths to named Aura components that only serve component metadata — the
  fragment still fires, but the specialist should evaluate whether the loader-state is present
- Encrypted/MAC-verified ViewState where the serialized payload cannot be tampered — rule fires
  on the path/param, not the integrity check; specialist confirms exploitability
- Generic `data=` parameters on REST endpoints — `data` is in the key set, but a REST
  endpoint with `data=` will typically also match a higher-specificity bucket; check the
  full `priority_reason` chain

## Attack classes

- **Java deserialization RCE via gadget chain:** attacker supplies a crafted ysoserial payload;
  server calls `ObjectInputStream.readObject()` against attacker-controlled bytes
- **ASP.NET ViewState tampering:** unprotected or MAC-bypassed ViewState allows arbitrary
  object-graph injection leading to RCE via TypeConfuseDelegate or similar gadgets
- **Python pickle RCE:** `pickle.loads()` on attacker-controlled bytes executes arbitrary code
- **Siteforce state injection:** decoded Aura loader-state keys (`app`, `mode`, `fwuid`) may
  be modifiable to alter the Aura bootstrap path or trigger deserialization of a forged state

## Corpus grounding

6 actionable `deserialization` templates (12 rows) in the first cms-gov deep sweep.
Second deep sweep (xhigh-corrected): 56 actionable templates (112 rows) — majority were
static-looking Salesforce/Siteforce `/sfsites/l/{json}/...` loader-state URLs upgraded from
`static-low` to `deserialization` by GPT-5.5 xhigh review. Third targeted sweep: 199 actionable
templates (199 rows), same Aura pattern. The `/sfsites/` path fragment was added specifically to
capture this Siteforce pattern. See `docs/research/classify-surface-2026-06/README.md` §4b
(deserialization cross-corpus validation) and the per-sweep tables in that README.

## Sources

- [ysoserial — Java deserialization gadget chains](https://github.com/frohoff/ysoserial)
- [PayloadsAllTheThings — Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [OWASP A08:2021 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [Salesforce Aura Framework Security](https://developer.salesforce.com/docs/atlas.en-us.lightning.meta/lightning/security_csp.htm)

## Related

- `agent/references/gf-patterns/rce.md` — direct RCE surface (deserialization is an indirect RCE pathway via gadget chains)
- `agent/references/gf-patterns/upload_fields.md` — file uploads that trigger server-side deserialization
