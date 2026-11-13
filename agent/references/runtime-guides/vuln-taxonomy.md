---
description: Canonical vuln_class vocabulary shared by every track, and the class token `record-probe --attack-family` takes. Lists the 66 canonical classes in their families, with the surface_type, gf-bucket, technique and skill mappings onto them. agent/scripts/assess/lib/vuln_taxonomy.py is authoritative; this is its readable mirror.
last_reviewed: 2026-09-17
origin: Vigil
---

# Canonical Vuln-Class Taxonomy

`vuln_class` is the one class vocabulary the web, code and blue tracks share. gf-buckets, skill
`vuln_class:` frontmatter, `surface_type` and the code track's family lists all map onto it.
`agent/scripts/assess/lib/vuln_taxonomy.py` is authoritative; the drift tests fail when a skill,
gf-bucket, surface_type, technique or code family names a non-canonical class. Code-track classes
(`buffer-overflow`, `web-app-auth`, …) sit inside code-oriented families instead of forming a
parallel vocabulary, and are marked _(code track)_ below.

`vigil assess record-probe --attack-family <value>` takes a **class** token from the list below
(`idor`, `sqli`, `ssrf`), not the family heading (`access-control`, `injection`), despite the flag's
name. An unlisted value warns and is stored verbatim.

## Families

The depth gate reasons at **family** granularity; a class belongs to exactly one
family.

### access-control — Authorization defects: object/function/tenant access not enforced.
- `idor` — Insecure direct object reference (object-level authz).
- `bola` — Broken object-level authorization (API).
- `bfla` — Broken function-level authorization.
- `path-authz` — Path/route-level authorization gaps.

### auth — Authentication & session: bypass, token, federation, session, enumeration.
- `auth-bypass` — Authentication bypass.
- `jwt` — JWT/token forgery, confusion, weak verification.
- `oauth` — OAuth/OIDC flow and grant abuse.
- `saml` — SAML assertion/signature abuse.
- `session` — Session fixation/management defects.
- `user-enumeration` — Account/user enumeration.
- `web-app-auth` — Web-app authentication weakness _(code track)_.

### injection — Untrusted input reaches an interpreter/parser/sink.
- `sqli` — SQL injection.
- `nosqli` — NoSQL injection.
- `cmdi` — OS command / code execution injection.
- `ssti` — Server-side template injection.
- `xxe` — XML external entity / XML injection.
- `ssi-injection` — Server-Side Includes (SSI) directive injection.
- `ldap-injection` — LDAP injection.
- `xpath-injection` — XPath injection.
- `graphql-injection` — GraphQL query/mutation abuse & injection.
- `elasticsearch-injection` — Elasticsearch/search-DSL injection.
- `mass-assignment` — Mass assignment / over-posting.
- `crlf` — CRLF / header injection.
- `deserialization` — Unsafe deserialization _(code track)_.
- `csv-injection` — CSV/spreadsheet formula (DDE) injection via exported data.
- `injection` — Generic injection (code-track coarse family) _(code track)_.
- `web-app-injection` — Web-app injection _(code track)_.

### ssrf — Server-side request forgery and forced redirects/fetches.
- `ssrf` — Server-side request forgery.
- `open-redirect` — Open redirect / forced navigation.

### file — File handling: upload, inclusion, traversal.
- `file-upload` — Unrestricted/abusable file upload.
- `lfi` — Local file inclusion.
- `rfi` — Remote file inclusion.
- `path-traversal` — Path/directory traversal.
- `img-traversal` — Image/asset path traversal variant.

### disclosure — Information / secret / source / debug exposure.
- `info-disclosure` — Sensitive information disclosure.
- `secrets-exposure` — Exposed secrets/keys/credentials.
- `debug-exposure` — Debug/admin/internal endpoint exposure.
- `source-disclosure` — Source/sourcemap/backup exposure.
- `web-app-data-exposure` — Web-app data over-exposure _(code track)_.

### business-logic — Workflow, state, race, and rate-limit abuse.
- `business-logic` — Business-logic / workflow abuse.
- `race-condition` — Race condition / TOCTOU.
- `rate-limit` — Missing/weak rate limiting.
- `algorithmic-dos` — Algorithmic complexity DoS _(code track)_.

### client-side — Browser-trust defects: XSS, CSRF, CORS, pollution.
- `xss` — Cross-site scripting.
- `csrf` — Cross-site request forgery.
- `cors` — CORS misconfiguration.
- `prototype-pollution` — Prototype pollution.
- `clickjacking` — Clickjacking / UI redress via frame embedding.

### protocol — HTTP/transport-layer defects: smuggling, headers, cache, ws.
- `request-smuggling` — HTTP request smuggling/desync.
- `host-header-injection` — Host-header injection.
- `cache-poisoning` — Web cache poisoning/deception.
- `websocket` — WebSocket security defects.

### crypto — Cryptographic misuse.
- `crypto-misuse` — Cryptographic misuse _(code track)_.

### memory-safety — Native memory-safety (code track): overflow, UAF, type confusion.
- `buffer-overflow` — Stack/heap buffer overflow _(code track)_.
- `integer-overflow` — Integer overflow/underflow _(code track)_.
- `format-string` — Format-string vulnerability _(code track)_.
- `null-dereference` — Null-pointer dereference _(code track)_.
- `use-after-free` — Use-after-free _(code track)_.
- `uninitialized-memory` — Uninitialized memory use _(code track)_.
- `type-confusion` — Type confusion _(code track)_.

### error-handling — Robustness / fault handling (code track).
- `error-handling` — Error/exception handling defects _(code track)_.

### ai-ml — AI/ML-specific security (prompt injection, model abuse).
- `ai-ml-security` — AI/ML security (model/data/inference abuse) _(code track)_.
- `prompt-injection` — LLM prompt injection.

### infrastructure — Build, container and deployment posture: runtime privilege, exposed services, build supply chain.
- `privilege-escalation` — Container/host privilege escalation: root runtime, over-permissive modes, build-time sudo _(code track)_.
- `network-exposure` — Service/port exposed beyond its intended network boundary _(code track)_.
- `supply-chain` — Build/deploy supply chain: remote or unpinned code and assets executed as trusted _(code track)_.

`treesitter_index.py`'s Dockerfile, shell, HTML and CSS extractors emit these three. Keep them in
this family. They have no untrusted input reaching an interpreter (`injection`), no request-time
inclusion (`rfi`), no principal or routed function (`access-control`) and no HTTP endpoint
(`disclosure`), so filing them under any of those misroutes the depth gate.

## surface_type → expected classes

A `surface_type` (`assess.lib.surfaces.VALID_SURFACE_TYPES`) implies the class
campaigns worth running on that surface (depth-gate translation). The two
catch-alls (`misconfiguration` / `informational`) map to disclosure-only.

| surface_type | expected classes |
|---|---|
| `auth_entry` | `auth-bypass`, `jwt`, `oauth`, `saml`, `session` |
| `account_recovery` | `auth-bypass`, `user-enumeration`, `session` |
| `object_reference` | `idor`, `bola`, `bfla` |
| `privileged_write` | `bfla`, `path-authz`, `mass-assignment` |
| `file_handling` | `file-upload`, `lfi`, `path-traversal` |
| `dynamic_render` | `xss`, `ssti`, `ssi-injection` |
| `api_documentation` | `bola`, `bfla`, `mass-assignment`, `graphql-injection` |
| `workflow_token` | `business-logic`, `race-condition` |
| `misconfiguration` | `info-disclosure`, `debug-exposure` |
| `informational` | `info-disclosure` |

## gf-bucket → class

The 41 gf-buckets (`assess.lib.classify_buckets._BUCKETS`) are the web-recon
signal, listed here in declaration order (which is also weight-descending and
governs tie-break precedence when multiple buckets match the same row). A
bucket with no single class is a **generic family-level hint** the
recommender treats as low-confidence.

| gf-bucket | weight | class |
|---|---|---|
| `rce` | 50 | `cmdi` |
| `graphql` | 45 | `graphql-injection` |
| `secret_vault` | 45 | `secrets-exposure` |
| `ssrf` | 40 | `ssrf` |
| `cloud_metadata` | 40 | `ssrf` |
| `sqli` | 40 | `sqli` |
| `lfi` | 40 | `lfi` |
| `auth` | 40 | `auth-bypass` |
| `deserialization` | 40 | `deserialization` |
| `dotnet_handler` | 40 | `deserialization` |
| `xxe` | 40 | `xxe` |
| `llm_api` | 40 | `prompt-injection` |
| `img_traversal` | 35 | `img-traversal` |
| `oauth-oidc` | 35 | `oauth` |
| `sso` | 35 | `saml` |
| `trust_surface` | 35 | _(generic — family-level hint)_ |
| `idor` | 35 | `idor` |
| `idp_admin` | 35 | `auth-bypass` |
| `wordpress` | 35 | `user-enumeration` |
| `cms_db_admin` | 35 | `auth-bypass` |
| `nosqli` | 35 | `nosqli` |
| `prototype-pollution` | 35 | `prototype-pollution` |
| `upload_fields` | 30 | `file-upload` |
| `debug_logic` | 30 | `debug-exposure` |
| `websocket` | 30 | `websocket` |
| `webhook` | 30 | `ssrf` |
| `jwt` | 30 | `jwt` |
| `servicenow` | 30 | `idor` |
| `privileged_action` | 30 | `bfla` |
| `mass-assignment` | 30 | `mass-assignment` |
| `devops_console` | 30 | `debug-exposure` |
| `ssi` | 30 | `ssi-injection` |
| `redirect` | 25 | `open-redirect` |
| `ssti` | 25 | `ssti` |
| `cors` | 25 | `cors` |
| `api-versioning` | 25 | _(generic — family-level hint)_ |
| `object-storage` | 25 | `info-disclosure` |
| `api` | 20 | _(generic — family-level hint)_ |
| `xss` | 20 | `xss` |
| `interestingparams` | 15 | _(generic — family-level hint)_ |
| `interestingext` | 10 | `secrets-exposure` |

`classify_buckets.BUCKET_SKILLS` is **derived** from this table + the skill
`vuln_class:` frontmatter (`vuln_taxonomy.derive_bucket_skills()`) — there is no
hand-maintained bucket→skill dict anymore.

## technique → class

`vuln_taxonomy.TECHNIQUE_TO_CLASS` maps each `--technique` value (`vigil assess kali exec --help`
lists the enum) to the lowercase class of the same name (`SQLI` → `sqli`, `PATH-TRAVERSAL` →
`path-traversal`). Four exceptions: `RCE` → `cmdi`, `AUTH` → `auth-bypass`, `HOST-HEADER` →
`host-header-injection` and `GRAPHQL` → `graphql-injection`. The operational tags `RECON`,
`DISCOVERY`, `PARAM-DISCOVERY`, `FUZZ`, `OSINT`, `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `META`,
`HEALTH`, `LOG-READ` and `OTHER` map to no class.

## class → skills

`vigil assess list-skills --json` gives each offensive skill's `vuln_class` (derived by
`vuln_taxonomy.build_class_to_skills()`). Supporting, recon, fuzzing, triage, reporting,
dispatching and blue skills have no `vuln_class`. These classes have no dedicated skill, so use the
family's nearest skill and your own method: `path-authz`, `ssi-injection`, `ldap-injection`,
`xpath-injection`, `csv-injection`, `clickjacking`, `privilege-escalation`, `network-exposure`,
`supply-chain`.
