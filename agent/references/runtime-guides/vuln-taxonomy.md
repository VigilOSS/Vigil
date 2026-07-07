---
description: Canonical cross-track vuln-class taxonomy — the single vocabulary the web, code, and blue tracks share. Lists the 63 canonical classes grouped into families, and which surface_types / gf-buckets / techniques / skills map to which class. Source of truth is assess.lib.vuln_taxonomy; this doc is the human-readable view.
last_reviewed: 2026-07-07
origin: Vigil
---

# Canonical Vuln-Class Taxonomy

> **Source of truth:** `agent/scripts/assess/lib/vuln_taxonomy.py`. This doc is the
> human-readable mirror — the module is authoritative and the drift tests in
> `orchestrator/backend/tests/test_vuln_taxonomy.py` fail CI if the two disagree
> (a skill, gf-bucket, surface_type, technique, or code family that references a
> non-canonical class breaks the build).
>
> **Review cadence:** re-confirm against OWASP WSTG / OWASP ASVS / OWASP API
> Security Top 10 (2023) / NIST SP 800-115 and the live skill roster each
> engagement-program review (≈quarterly), and whenever a new offensive skill or
> framework is added. The taxonomy is **data, not control flow** — adding a class
> or framework is a one-line edit to `VULN_CLASSES` plus (for skills) a
> `vuln_class:` frontmatter line. `last_reviewed:` above tracks the last audit.

`vuln_class` is the **one canonical cross-track term** (master plan R-M5). It
replaces four taxonomies that drifted independently — gf-buckets, the
hand-maintained `BUCKET_SKILLS` dict, `surface_type`, and the code track's
family lists. The canonical set is the **union** of the web attack classes and
the code families, so the code track **aligns by inclusion**: every string the
code track validates against (`buffer-overflow`, `web-app-auth`, …) is a
canonical class here, **namespaced** into a code-oriented family
(`memory-safety`, `crypto`, `error-handling`, `ai-ml`) rather than forked into a
parallel term. Code-specific classes are marked _(code track)_ below.

## Attack-surface-enumeration anchors

The class list is kept exhaustive against these external references (cited for
completeness of attack-surface enumeration, not as a compliance checklist):
**OWASP WSTG** (Web Security Testing Guide), **OWASP ASVS** (Application Security
Verification Standard), **OWASP API Security Top 10 (2023)**, and **NIST SP
800-115** (Technical Guide to Information Security Testing and Assessment). When a
new framework / API style / auth method appears (e.g. passkeys/WebAuthn, gRPC-web,
tRPC), check these anchors and add the missing class here.

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

The 40 gf-buckets (`assess.lib.classify_buckets._BUCKETS`) are the web-recon
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

Each `--technique` audit-enum value (`assess.lib.audit_enums.TECHNIQUE_ENUM`)
maps to a canonical class (operational tags map to nothing).

| technique | class |
|---|---|
| `SSRF` | `ssrf` |
| `XSS` | `xss` |
| `XXE` | `xxe` |
| `SQLI` | `sqli` |
| `NOSQLI` | `nosqli` |
| `SSTI` | `ssti` |
| `RCE` | `cmdi` |
| `CMDI` | `cmdi` |
| `LFI` | `lfi` |
| `RFI` | `rfi` |
| `PATH-TRAVERSAL` | `path-traversal` |
| `CRLF` | `crlf` |
| `DESERIALIZATION` | `deserialization` |
| `PROTOTYPE-POLLUTION` | `prototype-pollution` |
| `MASS-ASSIGNMENT` | `mass-assignment` |
| `IDOR` | `idor` |
| `BOLA` | `bola` |
| `BFLA` | `bfla` |
| `AUTH` | `auth-bypass` |
| `JWT` | `jwt` |
| `OAUTH` | `oauth` |
| `SAML` | `saml` |
| `SESSION` | `session` |
| `USER-ENUMERATION` | `user-enumeration` |
| `OPEN-REDIRECT` | `open-redirect` |
| `CSRF` | `csrf` |
| `CORS` | `cors` |
| `REQUEST-SMUGGLING` | `request-smuggling` |
| `HOST-HEADER` | `host-header-injection` |
| `CACHE-POISONING` | `cache-poisoning` |
| `WEBSOCKET` | `websocket` |
| `GRAPHQL` | `graphql-injection` |
| `FILE-UPLOAD` | `file-upload` |
| `BUSINESS-LOGIC` | `business-logic` |
| `RACE-CONDITION` | `race-condition` |
| `RATE-LIMIT` | `rate-limit` |
| `INFO-DISCLOSURE` | `info-disclosure` |

Operational / non-vuln technique tags (no class): `RECON`, `DISCOVERY`, `FUZZ`,
`OSINT`, `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `META`, `HEALTH`, `LOG-READ`, `OTHER`.

## class → skills

Which `agent/skills/<name>/SKILL.md` declares each class in its `vuln_class:`
frontmatter (derived live by `vuln_taxonomy.build_class_to_skills()`). The 11
web-exclusive classes (`idor`, `sqli`, `ssrf`, `xss`, `ssti`, `lfi`,
`img-traversal`, `cmdi`, `open-redirect`, `cors`, `file-upload`) are reserved to
their web skills and never declared by a code skill. Two classes
(`ldap-injection`, `path-authz`) intentionally have no dedicated skill yet — they
are tracked in the test's `KNOWN_SKILLLESS_CLASSES` allowlist so the
completeness drift test stays honest.

| class | skills |
|---|---|
| `idor` | `idor-testing`, `split-brain-idor` |
| `bola` | `bff-parameter-override`, `graphql-testing` |
| `bfla` | `auth-bypass` |
| `path-authz` | _(no dedicated skill — allowlisted)_ |
| `auth-bypass` | `auth-bypass` |
| `jwt` | `jwt-testing` |
| `oauth` | `oauth-oidc-testing` |
| `saml` | `saml-sso-testing` |
| `session` | `auth-bypass` |
| `user-enumeration` | `user-enumeration` |
| `web-app-auth` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `sqli` | `sqli-testing` |
| `nosqli` | `nosql-injection` |
| `cmdi` | `command-injection` |
| `ssti` | `ssti-testing` |
| `xxe` | `xxe-testing` |
| `ssi-injection` | _(no dedicated skill — allowlisted)_ |
| `ldap-injection` | _(no dedicated skill — allowlisted)_ |
| `xpath-injection` | _(no dedicated skill — allowlisted)_ |
| `graphql-injection` | `graphql-testing` |
| `elasticsearch-injection` | `elasticsearch-injection` |
| `mass-assignment` | `bff-parameter-override`, `mass-assignment` |
| `crlf` | `crlf-injection` |
| `deserialization` | `code-variant-analysis`, `code-vulnerability-analysis`, `deserialization-testing` |
| `csv-injection` | _(no dedicated skill — allowlisted)_ |
| `injection` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `web-app-injection` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `ssrf` | `ssrf-testing` |
| `open-redirect` | `open-redirect-testing` |
| `file-upload` | `file-upload-testing` |
| `lfi` | `file-inclusion` |
| `rfi` | `file-inclusion` |
| `path-traversal` | `file-inclusion` |
| `img-traversal` | `file-inclusion` |
| `info-disclosure` | `info-disclosure-testing` |
| `secrets-exposure` | `sensitive-data-detection`, `source-analysis` |
| `debug-exposure` | `info-disclosure-testing` |
| `source-disclosure` | `sensitive-data-detection`, `source-analysis` |
| `web-app-data-exposure` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `business-logic` | `business-logic-testing` |
| `race-condition` | `race-condition-testing` |
| `rate-limit` | `rate-limit-bypass` |
| `algorithmic-dos` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis` |
| `xss` | `xss-testing` |
| `csrf` | `csrf-testing` |
| `cors` | `cors-testing` |
| `prototype-pollution` | `prototype-pollution` |
| `clickjacking` | _(no dedicated skill — allowlisted)_ |
| `request-smuggling` | `request-smuggling` |
| `host-header-injection` | `host-header-injection` |
| `cache-poisoning` | `cache-poisoning` |
| `websocket` | `websocket-testing` |
| `crypto-misuse` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `buffer-overflow` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis`, `heap-rce-evidence-ladder` |
| `integer-overflow` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis` |
| `format-string` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis` |
| `null-dereference` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis` |
| `use-after-free` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis`, `heap-rce-evidence-ladder` |
| `uninitialized-memory` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis` |
| `type-confusion` | `code-fuzz-campaign`, `code-variant-analysis`, `code-vulnerability-analysis`, `heap-rce-evidence-ladder` |
| `error-handling` | `code-variant-analysis`, `code-vulnerability-analysis` |
| `ai-ml-security` | `ai-ml-on-device-security` |
| `prompt-injection` | `ai-ml-on-device-security` |

> The `class → skills` table is a snapshot of derived state; the live answer is
> `vigil assess list-skills --json` (each offensive skill carries its
> `vuln_class`) and `vuln_taxonomy.build_class_to_skills()`. Supporting / recon /
> fuzzing / triage / reporting / dispatching / blue-team skills intentionally
> omit `vuln_class:`.
