---
name: info-disclosure-testing
description: Information disclosure detection — error messages, files, headers, debug endpoints
origin: Vigil
vuln_class: info-disclosure, debug-exposure
---

# Information Disclosure Testing

Severity rides on what is disclosed: `/actuator/heapdump` with cleartext secrets is a finding in
five minutes; thirty minutes documenting `Server: nginx/1.24.0` is wasted. Hunt the high-value
tier first; disclosures feed every other test class.

## When to Activate

- Early in any engagement; verbose errors seen during other testing; Java/Spring apps (actuator is
  common and high-value); anywhere `.git/` or `.env` might be exposed; stacks with known debug
  endpoints.

`--technique INFO-DISCLOSURE`; endpoint probes via `vigil assess kali exec … --probe-kind
fingerprint --phase consume-test --timeout <N> -- curl …`, sweeps via `vigil assess kali ffuf`.
Standard paths (framework debug endpoints, `/.env` and config files, actuator, VCS, backups):
`agent/references/payloads/info-disclosure-probes.md`.

## Value tiers

1. **Credentials in responses** (test, extract, validate each): `.env`; `/actuator/env` and
   `/actuator/heapdump`; Apache `/server-status`/`/server-info`; `phpinfo`; connection strings in
   DB errors; API responses returning more fields than the UI shows (passwords, tokens); debug
   endpoints dumping other users' request context incl. `Authorization`. Cloud metadata through a
   proxy or SSRF belongs to `agent/skills/ssrf-testing/SKILL.md`.
2. **Internals that enable a chain:** internal IPs/hostnames in headers and errors, proxy/LB
   identity, `/actuator/mappings`/`configprops`, GraphQL introspection, Swagger/OpenAPI, WSDL,
   routing/feature-flag debug output. These are intel and chain seeds; on their own they are
   informational under `agent/references/finding-fp-and-severity-gate.md`.
3. **Fingerprints** (version banners, stack frames, cookie names): useful only for a CVE match;
   record them with `vigil assess intel record note`, not as findings.

Error triggering (malformed/absent Content-Type, special characters, type confusion, an
oversized header or a request with thousands of parameters forcing a 500) is standard technique;
single requests like these are not availability tests. Large-volume or body-flood probes (a
100 MB upload, request floods) degrade the service, so run them only where the ROE allows
availability testing (`agent/shared-constraints.md` §1).

## Spring Boot actuator

| Endpoint | Why it matters |
|---|---|
| `heapdump` | every live object: secrets, sessions, DB credentials (`strings … \| grep -iE 'password\|secret\|token\|jdbc\|AKIA'`; Eclipse MAT OQL for structure) |
| `env` | all properties; `******` values can sometimes be unmasked on Boot 1.x by POSTing an override and reading it back |
| `trace` / `httptrace` / `httpexchanges` | recent requests with other users' headers, cookies, API keys |
| `jolokia` | JMX access, an RCE path via MBeans |
| `mappings`, `configprops` | full route map (admin/internal routes brute force misses) and config tree |
| `beans`, `loggers` | security filters and providers; POST a logger to DEBUG, then trigger operations to leak data into logs |

Also try alternate bases (`/manage`, `/management`, `/admin`, `/internal`, `/monitoring`) and
management ports (8081, 8443, 9090, 9443).

## Exposed `.git`

`/.git/HEAD` returning `ref: refs/heads/…` while `/.git/` is 403 still means objects are
fetchable. Reconstruct the repository from inside the runtime (fetch the objects through
`vigil assess kali exec`, never from the host), then scan the copy and its history:
`trufflehog filesystem --directory <copy>`, `git log --all --full-history -p` filtered for
secrets and config files. Secrets "removed" in a later commit are still there.

Validate a recovered credential with one login or who-am-I request (the operator's Credential
Auto-Use step), then show what it grants with one minimal sample, never a bulk pull
(`agent/rules/hunting.md` §2, §10). Source maps, inline JS secrets and HTML comments:
`agent/skills/source-analysis/SKILL.md` §2, §3 and §6 "Source Map Analysis"; classifying what a
recovered corpus contains: `agent/skills/sensitive-data-detection/SKILL.md`. Exposed buckets: `agent/skills/cloud-exposure/SKILL.md`.
Vendor installer defaults in CSP/CORS: `agent/references/payloads/csp-default-grep.md`.

## Kill and escalate

- Only fingerprint-tier disclosures with no CVE match → intel, move on. Actuator/debug paths all
  404 → move on.
- A credential or exposed `.git` → validate (Credential Auto-Use), record, then keep checking sibling hosts
  and endpoints, which often share the misconfiguration (`agent/rules/hunting.md` §6).
- A 401/403 on `/actuator`, `/debug`, `/console`, `/swagger`, `/.git/HEAD`, `/.env` means the path
  exists: enumerate children, since parent ACLs often miss them.
- A stack trace leaking framework, driver, absolute path, internal host, queue, account ID or
  commit hash: each is a pivot seed (targeted CVEs, traversal payloads, source retrieval).
- Backup/IDE artefacts (`.bak`, `.old`, `~`, `.swp`, `.DS_Store`, `.idea/`, `.vscode/`) on one
  path → sweep every discovered directory.
- Headers naming pods, internal services (`Via`, `X-Served-By`, `Server-Timing`) or cloud IDs →
  map the internal architecture.
- A managed platform (Confluence, Jira, GitLab, Jenkins, Sitecore, Citrix, Fortinet) or a
  vulnerable version → validate the highest-impact CVE for that exact version.

## What to Record

What was disclosed, where, and the attacker outcome it enables, with one minimal sample. Format:
`agent/references/runtime-guides/web-finding-recording.md`.
