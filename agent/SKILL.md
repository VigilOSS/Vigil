# AI Threat Hunting Skill Index

Use this file when you need to decide which skill to load before starting specialist work.
Read `agent/shared-constraints.md` first, then select from this index.

## Selection Rule

1. Load `agent/shared-constraints.md` first (subagents) or confirm constraints are active (operator).
2. Find the best-fit skill below using the "Use when:" line.
3. Load that skill file in full before running target work.
4. When the skill's "Extended Resources" lists reference files, read those too — they contain the payloads and checklists for that test class.
5. Check `agent/references/INDEX.md` for additional depth only after the skill is loaded.

---

## Core Workflow Skills

- `agent/skills/web-recon/SKILL.md`
  **Use when:** Starting Phase 1; fingerprinting hosts, ports, tech stacks, headers, web services.
  **Paired references:** `references/tools/recon/nmap.md`, `references/tools/recon/whatweb.md`, `references/tools/recon/httpx.md`, `references/tools/recon/wafw00f.md`

- `agent/skills/source-analysis/SKILL.md`
  **Use when:** Analyzing HTML/JS/CSS for routes, secrets, API bases, SPA bundles, source maps.
  **Paired references:** `references/payloads/info-disclosure-probes.md`, `references/tools/exploitation/dalfox.md` _(for JS-discovered parameterized URLs)_

- `agent/skills/case-dispatching/SKILL.md`
  **Use when:** Operator needs to coordinate the Phase 2/3 work-buffer loop (reset-stale → stats → fetch → dispatch → done → requeue).
  **Paired references:** _(none — coordination logic only)_

- `agent/skills/report-generation/SKILL.md`
  **Use when:** Writing the final or interim engagement report in Phase 5.
  **Paired references:** _(uses durable finding state and synchronized artifacts)_

- `agent/skills/osint-recon/SKILL.md`
  **Use when:** Gathering CVEs, public disclosures, DNS exposure, org intel, or historical breach data.
  **Paired references:** _(web-sourced; no local payload files)_

- `agent/skills/athena-log-investigation/SKILL.md`
  **Use when:** Logs are available after exploit work and you need to check for prior exploitation evidence.
  **Paired references:** _(environment-specific; consult operator for log source)_

---

## Targeted Testing Skills

Load the relevant skill before starting validation or exploitation of a candidate surface.

- `agent/skills/auth-bypass/SKILL.md`
  **Use when:** Testing login bypass, session fixation, MFA bypass, token manipulation, or credential-based auth logic.
  **Paired references:** `references/payloads/jwt-payloads.md`, `references/vuln-checklists/A07-authentication-failures.md`

- `agent/skills/business-logic-testing/SKILL.md`
  **Use when:** Testing price manipulation, quantity abuse, workflow skipping, coupon/promo abuse, or payment bypass.
  **Paired references:** `references/payloads/business-logic-payloads.md`, `references/vuln-checklists/A06-insecure-design.md`

- `agent/skills/command-injection/SKILL.md`
  **Use when:** Input lands in OS commands, shell eval, or system calls (ping, DNS lookup, file conversion, etc.).
  **Paired references:** `references/payloads/command-injection-payloads.md`, `references/vuln-checklists/A05-injection.md`

- `agent/skills/cors-testing/SKILL.md`
  **Use when:** Testing cross-origin access, `Access-Control-Allow-Origin` policy, or credentialed cross-site requests.
  **Paired references:** `references/payloads/cors-payloads.md`, `references/vuln-checklists/A01-broken-access-control.md`

- `agent/skills/csrf-testing/SKILL.md`
  **Use when:** Testing state-changing requests without proper origin or token validation.
  **Paired references:** `references/payloads/csrf-payloads.md`, `references/vuln-checklists/A01-broken-access-control.md`

- `agent/skills/deserialization-testing/SKILL.md`
  **Use when:** Application deserializes user-controlled data (Java, PHP, Python pickle, Node.js, .NET).
  **Paired references:** `references/payloads/deserialization-payloads.md`, `references/vuln-checklists/A08-integrity-failures.md`

- `agent/skills/directory-fuzzing/SKILL.md`
  **Use when:** Discovering hidden paths, admin panels, backup files, or undocumented endpoints via wordlist fuzzing.
  **Paired references:** `references/tools/fuzzing/ffuf.md`, `references/tools/fuzzing/feroxbuster.md`

- `agent/skills/file-inclusion/SKILL.md`
  **Use when:** Testing LFI/RFI, path traversal, PHP wrapper abuse, or log poisoning via file-path parameters.
  **Paired references:** `references/payloads/file-inclusion-payloads.md`, `references/payloads/directory-traversal-payloads.md`

- `agent/skills/file-upload-testing/SKILL.md`
  **Use when:** Testing file upload endpoints for extension bypass, content-type bypass, SVG XSS, or zip slip.
  **Paired references:** `references/payloads/upload-payloads.md`, `references/vuln-checklists/A05-injection.md`

- `agent/skills/graphql-testing/SKILL.md`
  **Use when:** Target exposes a GraphQL API; testing introspection, batching abuse, injection in variables, or authorization on queries/mutations.
  **Paired references:** `references/payloads/graphql-payloads.md`, `references/api-security/API05-broken-function-authz.md`

- `agent/skills/idor-testing/SKILL.md`
  **Use when:** Testing object references in API parameters, IDs, GUIDs, or path segments for unauthorized access.
  **Paired references:** `references/vuln-checklists/A01-broken-access-control.md`, `references/api-security/API01-broken-object-level-authz.md`

- `agent/skills/info-disclosure-testing/SKILL.md`
  **Use when:** Probing for exposed debug endpoints, error responses, environment files, metadata endpoints, or stack traces.
  **Paired references:** `references/payloads/info-disclosure-probes.md`, `references/vuln-checklists/A02-security-misconfiguration.md`

- `agent/skills/jwt-testing/SKILL.md`
  **Use when:** Target uses JWT authentication; testing `alg:none`, key confusion, JWK/kid injection, or weak secret brute-force. Use in addition to auth-bypass when JWT is the mechanism.
  **Paired references:** `references/payloads/jwt-payloads.md`, `references/vuln-checklists/A07-authentication-failures.md`

- `agent/skills/open-redirect-testing/SKILL.md`
  **Use when:** Testing redirect parameters (`next`, `url`, `return_to`, etc.) for open redirect or OAuth token theft chains.
  **Paired references:** `references/payloads/open-redirect-payloads.md`, `references/vuln-checklists/A01-broken-access-control.md`

- `agent/skills/parameter-fuzzing/SKILL.md`
  **Use when:** Fuzzing hidden or undocumented query/body parameters, header variants, or content-type mutations.
  **Paired references:** `references/tools/fuzzing/ffuf.md`

- `agent/skills/port-scanning/SKILL.md`
  **Use when:** Discovering open ports, service banners, and non-web services on in-scope hosts.
  **Paired references:** `references/tools/recon/nmap.md`

- `agent/skills/race-condition-testing/SKILL.md`
  **Use when:** Testing time-of-check/time-of-use (TOCTOU) flaws, limit-overrun conditions, or concurrent state mutations.
  **Paired references:** `references/payloads/race-condition-payloads.md`, `references/vuln-checklists/A06-insecure-design.md`

- `agent/skills/request-smuggling/SKILL.md`
  **Use when:** Target sits behind a reverse proxy or load balancer; testing CL.TE, TE.CL, TE.TE, or HTTP/2 downgrade desync.
  **Paired references:** `references/payloads/request-smuggling-payloads.md`, `references/vuln-checklists/A05-injection.md`

- `agent/skills/sensitive-data-detection/SKILL.md`
  **Use when:** Scanning responses, JS bundles, or downloadable files for exposed secrets, PII, tokens, or internal data.
  **Paired references:** `references/payloads/info-disclosure-probes.md`, `references/vuln-checklists/A04-cryptographic-failures.md`

- `agent/skills/sqli-testing/SKILL.md`
  **Use when:** Input is reflected in SQL queries (search, login, filters, sort params, REST IDs, GraphQL variables).
  **Paired references:** `references/payloads/sqli-payloads.md`, `references/vuln-checklists/A05-injection.md`, `references/tools/exploitation/sqlmap.md`

- `agent/skills/ssrf-testing/SKILL.md`
  **Use when:** User-controlled URL or hostname parameter is fetched server-side (webhooks, imports, previews, image fetch, PDF render).
  **Paired references:** `references/payloads/ssrf-payloads.md`, `references/api-security/API07-ssrf.md`

- `agent/skills/ssti-testing/SKILL.md`
  **Use when:** Input is reflected inside a server-side template (Jinja2, Twig, Pug, Freemarker, ERB, Velocity, etc.).
  **Paired references:** `references/payloads/ssti-payloads.md`, `references/vuln-checklists/A05-injection.md`

- `agent/skills/nuclei-scanning/SKILL.md`
  **Use when:** Live targets identified and tech stacks known; running template-based vulnerability sweeps for CVEs, misconfigs, and exposures.
  **Paired references:** `references/tools/recon/nuclei.md`

- `agent/skills/subdomain-enumeration/SKILL.md`
  **Use when:** The `hosts` array in scope.json contains `*.domain` entries; enumerating subdomains for additional attack surface.
  **Paired references:** `references/tools/recon/httpx.md`, `references/tools/recon/puredns.md`, `references/tools/recon/dnsx.md`

- `agent/skills/user-enumeration/SKILL.md`
  **Use when:** Testing login, password reset, or registration flows for username/email oracle behavior.
  **Paired references:** `references/vuln-checklists/A07-authentication-failures.md`

- `agent/skills/websocket-testing/SKILL.md`
  **Use when:** Target uses WebSocket connections; testing message injection, auth drift, or cross-site WebSocket hijacking.
  **Paired references:** `references/vuln-checklists/A01-broken-access-control.md`

- `agent/skills/xss-testing/SKILL.md`
  **Use when:** User input is reflected in HTML/JS context (reflected, stored, or DOM-based XSS).
  **Paired references:** `references/payloads/xss-payloads.md`, `references/vuln-checklists/A05-injection.md`, `references/tools/exploitation/dalfox.md`

- `agent/skills/xxe-testing/SKILL.md`
  **Use when:** Application parses XML input (file upload, SOAP API, SVG, DOCX, RSS feed).
  **Paired references:** `references/payloads/xxe-payloads.md`, `references/vuln-checklists/A05-injection.md`

---

## Code Analysis Skills

Load these skills when performing white-box source code analysis (operator-core-code.md mode).

- `agent/skills/code-architecture-mapping/SKILL.md`
  **Use when:** Phase 1 — classifying a new repository's files, mapping modules, identifying trust boundaries, building the threat model.
  **Paired references:** _(works from project metadata, no vulnerability references needed)_

- `agent/skills/code-context-building/SKILL.md`
  **Use when:** Phase 2 — extracting function-level context slices with call graphs, data flow, and guard annotations for a module batch.
  **Paired references:** _(reads source files directly during execution)_

- `agent/skills/code-vulnerability-analysis/SKILL.md`
  **Use when:** Phase 3 — performing deep vulnerability analysis on context slices. Load the CWE-specific reference matching the context's slot types.
  **Paired references:** `references/code-vuln-patterns/buffer-overflow.md`, `references/code-vuln-patterns/integer-overflow.md`, `references/code-vuln-patterns/format-string.md`, `references/code-vuln-patterns/use-after-free.md`, `references/code-vuln-patterns/injection.md`, `references/code-vuln-patterns/race-condition.md`, `references/code-vuln-patterns/crypto-misuse.md`, `references/code-vuln-patterns/auth-bypass.md`, `references/code-vuln-patterns/uninitialized-memory.md`, `references/code-vuln-patterns/type-confusion.md`, `references/code-vuln-patterns/null-dereference.md`, `references/code-vuln-patterns/algorithmic-dos.md`, `references/code-vuln-patterns/error-handling.md`

- `agent/skills/code-variant-analysis/SKILL.md`
  **Use when:** Phase 4 — scanning the codebase for variant instances of a confirmed bug pattern.
  **Paired references:** _(uses original finding details as reference)_

- `agent/skills/code-finding-verification/SKILL.md`
  **Use when:** Phase 5 — eliminating false positives via full entry-to-sink traces and constrained attacker persona.
  **Paired references:** _(uses build system configuration and compile-time flags)_
