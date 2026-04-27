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

- `agent/skills/kali-exec/SKILL.md`
  **Use when:** Always — every target-facing call uses `aith assess kali ...`. Foundational, paired with `shared-constraints.md`.
  **Paired references:** `references/runtime-guides/kali-cli.md`, plus per-verb references listed inside the skill.

- `agent/skills/web-recon/SKILL.md`
  **Use when:** Starting Phase 1; fingerprinting hosts, ports, tech stacks, headers, web services.
  **Paired references:** `references/tools/recon/nmap.md`, `references/tools/recon/whatweb.md`, `references/tools/recon/httpx.md`, `references/tools/recon/wafw00f.md`, `references/tools/recon/nikto.md`, `references/tools/fuzzing/ffuf.md`

- `agent/skills/source-analysis/SKILL.md`
  **Use when:** Analyzing HTML/JS/CSS for routes, secrets, API bases, SPA bundles, source maps.
  **Paired references:** `references/payloads/info-disclosure-probes.md`, `references/tools/exploitation/dalfox.md` _(for JS-discovered parameterized URLs)_

- `agent/skills/surface-collection/SKILL.md`
  **Use when:** Phase 2 (Collect); running Katana + gau + historical URL enrichment, intelligent URL triage, and work-buffer population.
  **Paired references:** `references/tools/recon/gau.md`, `references/tools/recon/httpx.md`

- `agent/skills/gau-triage/SKILL.md`
  **Use when:** After Phase 2 ingestion, a large (~500+) historical URL corpus remains to triage; deep pass of gf classification → httpx body fetch → trufflehog secret scan (no external HTTP by default). Operator-dispatched; owned by surface-collector.
  **Paired references:** `references/tools/recon/gf.md`, `references/tools/recon/trufflehog.md`, `references/tools/recon/httpx.md`, `references/tools/recon/gau.md`

- `agent/skills/case-dispatching/SKILL.md`
  **Use when:** Operator needs to coordinate the Phase 3 work-buffer consumption loop (reset-stale → stats → fetch → dispatch → done → requeue).
  **Paired references:** _(none — coordination logic only)_

- `agent/skills/report-generation/SKILL.md`
  **Use when:** Writing the final or interim engagement report in Phase 7 or on demand.
  **Paired references:** _(uses durable backend finding state)_

- `agent/skills/osint-recon/SKILL.md`
  **Use when:** Gathering CVEs, public disclosures, DNS exposure, org intel, or historical breach data.
  **Paired references:** _(web-sourced; no local payload files)_

- `agent/skills/vendor-platform-enum/SKILL.md`
  **Use when:** A single vendor-platform read primitive surfaces (Salesforce SObject, ServiceNow GlideRecord row, Drupal JSON:API entity, Pexip admin-API namespace) — the same dispatch must run the matching deep-enum playbook before returning, because stopping at the first leak misses the full anonymous-readable namespace.
  **Paired references:** `references/payloads/salesforce-aura-payloads.md`, `references/payloads/servicenow-glide-payloads.md`, `references/payloads/drupal-jsonapi-payloads.md`, `references/payloads/pexip-admin-api-payloads.md`

- `agent/skills/athena-log-investigation/SKILL.md`
  **Use when:** Logs are available after exploit work and you need to check for prior exploitation evidence.
  **Paired references:** _(environment-specific; consult operator for log source)_

---

## Targeted Testing Skills

Load the relevant skill before starting validation or exploitation of a candidate surface.

- `agent/skills/auth-bypass/SKILL.md`
  **Use when:** Testing login bypass, session fixation, MFA bypass, token manipulation, or credential-based auth logic.
  **Paired references:** `references/payloads/jwt-payloads.md`

- `agent/skills/business-logic-testing/SKILL.md`
  **Use when:** Testing price manipulation, quantity abuse, workflow skipping, coupon/promo abuse, or payment bypass.
  **Paired references:** `references/payloads/business-logic-payloads.md`

- `agent/skills/cache-poisoning/SKILL.md`
  **Use when:** Target sits behind a CDN, reverse proxy, or caching layer; testing for cache poisoning via unkeyed headers or cache deception via path normalization.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/command-injection/SKILL.md`
  **Use when:** Input lands in OS commands, shell eval, or system calls (ping, DNS lookup, file conversion, etc.).
  **Paired references:** `references/payloads/command-injection-payloads.md`

- `agent/skills/cors-testing/SKILL.md`
  **Use when:** Testing cross-origin access, `Access-Control-Allow-Origin` policy, or credentialed cross-site requests.
  **Paired references:** `references/payloads/cors-payloads.md`

- `agent/skills/crlf-injection/SKILL.md`
  **Use when:** User input appears in HTTP response headers, redirect locations, or logged fields; testing for header injection and response splitting.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/csrf-testing/SKILL.md`
  **Use when:** Testing state-changing requests without proper origin or token validation.
  **Paired references:** `references/payloads/csrf-payloads.md`

- `agent/skills/deserialization-testing/SKILL.md`
  **Use when:** Application deserializes user-controlled data (Java, PHP, Python pickle, Node.js, .NET).
  **Paired references:** `references/payloads/deserialization-payloads.md`

- `agent/skills/directory-fuzzing/SKILL.md`
  **Use when:** Discovering hidden paths, admin panels, backup files, or undocumented endpoints via wordlist fuzzing.
  **Paired references:** `references/tools/fuzzing/ffuf.md`, `references/tools/fuzzing/feroxbuster.md`

- `agent/skills/file-inclusion/SKILL.md`
  **Use when:** Testing LFI/RFI, path traversal, PHP wrapper abuse, or log poisoning via file-path parameters.
  **Paired references:** `references/payloads/file-inclusion-payloads.md`, `references/payloads/directory-traversal-payloads.md`

- `agent/skills/file-upload-testing/SKILL.md`
  **Use when:** Testing file upload endpoints for extension bypass, content-type bypass, SVG XSS, or zip slip.
  **Paired references:** `references/payloads/upload-payloads.md`

- `agent/skills/graphql-testing/SKILL.md`
  **Use when:** Target exposes a GraphQL API; testing introspection, batching abuse, injection in variables, or authorization on queries/mutations.
  **Paired references:** `references/payloads/graphql-payloads.md`, `references/api-security/API05-broken-function-authz.md`

- `agent/skills/host-header-injection/SKILL.md`
  **Use when:** Application reflects or routes on the Host header; testing password reset poisoning, cache poisoning via Host, SSRF through Host manipulation, hostname-based access control bypass, or virtual host enumeration.
  **Paired references:** `agent/skills/cache-poisoning/SKILL.md`, `agent/skills/ssrf-testing/SKILL.md`

- `agent/skills/aws-iam-privesc/SKILL.md`
  **Use when:** AWS credentials obtained or IAM scope in cloud pentest; enumerating privilege escalation paths via dangerous policy combinations (PassRole+Lambda, CreatePolicyVersion, AssumeRole), wildcard policies, cross-account role chaining, and metadata service exploitation.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/cobalt-strike-analysis/SKILL.md`
  **Use when:** Suspected Cobalt Strike beacon in memory dump, disk artifact, or network capture; extracting beacon configuration (C2 endpoints, watermarks, malleable profiles), assessing operator OPSEC, and generating network detection signatures.
  **Paired references:** `references/offensive-tactics/red-team-infra/c2-frameworks.md`

- `agent/skills/container-escape-detection/SKILL.md`
  **Use when:** Testing containerized applications (Docker, Kubernetes pods); enumerating capabilities, detecting privileged container escape vectors (Docker socket, cgroup abuse, sensitive mounts), and validating Falco/seccomp enforcement.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/dns-tunneling-detection/SKILL.md`
  **Use when:** Investigating potential data exfiltration via DNS; analyzing query entropy, subdomain patterns, record type ratios, and query volume in Zeek/Splunk logs to detect tunneling tools (iodine, dnscat2, DNSExfiltrator, Cobalt Strike DNS).
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/idor-testing/SKILL.md`
  **Use when:** Testing object references in API parameters, IDs, GUIDs, or path segments for unauthorized access.
  **Paired references:** `references/api-security/API01-broken-object-level-authz.md`

- `agent/skills/info-disclosure-testing/SKILL.md`
  **Use when:** Probing for exposed debug endpoints, error responses, environment files, metadata endpoints, or stack traces.
  **Paired references:** `references/payloads/info-disclosure-probes.md`

- `agent/skills/jwt-testing/SKILL.md`
  **Use when:** Target uses JWT authentication; testing `alg:none`, key confusion, JWK/kid injection, or weak secret brute-force. Use in addition to auth-bypass when JWT is the mechanism.
  **Paired references:** `references/payloads/jwt-payloads.md`

- `agent/skills/mass-assignment/SKILL.md`
  **Use when:** API accepts JSON/form-encoded bodies for create/update operations; testing for unauthorized field binding, privilege escalation via extra parameters, or excessive data exposure in responses.
  **Paired references:** `references/api-security/API03-broken-property-authz.md`

- `agent/skills/nosql-injection/SKILL.md`
  **Use when:** Application uses MongoDB, CouchDB, Redis, or Elasticsearch; parameters may reach NoSQL queries via operator injection or JavaScript execution.
  **Paired references:** `references/payloads/nosql-injection-payloads.md`

- `agent/skills/oauth-oidc-testing/SKILL.md`
  **Use when:** Application uses OAuth 2.0 or OpenID Connect for authentication; testing redirect_uri manipulation, state parameter abuse, token leakage, scope escalation, or PKCE bypass.
  **Paired references:** `references/payloads/jwt-payloads.md`

- `agent/skills/open-redirect-testing/SKILL.md`
  **Use when:** Testing redirect parameters (`next`, `url`, `return_to`, etc.) for open redirect or OAuth token theft chains.
  **Paired references:** `references/payloads/open-redirect-payloads.md`

- `agent/skills/parameter-fuzzing/SKILL.md`
  **Use when:** Fuzzing hidden or undocumented query/body parameters, header variants, or content-type mutations.
  **Paired references:** `references/tools/fuzzing/ffuf.md`

- `agent/skills/port-scanning/SKILL.md`
  **Use when:** Discovering open ports, service banners, and non-web services on in-scope hosts.
  **Paired references:** `references/tools/recon/nmap.md`

- `agent/skills/prototype-pollution/SKILL.md`
  **Use when:** JavaScript/Node.js application accepts JSON input that may flow through deep merge or recursive assignment; testing for prototype chain pollution leading to XSS, RCE, or DoS.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/rate-limit-bypass/SKILL.md`
  **Use when:** Testing rate limiting on login, registration, OTP, or API endpoints; bypassing limits via IP spoofing headers, path variation, account rotation, parameter pollution, or concurrent request techniques.
  **Paired references:** `references/api-security/API04-resource-consumption.md`

- `agent/skills/race-condition-testing/SKILL.md`
  **Use when:** Testing time-of-check/time-of-use (TOCTOU) flaws, limit-overrun conditions, or concurrent state mutations.
  **Paired references:** `references/payloads/race-condition-payloads.md`

- `agent/skills/request-smuggling/SKILL.md`
  **Use when:** Target sits behind a reverse proxy or load balancer; testing CL.TE, TE.CL, TE.TE, or HTTP/2 downgrade desync.
  **Paired references:** `references/payloads/request-smuggling-payloads.md`

- `agent/skills/sensitive-data-detection/SKILL.md`
  **Use when:** Scanning responses, JS bundles, or downloadable files for exposed secrets, PII, tokens, or internal data.
  **Paired references:** `references/payloads/info-disclosure-probes.md`

- `agent/skills/sqli-testing/SKILL.md`
  **Use when:** Input is reflected in SQL queries (search, login, filters, sort params, REST IDs, GraphQL variables).
  **Paired references:** `references/payloads/sqli-payloads.md`, `references/tools/exploitation/sqlmap.md`

- `agent/skills/ssrf-testing/SKILL.md`
  **Use when:** User-controlled URL or hostname parameter is fetched server-side (webhooks, imports, previews, image fetch, PDF render).
  **Paired references:** `references/payloads/ssrf-payloads.md`, `references/api-security/API07-ssrf.md`

- `agent/skills/ssti-testing/SKILL.md`
  **Use when:** Input is reflected inside a server-side template (Jinja2, Twig, Pug, Freemarker, ERB, Velocity, etc.).
  **Paired references:** `references/payloads/ssti-payloads.md`

- `agent/skills/nuclei-scanning/SKILL.md`
  **Use when:** Live targets identified and tech stacks known; running template-based vulnerability sweeps for CVEs, misconfigs, and exposures.
  **Paired references:** `references/tools/recon/nuclei.md`

- `agent/skills/subdomain-enumeration/SKILL.md`
  **Use when:** The `hosts` array in scope.json contains `*.domain` entries; enumerating subdomains for additional attack surface.
  **Paired references:** `references/tools/recon/httpx.md`, `references/tools/recon/puredns.md`, `references/tools/recon/dnsx.md`

- `agent/skills/user-enumeration/SKILL.md`
  **Use when:** Testing login, password reset, or registration flows for username/email oracle behavior.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/websocket-testing/SKILL.md`
  **Use when:** Target uses WebSocket connections; testing message injection, auth drift, or cross-site WebSocket hijacking.
  **Paired references:** _(none — methodology in skill)_

- `agent/skills/xss-testing/SKILL.md`
  **Use when:** User input is reflected in HTML/JS context (reflected, stored, or DOM-based XSS).
  **Paired references:** `references/payloads/xss-payloads.md`, `references/tools/exploitation/dalfox.md`

- `agent/skills/xxe-testing/SKILL.md`
  **Use when:** Application parses XML input (file upload, SOAP API, SVG, DOCX, RSS feed).
  **Paired references:** `references/payloads/xxe-payloads.md`

- `agent/skills/cicd-security/SKILL.md`
  **Use when:** Target has public GitHub repositories with `.github/workflows/` files; recon discovers GitHub org; code analysis encounters CI/CD workflow YAML. Covers expression injection, untrusted checkout, artifact/cache poisoning, supply chain attacks, self-hosted runner exploitation, and AI agent security.
  **Paired references:** `references/code-vuln-patterns/injection.md`, `references/payloads/command-injection-payloads.md`

---

## Mobile Security Skills

Load these skills for authorized Android/iOS app, device-lab, and mobile fuzzing work.

- `agent/skills/android-app-security/SKILL.md`
  **Use when:** Testing Android APK/AAB artifacts, mobile APIs, local storage, Keystore use, TLS/pinning, exported components, deep links, WebView bridges, native libraries, or runtime instrumentation.
  **Paired references:** `references/mobile/android-app-security.md`, `references/mobile/mobile-lab-setup.md`, `references/mobile/android-platform-device-lab.md`, `references/mobile/mobile-fuzzing.md`

- `agent/skills/ios-app-security/SKILL.md`
  **Use when:** Testing iOS IPA/Xcode/TestFlight builds, mobile APIs, Keychain, local storage, ATS/TLS, URL schemes, universal links, pasteboard, WebView bridges, native code, or runtime instrumentation.
  **Paired references:** `references/mobile/ios-app-security.md`, `references/mobile/mobile-lab-setup.md`, `references/mobile/ios-platform-device-lab.md`, `references/mobile/mobile-fuzzing.md`

- `agent/skills/mobile-lab-setup/SKILL.md`
  **Use when:** Deciding whether mobile testing needs emulators, simulators, owned physical devices, rooted/jailbroken devices, Mac ARM host setup, Docker, proxies, device farms, or CI automation.
  **Paired references:** `references/mobile/mobile-lab-setup.md`, `references/mobile/android-platform-device-lab.md`, `references/mobile/ios-platform-device-lab.md`

- `agent/skills/mobile-fuzzing/SKILL.md`
  **Use when:** Fuzzing mobile app APIs, imported files, parsers, deep links, intents, URL schemes, WebView inputs, native libraries, Android Binder/AIDL, iOS XPC/Mach, or mobile crash triage.
  **Paired references:** `references/mobile/mobile-fuzzing.md`, `references/code-vuln-patterns/fuzz-harness-patterns.md`, `references/mobile/android-app-security.md`, `references/mobile/ios-app-security.md`

- `agent/skills/masvs-privacy-testing/SKILL.md`
  **Use when:** Testing OWASP MASVS-PRIVACY controls: identifier collection (IDFA/GAID/IMEI/MAC), App Tracking Transparency compliance, Android Privacy Sandbox migration, data deletion completeness, privacy label vs actual behavior, or analytics/telemetry over-collection.
  **Paired references:** `references/mobile/masvs-privacy-testing.md`, `references/mobile/android-app-security.md`, `references/mobile/ios-app-security.md`, `references/mobile/mobile-lab-setup.md`

- `agent/skills/ai-ml-on-device-security/SKILL.md`
  **Use when:** App bundles on-device ML models (Core ML, TFLite, ONNX), integrates LLM features (Apple Intelligence, Gemini Nano, OpenAI/Anthropic SDK), uses ML Kit or Vision/NL frameworks, or participates in federated learning. Covers model extraction, inference data leakage, content filter bypass, prompt injection, and federated learning assessment.
  **Paired references:** `references/mobile/ai-ml-on-device-security.md`, `references/mobile/android-app-security.md`, `references/mobile/ios-app-security.md`, `references/mobile/mobile-lab-setup.md`, `references/code-vuln-patterns/ai-ml-security.md`

- `agent/skills/sdk-supply-chain-security/SKILL.md`
  **Use when:** Assessing third-party SDK supply chain risk: building SDK BOM, checking bundled SDK versions against CVEs, detecting known malicious SDKs (SpinOK/Goldoson), auditing SDK data exfiltration, or analyzing SDK permission scope versus app needs.
  **Paired references:** `references/mobile/sdk-supply-chain-security.md`, `references/mobile/android-app-security.md`, `references/mobile/ios-app-security.md`, `references/mobile/masvs-privacy-testing.md`

---

## Code Analysis Skills

Load these skills when performing white-box source code analysis (operator-core-code.md mode).
Pipeline: Ingest → Classify+Map → Hunt → Verify+Variant → Fuzz (conditional)

- `agent/skills/code-architecture-mapping/SKILL.md`
  **Use when:** Phase 1 (Classify+Map) — classifying files, mapping modules, building threat model, producing cross-module call graph, generating attack hypotheses.
  **Paired references:** _(works from project metadata, no vulnerability references needed)_

- `agent/skills/code-vulnerability-analysis/SKILL.md`
  **Use when:** Phase 2 (Hunt) — performing deep vulnerability analysis on source code files using Trail of Bits methodology. Load the CWE-specific reference matching the target's CWE families.
  **Paired references:** `references/code-vuln-patterns/buffer-overflow.md`, `references/code-vuln-patterns/integer-overflow.md`, `references/code-vuln-patterns/format-string.md`, `references/code-vuln-patterns/use-after-free.md`, `references/code-vuln-patterns/injection.md`, `references/code-vuln-patterns/race-condition.md`, `references/code-vuln-patterns/crypto-misuse.md`, `references/code-vuln-patterns/auth-bypass.md`, `references/code-vuln-patterns/path-traversal.md`, `references/code-vuln-patterns/ssrf.md`, `references/code-vuln-patterns/open-redirect.md`, `references/code-vuln-patterns/file-upload.md`, `references/code-vuln-patterns/xxe.md`, `references/code-vuln-patterns/deserialization.md`, `references/code-vuln-patterns/uninitialized-memory.md`, `references/code-vuln-patterns/type-confusion.md`, `references/code-vuln-patterns/null-dereference.md`, `references/code-vuln-patterns/algorithmic-dos.md`, `references/code-vuln-patterns/error-handling.md`, `references/code-vuln-patterns/web-app-data-exposure.md`, `references/code-vuln-patterns/ai-ml-security.md`

- `agent/skills/code-variant-analysis/SKILL.md`
  **Use when:** Phase 3 (Verify+Variant, parallel) — scanning the codebase for variant instances of a confirmed bug pattern.
  **Paired references:** _(uses original finding details and CWE pattern reference from the hunter)_

- `agent/skills/code-finding-verification/SKILL.md`
  **Use when:** Phase 3 (Verify+Variant, parallel) — eliminating false positives via five-check protocol with devil's advocate methodology and multi-perspective voting.
  **Paired references:** _(uses build system configuration, CWE pattern references for pattern verification)_

- `agent/skills/code-fuzz-campaign/SKILL.md`
  **Use when:** Phase 4 (Fuzz, conditional) — AI-driven fuzz campaigns for C/C++ codebases. Selects targets from structural index and Phase 2 findings, writes libFuzzer/AFL++ harnesses, compiles under ASAN/UBSAN, configures campaigns, and triages crashes with rigorous false-positive gates. Skip when codebase is memory-safe or has no memory-safety findings.
  **Paired references:** `references/code-vuln-patterns/fuzz-harness-patterns.md`, `references/code-vuln-patterns/buffer-overflow.md`, `references/code-vuln-patterns/integer-overflow.md`, `references/code-vuln-patterns/use-after-free.md`, `references/code-vuln-patterns/uninitialized-memory.md`
